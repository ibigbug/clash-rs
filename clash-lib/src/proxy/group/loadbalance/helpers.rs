use std::{
    io::Cursor,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use futures::future::BoxFuture;
use murmur3::murmur3_32;
use public_suffix::{DEFAULT_PROVIDER, EffectiveTLDProvider};
use tokio::sync::Mutex;

use crate::{
    app::remote_content_manager::ProxyManager, proxy::AnyOutboundHandler,
    session::Session,
};

pub type StrategyFn = Box<
    dyn FnMut(
            Vec<AnyOutboundHandler>,
            &Session,
        ) -> BoxFuture<'static, std::io::Result<AnyOutboundHandler>>
        + Send
        + Sync,
>;

fn get_key(sess: &Session) -> String {
    match &sess.destination {
        crate::session::SocksAddr::Ip(addr) => addr.ip().to_string(),
        crate::session::SocksAddr::Domain(host, _) => DEFAULT_PROVIDER
            .effective_tld_plus_one(host)
            .map(|s| s.to_string())
            .unwrap_or_default(),
    }
}

fn get_key_src_and_dst(sess: &Session) -> String {
    let dst = get_key(sess);
    let src = match &sess.source {
        std::net::SocketAddr::V4(socket_addr_v4) => socket_addr_v4.ip().to_string(),
        std::net::SocketAddr::V6(socket_addr_v6) => socket_addr_v6.ip().to_string(),
    };
    format!("{src}-{dst}")
}

fn jump_hash(key: u64, buckets: i32) -> i32 {
    let mut key = key;
    let mut b = -1i64;
    let mut j = 0i64;
    while j < buckets as i64 {
        b = j;
        key = key.wrapping_mul(2862933555777941757).wrapping_add(1);
        j = ((b + 1) as f64 * (1i64 << 31) as f64 / ((key >> 33) + 1) as f64) as i64;
    }
    b as i32
}

pub fn strategy_rr() -> StrategyFn {
    let mut index = 0;
    Box::new(move |proxies: Vec<AnyOutboundHandler>, _: &Session| {
        let len = proxies.len();
        if len == 0 {
            return Box::pin(futures::future::err(std::io::Error::other(
                "no proxy found",
            )));
        }
        index = (index + 1) % len;
        Box::pin(futures::future::ok(proxies[index].clone()))
    })
}

pub fn strategy_consistent_hashring() -> StrategyFn {
    Box::new(move |proxies, sess| {
        if proxies.is_empty() {
            return Box::pin(futures::future::err(std::io::Error::other(
                "no proxy found",
            )));
        }
        let key = murmur3_32(&mut Cursor::new(get_key(sess)), 0).unwrap() as u64;
        let buckets = proxies.len() as i32;
        // jump_hash with buckets > 0 always returns a valid index in [0,
        // buckets) so a single call suffices; no retry needed.
        let index = jump_hash(key, buckets);
        if let Some(proxy) = proxies.get(index as usize) {
            Box::pin(futures::future::ok(proxy.clone()))
        } else {
            Box::pin(futures::future::err(std::io::Error::other(
                "no proxy found",
            )))
        }
    })
}

#[cfg(test)]
static TEST_LRU_STATE: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(CACHE_MISS);
#[cfg(test)]
const CACHE_MISS: usize = 0;
#[cfg(test)]
const CACHE_HIT: usize = 1;
#[cfg(test)]
const CACHE_UPDATE: usize = 2;

pub fn strategy_sticky_session(proxy_manager: ProxyManager) -> StrategyFn {
    let max_retry = 5;
    // 10 minutes, 1024 entries
    let lru_cache: lru_time_cache::LruCache<u64, usize> =
        lru_time_cache::LruCache::with_expiry_duration_and_capacity(
            std::time::Duration::from_secs(60 * 10),
            1024,
        );
    let lru_cache = Arc::new(Mutex::new(lru_cache));
    Box::new(move |proxies, sess| {
        let key_str = get_key_src_and_dst(sess);
        let key = murmur3_32(&mut Cursor::new(&key_str), 0).unwrap() as u64;
        let proxy_manager_clone = proxy_manager.clone();
        let lru_cache_clone = lru_cache.clone();
        let timestamp = || {
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos() as u64
        };

        Box::pin(async move {
            let buckets = proxies.len() as i32;
            let (start_index, hit) = match lru_cache_clone.lock().await.get(&key) {
                Some(&index) => {
                    #[cfg(test)]
                    {
                        TEST_LRU_STATE
                            .store(CACHE_HIT, std::sync::atomic::Ordering::Relaxed);
                    }
                    (index, true)
                }
                None => (jump_hash(key + timestamp(), buckets) as usize, false),
            };

            // use `do - while` since we have the cached result
            let mut index = start_index;
            for _ in 0..max_retry {
                if let Some(proxy) = proxies.get(index)
                    && proxy_manager_clone.alive(proxy.name()).await
                {
                    // now it's a valid proxy
                    // check if it's the same as the last one(likely)
                    // update the cache if:
                    //   1. the index is not the same as the start_index
                    //   2. the start_index is not fetched from the cache
                    if index != start_index || !hit {
                        lru_cache_clone.lock().await.insert(key, index);
                        #[cfg(test)]
                        {
                            TEST_LRU_STATE.store(
                                CACHE_UPDATE,
                                std::sync::atomic::Ordering::Relaxed,
                            );
                        }
                    }
                    return Ok(proxy.clone());
                }
                // the cached proxy is dead, change the key by a new timestamp
                // and try again
                index = jump_hash(key + timestamp(), buckets) as usize;
            }
            // TODO: if we should just remove the key from the cache?
            lru_cache_clone.lock().await.insert(key, 0);
            #[cfg(test)]
            {
                TEST_LRU_STATE
                    .store(CACHE_MISS, std::sync::atomic::Ordering::Relaxed);
            }
            Err(std::io::Error::other("no proxy found"))
        })
    })
}

#[cfg(test)]
mod tests {
    use std::{
        net::{Ipv4Addr, SocketAddr, SocketAddrV4},
        sync::Arc,
    };

    use super::*;
    use crate::{
        app::remote_content_manager::ProxyManager,
        proxy::utils::test_utils::noop::{NoopOutboundHandler, NoopResolver},
        session::SocksAddr,
    };

    macro_rules! assert_cache_state {
        ($state:expr_2021) => {
            assert_eq!(
                TEST_LRU_STATE.load(std::sync::atomic::Ordering::Relaxed),
                $state
            );
        };
    }

    #[tokio::test]
    async fn test_sticky_session() {
        let resolver = Arc::new(NoopResolver);
        let proxies = vec![
            Arc::new(NoopOutboundHandler {
                name: "a".to_string(),
            }) as _,
            Arc::new(NoopOutboundHandler {
                name: "b".to_string(),
            }) as _,
            Arc::new(NoopOutboundHandler {
                name: "c".to_string(),
            }) as _,
        ];
        let manager = ProxyManager::new(resolver, None);
        // if the proxy alive state isn't set, will return true by default
        // so we need to clear the alive states first
        manager.report_alive("a", false, None).await;
        manager.report_alive("b", false, None).await;
        manager.report_alive("c", false, None).await;

        let mut strategy_fn = strategy_sticky_session(manager.clone());

        // all proxies is not alive since we have not setup the proxy manager
        let res = strategy_fn(proxies.clone(), &Session::default()).await;
        assert!(res.is_err());
        assert_cache_state!(CACHE_MISS);

        manager.report_alive("a", true, None).await;
        manager.report_alive("b", true, None).await;
        manager.report_alive("c", true, None).await;

        let mut session1 = Session::default();
        let src1 = Ipv4Addr::new(127, 0, 0, 1);
        let dst1 = Ipv4Addr::new(1, 1, 1, 1);
        session1.source = SocketAddr::V4(SocketAddrV4::new(src1, 8964));
        session1.destination =
            SocksAddr::Ip(SocketAddr::V4(SocketAddrV4::new(dst1, 80)));

        // 1.1 first time, cache miss & update
        let res = strategy_fn(proxies.clone(), &session1).await;
        assert_cache_state!(CACHE_UPDATE);
        let session1_outbound_name_1 = res.unwrap().name().to_owned();

        // 1.2 second time, cache hit
        let res = strategy_fn(proxies.clone(), &session1).await;
        assert_eq!(res.unwrap().name(), session1_outbound_name_1);
        assert_cache_state!(CACHE_HIT);
        // 1.3 third time, cache hit
        let res = strategy_fn(proxies.clone(), &session1).await;
        assert_eq!(res.unwrap().name(), session1_outbound_name_1);
        assert_cache_state!(CACHE_HIT);

        // 1.4 change the source address, cache miss & update
        let dst1_2 = Ipv4Addr::new(8, 8, 8, 8);
        session1.destination =
            SocksAddr::Ip(SocketAddr::V4(SocketAddrV4::new(dst1_2, 80)));
        let res = strategy_fn(proxies.clone(), &session1).await;
        assert_cache_state!(CACHE_UPDATE);
        let session1_outbound_name_2 = res.unwrap().name().to_owned();

        // 1.5 cache hit
        let res = strategy_fn(proxies.clone(), &session1).await;
        assert_eq!(res.unwrap().name(), session1_outbound_name_2);
        assert_cache_state!(CACHE_HIT);

        for i in 1..100 {
            // 1.6 change the src address, cache miss & update
            let src1_new = Ipv4Addr::new(192, 168, 2, i);
            session1.source = SocketAddr::V4(SocketAddrV4::new(src1_new, 8964));
            let res = strategy_fn(proxies.clone(), &session1).await;
            assert_cache_state!(CACHE_UPDATE);
            let session1_outbound_name_new = res.unwrap().name().to_owned();

            // 1.6 cache hit
            let res = strategy_fn(proxies.clone(), &session1).await;
            assert_eq!(res.unwrap().name(), session1_outbound_name_new);
            assert_cache_state!(CACHE_HIT);
        }
    }
}
