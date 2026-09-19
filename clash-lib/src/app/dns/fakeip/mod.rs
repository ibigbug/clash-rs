use std::{net, sync::Arc};

use crate::{Error, common::trie};

use async_trait::async_trait;
use byteorder::{BigEndian, ByteOrder};
use tokio::sync::RwLock;

mod file_store;
mod mem_store;

pub use file_store::FileStore;
pub use mem_store::InMemStore;

pub struct Opts {
    pub ipnet: ipnet::IpNet,
    pub skipped_hostnames: Option<trie::StringTrie<bool>>,
    pub store: Box<dyn Store>,
}

#[async_trait]
pub trait Store: Sync + Send {
    async fn get_by_host(&mut self, host: &str) -> Option<net::IpAddr>;
    async fn pub_by_host(&mut self, host: &str, ip: net::IpAddr);
    async fn get_by_ip(&mut self, ip: net::IpAddr) -> Option<String>;
    async fn put_by_ip(&mut self, ip: net::IpAddr, host: &str);
    async fn del_by_ip(&mut self, ip: net::IpAddr);
    async fn exist(&mut self, ip: net::IpAddr) -> bool;
    async fn copy_to(&self, store: &mut Box<dyn Store>);
}

pub type ThreadSafeFakeDns = Arc<RwLock<FakeDns>>;

pub struct FakeDns {
    max: u32,
    min: u32,
    #[allow(dead_code)]
    gateway: u32,
    offset: u32,
    skipped_hostnames: Option<trie::StringTrie<bool>>,
    ipnet: ipnet::IpNet,
    store: Box<dyn Store>,
}

impl FakeDns {
    pub fn new(opt: Opts) -> Result<Self, Error> {
        let ip = match opt.ipnet.network() {
            net::IpAddr::V4(ip) => ip,
            _ => unreachable!("fakeip range must be valid ipv4 subnet"),
        };
        let min = Self::ip_to_uint(&ip) + 2;
        let prefix_len = opt.ipnet.prefix_len();
        let max_prefix_len = opt.ipnet.max_prefix_len();
        debug_assert_eq!(max_prefix_len, 32, "v4 subnet");
        let total = (1 << (max_prefix_len - prefix_len)) - 2;

        let max = min + total - 1;

        Ok(Self {
            max,
            min,
            gateway: min - 1,
            offset: total - 1,
            skipped_hostnames: opt.skipped_hostnames,
            ipnet: opt.ipnet,
            store: opt.store,
        })
    }

    pub async fn lookup(&mut self, host: &str) -> net::IpAddr {
        if let Some(ip) = self.store.get_by_host(host).await {
            return ip;
        }

        let ip = self.get(host).await;
        self.store.pub_by_host(host, ip).await;
        ip
    }

    pub async fn reverse_lookup(&mut self, ip: net::IpAddr) -> Option<String> {
        if ip.is_ipv4() {
            self.store.get_by_ip(ip).await
        } else {
            None
        }
    }

    pub fn should_skip(&self, domain: &str) -> bool {
        self.skipped_hostnames
            .as_ref()
            .is_some_and(|host| host.search(domain).is_some())
    }

    #[allow(dead_code)]
    pub async fn exist(&mut self, ip: net::IpAddr) -> bool {
        ip.is_ipv4() && self.store.exist(ip).await
    }

    pub async fn is_fake_ip(&mut self, ip: net::IpAddr) -> bool {
        let net::IpAddr::V4(v4) = ip else {
            return false;
        };
        // Broadcast and multicast addresses are never allocated as fake IPs.
        if v4.is_broadcast() || v4.is_multicast() {
            return false;
        }
        // Only IPs that are both within the fake-IP range *and* have actually
        // been allocated in the store should be treated as fake IPs.  This
        // prevents directed-broadcast addresses (e.g. 198.18.0.255 for the
        // /24 TUN subnet) that fall inside the wider fake-IP /16 range from
        // triggering a failed reverse-lookup in the dispatcher.
        self.ipnet.contains(&ip) && self.store.exist(ip).await
    }

    #[allow(dead_code)]
    pub fn gateway(&self) -> net::Ipv4Addr {
        net::Ipv4Addr::from(self.gateway)
    }

    #[allow(dead_code)]
    pub fn ipnet(&self) -> ipnet::IpNet {
        self.ipnet
    }

    #[allow(dead_code)]
    pub async fn copy_from(&mut self, src: &Self) {
        src.store.copy_to(&mut self.store).await;
    }

    fn current_ip(&self) -> net::IpAddr {
        net::IpAddr::V4(net::Ipv4Addr::from(self.min + self.offset))
    }

    async fn get(&mut self, host: &str) -> net::IpAddr {
        let pool_size = self.max - self.min + 1;
        let current = self.offset;

        loop {
            self.offset = (self.offset + 1) % pool_size;
            let ip = self.current_ip();

            if self.offset == current {
                self.offset = (self.offset + 1) % pool_size;
                let ip = self.current_ip();
                self.store.del_by_ip(ip).await;
                break;
            }

            if !self.store.exist(ip).await {
                break;
            }
        }

        let ip = self.current_ip();
        self.store.put_by_ip(ip, host).await;
        ip
    }

    fn ip_to_uint(ip: &net::Ipv4Addr) -> u32 {
        BigEndian::read_u32(&ip.octets())
    }
}

#[cfg(test)]
mod tests {
    use std::{net, sync::Arc};

    use crate::{app::dns::fakeip::mem_store::InMemStore, common::trie};

    use super::{FakeDns, Opts};

    #[tokio::test]
    async fn test_inmem_basic() {
        let ipnet = "192.168.0.0/29".parse::<ipnet::IpNet>().unwrap();
        let store = Box::new(InMemStore::new(10));
        let mut pool = FakeDns::new(Opts {
            ipnet,
            skipped_hostnames: None,
            store,
        })
        .unwrap();

        let first = pool.lookup("foo.com").await;
        let last = pool.lookup("bar.com").await;

        let bar = pool.reverse_lookup(last).await;

        assert_eq!(first, net::IpAddr::from([192, 168, 0, 2]));
        assert_eq!(
            pool.lookup("foo.com").await,
            net::IpAddr::from([192, 168, 0, 2])
        );
        assert_eq!(last, net::IpAddr::from([192, 168, 0, 3]));
        assert!(bar.is_some());
        assert_eq!(bar, Some("bar.com".into()));
        assert_eq!(pool.gateway(), net::IpAddr::from([192, 168, 0, 1]));
        assert_eq!(pool.ipnet().to_string(), ipnet.to_string());
        assert!(pool.exist(net::IpAddr::from([192, 168, 0, 3])).await);
        assert!(!pool.exist(net::IpAddr::from([192, 168, 0, 4])).await);
        assert!(!pool.exist("::1".parse().unwrap()).await);
    }

    #[tokio::test]
    async fn test_inmem_cycle_used() {
        let store = Box::new(InMemStore::new(10));

        let ipnet = "192.168.0.0/29".parse::<ipnet::IpNet>().unwrap();
        let mut pool = FakeDns::new(Opts {
            ipnet,
            skipped_hostnames: None,
            store,
        })
        .unwrap();

        let foo = pool.lookup("foo.com").await;
        let bar = pool.lookup("bar.com").await;

        // Fill all 6 IPs in the /29 pool (min=192.168.0.2, max=192.168.0.7).
        // foo and bar already use 2, so 4 more are needed to fill the pool.
        for i in 0..4 {
            pool.lookup(&format!("{}.com", i)).await;
        }

        // Pool is now full — baz must recycle foo's IP (oldest entry).
        let baz = pool.lookup("baz.com").await;
        // foo.com's forward mapping was cleaned up by put_by_ip, so the next
        // lookup allocates a fresh IP (bar's recycled IP).
        let next = pool.lookup("foo.com").await;
        assert_eq!(foo, baz);
        assert_eq!(next, bar);
    }

    #[tokio::test]
    async fn test_pool_skip() {
        let store = Box::new(InMemStore::new(10));

        let ipnet = "192.168.0.0/30".parse::<ipnet::IpNet>().unwrap();
        let mut tree = trie::StringTrie::new();
        tree.insert("example.com", Arc::new(false));

        let pool = FakeDns::new(Opts {
            ipnet,
            skipped_hostnames: Some(tree),
            store,
        })
        .unwrap();

        assert!(pool.should_skip("example.com"));
        assert!(!pool.should_skip("foo.com"));
    }

    #[tokio::test]
    async fn test_pool_max_cache_size() {
        let store = Box::new(InMemStore::new(2));

        let ipnet = "192.168.0.0/24".parse::<ipnet::IpNet>().unwrap();
        let mut pool = FakeDns::new(Opts {
            ipnet,
            skipped_hostnames: None,
            store,
        })
        .unwrap();

        let first = pool.lookup("foo.com").await;

        pool.lookup("bar.com").await;
        pool.lookup("baz.com").await;
        let next = pool.lookup("foo.com").await;

        assert_ne!(first, next);
    }

    #[tokio::test]
    #[ignore = "copy not implemented"]
    async fn test_pool_clone() {
        let store = Box::new(InMemStore::new(2));

        let ipnet = "192.168.0.0/24".parse::<ipnet::IpNet>().unwrap();
        let mut pool = FakeDns::new(Opts {
            ipnet,
            skipped_hostnames: None,
            store,
        })
        .unwrap();

        let first = pool.lookup("foo.com").await;
        let last = pool.lookup("bar.com").await;
        assert_eq!(first, net::IpAddr::from([192, 168, 0, 2]));
        assert_eq!(last, net::IpAddr::from([192, 168, 0, 3]));

        let store = Box::new(InMemStore::new(2));

        let mut new_pool = FakeDns::new(Opts {
            ipnet,
            skipped_hostnames: None,
            store,
        })
        .unwrap();

        new_pool.copy_from(&pool).await;

        assert!(new_pool.reverse_lookup(first).await.is_some());
        assert!(new_pool.reverse_lookup(last).await.is_some());
    }

    #[tokio::test]
    async fn test_is_fake_ip_excludes_broadcast_and_unallocated() {
        let store = Box::new(InMemStore::new(10));

        // Use 198.18.0.0/16 (the default fake-ip-range) to mirror the real
        // production setup described in the bug report, where the TUN gateway
        // is 198.18.0.1/24 and its subnet broadcast 198.18.0.255 fell inside
        // the wider /16 fake-ip range.
        let ipnet = "198.18.0.0/16".parse::<ipnet::IpNet>().unwrap();
        let mut pool = FakeDns::new(Opts {
            ipnet,
            skipped_hostnames: None,
            store,
        })
        .unwrap();

        // Allocate one real fake IP.
        let allocated = pool.lookup("foo.com").await;
        assert!(
            pool.is_fake_ip(allocated).await,
            "allocated IP must be fake"
        );

        // Directed broadcast for the /24 TUN subnet (198.18.0.0/24) – never
        // allocated, yet it falls inside the /16 range.
        let directed_broadcast: net::IpAddr = "198.18.0.255".parse().unwrap();
        assert!(
            !pool.is_fake_ip(directed_broadcast).await,
            "directed broadcast must not be treated as a fake IP"
        );

        // Global broadcast must never be a fake IP.
        let global_broadcast: net::IpAddr = "255.255.255.255".parse().unwrap();
        assert!(
            !pool.is_fake_ip(global_broadcast).await,
            "255.255.255.255 must not be a fake IP"
        );

        // A multicast address must never be a fake IP.
        let multicast: net::IpAddr = "224.0.0.1".parse().unwrap();
        assert!(
            !pool.is_fake_ip(multicast).await,
            "multicast must not be a fake IP"
        );

        // An IP in the range that was never allocated must not be fake.
        let unallocated: net::IpAddr = "198.18.1.1".parse().unwrap();
        assert!(
            !pool.is_fake_ip(unallocated).await,
            "unallocated in-range IP must not be treated as a fake IP"
        );
    }
}
