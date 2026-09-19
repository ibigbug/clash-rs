use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

use tokio::time::Instant;
use tracing::debug;

use crate::proxy::AnyOutboundHandler;

use super::ProxyManager;

struct HealCheckInner {
    last_check: Instant,
    proxies: Vec<AnyOutboundHandler>,
}

pub struct HealthCheck {
    url: String,
    interval: u64,
    lazy: bool,
    proxy_manager: ProxyManager,
    inner: Arc<tokio::sync::RwLock<HealCheckInner>>,
    /// Fix(2026-08-04): when HealthCheck is dropped, signal the background
    /// task to stop (prevents task leak on configuration hot-reload).
    stopped: Arc<AtomicBool>,
    /// Handle of the ticker task, kept outside `inner` so `Drop` can abort it.
    task_handle: std::sync::Mutex<Option<tokio::task::JoinHandle<()>>>,
}

impl Drop for HealthCheck {
    fn drop(&mut self) {
        self.stopped.store(true, Ordering::Relaxed);
        if let Ok(mut h) = self.task_handle.lock()
            && let Some(h) = h.take()
        {
            h.abort();
        }
    }
}

impl HealthCheck {
    pub fn new(
        proxies: Vec<AnyOutboundHandler>,
        url: String,
        interval: u64,
        lazy: bool,
        proxy_manager: ProxyManager,
    ) -> Self {
        Self {
            url,
            interval,
            lazy,
            proxy_manager,
            stopped: Arc::new(AtomicBool::new(false)),
            task_handle: std::sync::Mutex::new(None),
            inner: Arc::new(tokio::sync::RwLock::new(HealCheckInner {
                last_check: tokio::time::Instant::now(),
                proxies,
            })),
        }
    }

    pub async fn kick_off(&self) {
        let interval = self.interval;
        let lazy = self.lazy;
        let inner = self.inner.clone();
        let proxy_manager = self.proxy_manager.clone();
        let url = self.url.clone();
        let stopped = self.stopped.clone();
        let task_handle = tokio::spawn(async move {
            // Initial check under the cancellable task tree
            let proxies = inner.read().await.proxies.clone();
            proxy_manager.check(&proxies, &url, None, false).await;
            inner.write().await.last_check = tokio::time::Instant::now();

            let mut ticker =
                tokio::time::interval(tokio::time::Duration::from_secs(interval));
            ticker.tick().await; // First tick completes immediately; consume it.
            loop {
                tokio::select! {
                    _ = ticker.tick() => {
                        if stopped.load(Ordering::Relaxed) {
                            debug!("healthcheck {} stopped", url);
                            break;
                        }
                        debug!("healthcheck ticking: {}, lazy: {}", url, lazy);
                        let now = tokio::time::Instant::now();
                        let last_check = inner.read().await.last_check;
                        if !lazy || now.duration_since(last_check).as_secs() >= interval {
                            let proxies = inner.read().await.proxies.clone();
                            proxy_manager.check(&proxies, &url, None, false).await;
                            inner.write().await.last_check = now;
                        }
                    },
                }
            }
        });

        if let Ok(mut h) = self.task_handle.lock() {
            *h = Some(task_handle);
        }
    }

    pub async fn touch(&self) {
        self.inner.write().await.last_check = tokio::time::Instant::now();
    }

    /// Run a health check pass.
    ///
    /// `force` is forwarded to [`ProxyManager::check`]: pass `true` for a
    /// user-triggered health check (e.g. via the `/providers/:name/healthcheck`
    /// API) so that proxies currently in backoff are still tested; pass
    /// `false` for automatic post-update checks where backoff should apply.
    pub async fn check(&self, force: bool) {
        let proxies = self.inner.read().await.proxies.clone();
        self.proxy_manager
            .check(&proxies, &self.url, None, force)
            .await;
    }

    pub async fn update(&self, proxies: Vec<AnyOutboundHandler>) {
        self.inner.write().await.proxies = proxies;
    }

    pub fn auto(&self) -> bool {
        self.interval != 0
    }
}
