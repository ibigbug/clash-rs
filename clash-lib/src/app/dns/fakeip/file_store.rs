use async_trait::async_trait;

use crate::app::profile::ThreadSafeCacheFile;

use super::Store;

pub struct FileStore(ThreadSafeCacheFile);

impl FileStore {
    pub fn new(store: ThreadSafeCacheFile) -> Self {
        Self(store)
    }
}

#[async_trait]
impl Store for FileStore {
    async fn get_by_host(&mut self, host: &str) -> Option<std::net::IpAddr> {
        self.0
            .get_fake_ip(host)
            .await
            .and_then(|ip| ip.parse().ok())
    }

    async fn pub_by_host(&mut self, host: &str, ip: std::net::IpAddr) {
        self.0.set_host_to_ip(host, &ip.to_string()).await;
    }

    async fn get_by_ip(&mut self, ip: std::net::IpAddr) -> Option<String> {
        self.0.get_fake_ip(&ip.to_string()).await
    }

    async fn put_by_ip(&mut self, ip: std::net::IpAddr, host: &str) {
        self.0.set_ip_to_host(&ip.to_string(), host).await;
    }

    async fn del_by_ip(&mut self, ip: std::net::IpAddr) {
        let host = self.get_by_ip(ip).await.unwrap_or_default();
        self.0.delete_fake_ip_pair(&ip.to_string(), &host).await;
    }

    async fn exist(&mut self, ip: std::net::IpAddr) -> bool {
        self.0.get_fake_ip(&ip.to_string()).await.is_some()
    }

    async fn copy_to(&self, #[allow(unused)] store: &mut Box<dyn Store>) {
        // NO-OP
    }

    async fn flush(&mut self) {
        self.0.flush_fake_ip().await;
    }
}
