use std::{collections::HashMap, sync::Arc};

use serde::{Deserialize, Serialize};
use tracing::{error, trace, warn};

#[derive(Serialize, Deserialize, Debug, Clone)]
struct Db {
    #[serde(default)]
    selected: HashMap<String, String>,
    #[serde(default)]
    ip_to_host: HashMap<String, String>,
    #[serde(default)]
    host_to_ip: HashMap<String, String>,
    #[serde(default)]
    smart_stats: HashMap<String, crate::proxy::group::smart::state::SmartStateData>,
    #[serde(default)]
    smart_policy_priority: HashMap<String, String>,
}

#[derive(Clone)]
pub struct ThreadSafeCacheFile(Arc<tokio::sync::RwLock<CacheFile>>);

impl ThreadSafeCacheFile {
    pub fn new(path: &str, store_selected: bool) -> Self {
        let store = Arc::new(tokio::sync::RwLock::new(CacheFile::new(
            path,
            store_selected,
        )));

        let path = path.to_string();
        let store_clone = store.clone();

        if store_selected {
            tokio::spawn(async move {
                let store = store_clone;
                loop {
                    tokio::time::sleep(tokio::time::Duration::from_secs(10)).await;
                    let r = store.read().await;
                    let db = r.db.clone();
                    drop(r);

                    let s = match serde_yaml::to_string(&db) {
                        Ok(s) => s,
                        Err(e) => {
                            error!("failed to serialize cache file: {}", e);
                            continue;
                        }
                    };

                    match tokio::fs::write(&path, s).await {
                        Err(e) => {
                            error!("failed to write cache file: {}", e);
                        }
                        _ => {
                            trace!("cache file flushed to {}", path);
                        }
                    }
                }
            });
        }

        Self(store)
    }

    pub async fn set_selected(&self, group: &str, server: &str) {
        let mut g = self.0.write().await;
        if g.store_selected() {
            g.set_selected(group, server);
        }
    }

    pub async fn get_selected(&self, group: &str) -> Option<String> {
        let g = self.0.read().await;
        if g.store_selected() {
            g.db.selected.get(group).cloned()
        } else {
            None
        }
    }

    #[allow(dead_code)]
    pub async fn get_selected_map(&self) -> HashMap<String, String> {
        let g = self.0.read().await;
        if g.store_selected() {
            g.get_selected_map()
        } else {
            HashMap::new()
        }
    }

    pub async fn set_ip_to_host(&self, ip: &str, host: &str) {
        self.0.write().await.set_ip_to_host(ip, host);
    }

    pub async fn set_host_to_ip(&self, host: &str, ip: &str) {
        self.0.write().await.set_host_to_ip(host, ip);
    }

    pub async fn get_fake_ip(&self, ip_or_host: &str) -> Option<String> {
        self.0.read().await.get_fake_ip(ip_or_host)
    }

    pub async fn delete_fake_ip_pair(&self, ip: &str, host: &str) {
        self.0.write().await.delete_fake_ip_pair(ip, host);
    }

    pub async fn flush_fake_ip(&self) {
        self.0.write().await.flush_fake_ip();
    }

    /// Store smart proxy group statistics
    pub async fn set_smart_stats(
        &self,
        group_name: &str,
        stats: crate::proxy::group::smart::state::SmartStateData,
    ) {
        let mut g = self.0.write().await;
        g.set_smart_stats(group_name, stats);
    }

    /// Get smart proxy group statistics
    pub async fn get_smart_stats(
        &self,
        group_name: &str,
    ) -> Option<crate::proxy::group::smart::state::SmartStateData> {
        let g = self.0.read().await;
        g.get_smart_stats(group_name)
    }
}

struct CacheFile {
    db: Db,

    store_selected: bool,
}

impl CacheFile {
    pub fn new(path: &str, store_selected: bool) -> Self {
        let db = match std::fs::read_to_string(path) {
            Ok(s) => match serde_yaml::from_str(&s) {
                Ok(db) => db,
                Err(e) => {
                    error!(
                        "failed to parse cache file: {}, initializing a new one",
                        e
                    );
                    Db {
                        selected: HashMap::new(),
                        ip_to_host: HashMap::new(),
                        host_to_ip: HashMap::new(),
                        smart_stats: HashMap::new(),
                        smart_policy_priority: HashMap::new(),
                    }
                }
            },
            Err(e) => {
                warn!("failed to read cache file: {}, initializing a new one", e);
                Db {
                    selected: HashMap::new(),
                    ip_to_host: HashMap::new(),
                    host_to_ip: HashMap::new(),
                    smart_stats: HashMap::new(),
                    smart_policy_priority: HashMap::new(),
                }
            }
        };

        Self { db, store_selected }
    }

    pub fn store_selected(&self) -> bool {
        self.store_selected
    }

    pub fn set_selected(&mut self, group: &str, server: &str) {
        self.db
            .selected
            .insert(group.to_string(), server.to_string());
    }

    pub fn get_selected_map(&self) -> HashMap<String, String> {
        self.db.selected.clone()
    }

    pub fn set_ip_to_host(&mut self, ip: &str, host: &str) {
        self.db.ip_to_host.insert(ip.to_string(), host.to_string());
    }

    pub fn set_host_to_ip(&mut self, host: &str, ip: &str) {
        self.db.host_to_ip.insert(host.to_string(), ip.to_string());
    }

    pub fn get_fake_ip(&self, ip_or_host: &str) -> Option<String> {
        self.db
            .ip_to_host
            .get(ip_or_host)
            .or_else(|| self.db.host_to_ip.get(ip_or_host))
            .cloned()
    }

    pub fn delete_fake_ip_pair(&mut self, ip: &str, host: &str) {
        self.db.ip_to_host.remove(ip);
        self.db.host_to_ip.remove(host);
    }

    pub fn flush_fake_ip(&mut self) {
        self.db.ip_to_host.clear();
        self.db.host_to_ip.clear();
    }

    pub fn set_smart_stats(
        &mut self,
        group_name: &str,
        stats: crate::proxy::group::smart::state::SmartStateData,
    ) {
        self.db.smart_stats.insert(group_name.to_string(), stats);
    }

    pub fn get_smart_stats(
        &self,
        group_name: &str,
    ) -> Option<crate::proxy::group::smart::state::SmartStateData> {
        self.db.smart_stats.get(group_name).cloned()
    }
}
