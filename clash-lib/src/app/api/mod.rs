use std::sync::{Arc, RwLock};

use tokio::sync::broadcast::Sender;

use super::{dispatcher::StatisticsManager, logging::LogEvent};
use crate::RuntimeComponents;

#[cfg(feature = "dashboard")]
mod embedded_dashboard;
mod handlers;
mod ipc;
mod middlewares;
mod runner;
mod tcp;
mod websocket;

pub use runner::ApiRunner;

pub struct AppState {
    pub log_source_tx: Sender<LogEvent>,
    pub components: Arc<RwLock<Arc<RuntimeComponents>>>,
}

impl AppState {
    pub fn statistics_manager(&self) -> Arc<StatisticsManager> {
        self.components.read().unwrap().statistics_manager.clone()
    }
}
