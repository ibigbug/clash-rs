use std::{
    collections::VecDeque,
    io,
    sync::{
        Mutex,
        atomic::{AtomicBool, AtomicU16, Ordering},
    },
    time::Duration,
};

use async_trait::async_trait;
use tracing::{debug, trace, warn};

use crate::{
    Error,
    app::{
        dispatcher::{BoxedInstrumentedDatagram, BoxedInstrumentedStream},
        dns::ThreadSafeDNSResolver,
        remote_content_manager::{
            ProxyManager, get_global_traffic_rate,
            providers::proxy_provider::ArcProxyProvider,
        },
    },
    proxy::{
        AnyOutboundHandler, ConnectorType, DialWithConnector, HandlerCommonOptions,
        OutboundHandler, OutboundType,
        group::{GroupProxyAPIResponse, selector::SelectorControl},
        utils::{RemoteConnector, provider_helper::get_proxies_from_providers},
    },
    session::Session,
};

// ============================================================================
// 自适应 tolerance 配置常量
// ============================================================================

/// 连续多少轮无切换后检查是否需要降级 tolerance
const ADAPTIVE_ROUNDS_THRESHOLD: u32 = 12;

/// 降级条件: 每轮 (当前延迟 - 最低延迟) 的平均值超过此阈值(ms)才降级
const ADAPTIVE_DIFF_THRESHOLD_MS: u64 = 20;

/// 降级后的 tolerance (ms)
const ADAPTIVE_LOW_TOLERANCE: u16 = 20;

/// 流量跳过阈值: 全局流量(含直连) > 此值(bytes/sec)时跳过此轮切换
/// 250 KB/s = 256000 bytes/sec
const TRAFFIC_SKIP_THRESHOLD_BPS: u64 = 250 * 1024;

// ============================================================================
// 自适应 tolerance 状态
// ============================================================================

/// 记录自适应 tolerance 的运行时状态
struct AdaptiveState {
    /// 自上次节点切换以来的轮数 (每检测到新 check_round 递增)
    rounds_since_switch: u32,
    /// 每轮的 (当前延迟 - 最低延迟) 差值(ms), 用于计算平均值
    delay_diffs: VecDeque<u64>,
    /// 当前生效的 tolerance (ms), 可能被自适应逻辑降低
    current_tolerance: u16,
    /// 上次处理的 check_round 值, 用于检测新一轮 healthcheck
    last_seen_round: u64,
}

impl AdaptiveState {
    fn new(base_tolerance: u16) -> Self {
        Self {
            rounds_since_switch: 0,
            delay_diffs: VecDeque::with_capacity(ADAPTIVE_ROUNDS_THRESHOLD as usize),
            current_tolerance: base_tolerance,
            last_seen_round: 0,
        }
    }

    /// 记录一轮的延迟差值, 并检查是否触发降级
    /// 返回 true 表示发生了切换 (调用方应重置状态)
    fn record_round(&mut self, diff_ms: u64, switched: bool, base_tolerance: u16) {
        if switched {
            // 发生了切换: 重置状态, 恢复基础 tolerance
            self.rounds_since_switch = 0;
            self.delay_diffs.clear();
            self.current_tolerance = base_tolerance;
            debug!(
                "adaptive: switch detected, tolerance reset to {}ms",
                base_tolerance
            );
            return;
        }

        self.rounds_since_switch = self.rounds_since_switch.saturating_add(1);
        self.delay_diffs.push_back(diff_ms);
        // 只保留最近 ADAPTIVE_ROUNDS_THRESHOLD 轮的数据
        if self.delay_diffs.len() > ADAPTIVE_ROUNDS_THRESHOLD as usize {
            self.delay_diffs.pop_front();
        }

        // 检查降级条件: 连续 N 轮无切换 且 平均差值 > 阈值
        if self.rounds_since_switch >= ADAPTIVE_ROUNDS_THRESHOLD
            && self.delay_diffs.len() >= ADAPTIVE_ROUNDS_THRESHOLD as usize
        {
            let avg_diff: f64 = self.delay_diffs.iter().sum::<u64>() as f64
                / self.delay_diffs.len() as f64;
            if avg_diff > ADAPTIVE_DIFF_THRESHOLD_MS as f64
                && self.current_tolerance > ADAPTIVE_LOW_TOLERANCE
            {
                self.current_tolerance = ADAPTIVE_LOW_TOLERANCE;
                debug!(
                    avg_diff_ms = avg_diff,
                    rounds = self.rounds_since_switch,
                    new_tolerance = ADAPTIVE_LOW_TOLERANCE,
                    "adaptive: tolerance lowered (no switch for {} rounds, avg \
                     diff {:.1}ms > {}ms)",
                    self.rounds_since_switch,
                    avg_diff,
                    ADAPTIVE_DIFF_THRESHOLD_MS
                );
            }
        }
    }
}

#[derive(Default)]
pub struct HandlerOptions {
    pub common_opts: HandlerCommonOptions,
    pub name: String,
    pub udp: bool,
}

pub struct Handler {
    opts: HandlerOptions,
    /// 基础 tolerance (配置值, 如 30ms), 切换后恢复到此值
    base_tolerance: u16,
    providers: Vec<ArcProxyProvider>,
    proxy_manager: ProxyManager,
    fastest_proxy_index: AtomicU16,
    /// 自适应 tolerance 运行时状态
    /// PoisonError 时 lock() 返回 Err, if let Ok 静默降级到 base_tolerance
    /// (概率极低, 临界区仅算术操作, 降级行为可接受)
    adaptive_state: Mutex<AdaptiveState>,
    /// 手动测速后强制切换标志 (API 调用 force_fastest() 设置)
    force_switch: AtomicBool,
    /// 手动锁定节点名称 (用户通过 PUT /proxies/AUTO 手动选择节点时设置)
    /// Some(name) = 锁定到指定节点名称, fastest() 返回该节点不自动切换
    /// None = 自动模式 (默认)
    manual_lock: Mutex<Option<String>>,
}

impl std::fmt::Debug for Handler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UrlTest")
            .field("name", &self.opts.name)
            .field("base_tolerance", &self.base_tolerance)
            .finish()
    }
}

impl Handler {
    pub fn new(
        opts: HandlerOptions,
        tolerance: u16,
        providers: Vec<ArcProxyProvider>,
        proxy_manager: ProxyManager,
    ) -> Self {
        Self {
            opts,
            base_tolerance: tolerance,
            providers,
            proxy_manager,
            fastest_proxy_index: AtomicU16::new(0),
            adaptive_state: Mutex::new(AdaptiveState::new(tolerance)),
            force_switch: AtomicBool::new(false),
            manual_lock: Mutex::new(None),
        }
    }

    async fn get_proxies(&self, touch: bool) -> Vec<AnyOutboundHandler> {
        get_proxies_from_providers(&self.providers, touch).await
    }

    /// 选择最快节点, 包含自适应 tolerance + 流量跳过 + 强制切换逻辑
    ///
    /// # 切换决策优先级
    /// 1. **强制切换** (force_switch=true): 手动测速后,
    ///    忽略所有条件直接选最低延迟
    /// 2. **流量跳过**: 代理流量 > 250KB/s 时, 跳过此轮切换 (保持当前节点)
    /// 3. **自适应 tolerance**:
    ///    - 基础 tolerance = 30ms (配置值)
    ///    - 连续 12 轮无切换 且 平均延迟差 > 20ms → 降到 20ms
    ///    - 发生切换后恢复 30ms
    /// 4. **正常 tolerance 逻辑**: 当前延迟 > (最低延迟 + tolerance) 才切换
    async fn fastest(&self, touch: bool) -> Option<AnyOutboundHandler> {
        let proxy_manager = self.proxy_manager.clone();

        let proxies = self.get_proxies(touch).await;
        if proxies.is_empty() {
            return None;
        }

        // --- 检查手动锁定 (用户通过 PUT /proxies/AUTO 手动选择节点) ---
        // 锁定时: 返回锁定的节点, 不进行自动切换
        // 若锁定的节点已被移除, 则清除锁定并恢复自动选择
        if let Ok(mut lock) = self.manual_lock.lock()
            && let Some(locked_name) = lock.clone()
        {
            if let Some((idx, proxy)) = proxies
                .iter()
                .enumerate()
                .find(|(_, p)| p.name() == locked_name)
            {
                self.fastest_proxy_index
                    .store(idx as u16, Ordering::Relaxed);
                return Some(proxy.clone());
            } else {
                *lock = None;
                warn!(
                    locked_name = locked_name,
                    "manual_lock: node no longer exists, lock cleared"
                );
            }
        }

        let current_fastest_index = std::cmp::min(
            self.fastest_proxy_index
                .load(std::sync::atomic::Ordering::Relaxed),
            proxies.len() as u16 - 1,
        ) as usize;

        let mut fastest = None;
        let mut current_alive = false;
        let mut current_delay = Duration::MAX;
        for (index, proxy) in proxies.iter().enumerate() {
            let (alive, delay) =
                proxy_manager.alive_and_last_delay(proxy.name()).await;
            if index == current_fastest_index {
                current_alive = alive;
            }
            if !alive {
                continue;
            }

            let delay = delay.unwrap_or(Duration::MAX);
            if index == current_fastest_index {
                current_delay = delay;
            }
            if match fastest {
                None => true,
                Some((_, fastest_delay)) => delay < fastest_delay,
            } {
                fastest = Some((index, delay));
            }
        }

        // --- 检查强制切换标志 (手动测速触发) ---
        // Fix(2026-08-04): when every proxy failed the manual test (fastest is
        // None), do NOT force-switch to index 0 (possibly dead) - keep current.
        let force_switch = self.force_switch.swap(false, Ordering::Relaxed);
        if force_switch {
            if let Some((fastest_index, fastest_delay)) = fastest {
                warn!(
                    fastest = %proxies[fastest_index].name(),
                    delay = ?fastest_delay,
                    from = %proxies[current_fastest_index].name(),
                    "force_switch: manual test triggered, selecting fastest"
                );
                self.fastest_proxy_index
                    .store(fastest_index as u16, Ordering::Relaxed);
                // 重置自适应状态
                if let Ok(mut state) = self.adaptive_state.lock() {
                    state.rounds_since_switch = 0;
                    state.delay_diffs.clear();
                    state.current_tolerance = self.base_tolerance;
                }
                return Some(proxies[fastest_index].clone());
            } else {
                warn!(
                    from = %proxies[current_fastest_index].name(),
                    "force_switch: all proxies failed manual test, keeping current"
                );
                return Some(proxies[current_fastest_index].clone());
            }
        }

        let (fastest_index, fastest_delay) = fastest.unwrap_or((0, Duration::MAX));

        // --- 检查全局流量速率, 决定是否跳过此轮切换 ---
        let traffic_rate = get_global_traffic_rate();
        let traffic_skip = traffic_rate > TRAFFIC_SKIP_THRESHOLD_BPS;

        // --- 获取当前 tolerance (可能被自适应降低) ---
        let effective_tolerance = if let Ok(state) = self.adaptive_state.lock() {
            state.current_tolerance
        } else {
            self.base_tolerance
        };

        // --- 检测是否是新一轮 healthcheck ---
        // 流量高时不更新 last_seen_round, 等流量降低后再处理该轮次
        // (避免流量跳过导致自适应数据永久丢失)
        let current_round = proxy_manager.check_round();
        let is_new_round = if !traffic_skip {
            if let Ok(mut state) = self.adaptive_state.lock() {
                if current_round != state.last_seen_round {
                    state.last_seen_round = current_round;
                    true
                } else {
                    false
                }
            } else {
                false
            }
        } else {
            false
        };

        // --- tolerance 切换决策 ---
        let tolerance = Duration::from_millis(effective_tolerance as u64);
        let switch_threshold = fastest_delay
            .checked_add(tolerance)
            .unwrap_or(Duration::MAX);

        // 是否应该切换到最快节点 (基于 tolerance 逻辑)
        let should_switch_by_tolerance =
            !current_alive || current_delay > switch_threshold;

        // 流量高时跳过切换 (但仍然更新 fastest_proxy_index 用于查询)
        let selected_index = if traffic_skip {
            // 流量 > 250KB/s: 跳过此轮切换, 保持当前节点
            // (除非当前节点已死亡, 此时必须切换)
            if !current_alive {
                fastest_index
            } else {
                current_fastest_index
            }
        } else if should_switch_by_tolerance {
            fastest_index
        } else {
            current_fastest_index
        };

        // --- 检测是否发生了切换 ---
        let switched = selected_index != current_fastest_index;

        // --- 发生切换时重置自适应状态 (无论是否 traffic_skip) ---
        // 修复: traffic_skip + 当前死亡时的 emergency 切换也需要重置, 否则
        // rounds_since_switch 不归零会导致后续过早降级 tolerance
        if switched && let Ok(mut state) = self.adaptive_state.lock() {
            state.rounds_since_switch = 0;
            state.delay_diffs.clear();
            state.current_tolerance = self.base_tolerance;
        }

        // --- 记录自适应状态 (仅在新一轮 healthcheck 且非流量跳过时) ---
        if is_new_round && !traffic_skip {
            // 计算当前延迟与最低延迟的差值(ms)
            let diff_ms = if current_delay != Duration::MAX
                && fastest_delay != Duration::MAX
            {
                current_delay.saturating_sub(fastest_delay).as_millis() as u64
            } else {
                0
            };

            if let Ok(mut state) = self.adaptive_state.lock() {
                state.record_round(diff_ms, switched, self.base_tolerance);
            }
        }

        self.fastest_proxy_index
            .store(selected_index as u16, Ordering::Relaxed);

        let selected = &proxies[selected_index];
        let selected_delay = if selected_index == fastest_index {
            fastest_delay
        } else {
            current_delay
        };

        if traffic_skip && switched {
            // 流量高但当前节点死亡, 紧急切换到最快节点
            debug!(
                from = %proxies[current_fastest_index].name(),
                to = %selected.name(),
                delay = ?selected_delay,
                traffic_rate_kibps = traffic_rate / 1024,
                "traffic skip but current died, emergency switch to fastest"
            );
        } else if traffic_skip {
            trace!(
                traffic_rate_kibps = traffic_rate / 1024,
                current = %selected.name(),
                "traffic skip: >250KB/s, keeping current node"
            );
        } else if switched {
            debug!(
                from = %proxies[current_fastest_index].name(),
                to = %selected.name(),
                delay = ?selected_delay,
                tolerance_ms = effective_tolerance,
                "switched node"
            );
        }

        trace!(
            fastest = %selected.name(),
            delay = ?selected_delay,
            tolerance_ms = effective_tolerance,
            traffic_kibps = traffic_rate / 1024,
            "`{}` fastest",
            self.name(),
        );

        Some(selected.clone())
    }
}

impl DialWithConnector for Handler {}

#[async_trait]
impl OutboundHandler for Handler {
    fn name(&self) -> &str {
        &self.opts.name
    }

    fn proto(&self) -> OutboundType {
        OutboundType::UrlTest
    }

    async fn support_udp(&self) -> bool {
        if self.opts.udp {
            return true;
        }
        match self.fastest(false).await {
            Some(fastest) => fastest.support_udp().await,
            None => false,
        }
    }

    async fn connect_stream(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
    ) -> io::Result<BoxedInstrumentedStream> {
        let fastest = self.fastest(false).await.ok_or_else(|| {
            io::Error::other(format!("no proxy found for {}", self.name()))
        })?;
        let s = fastest.connect_stream(sess, resolver).await?;

        s.append_to_chain(self.name()).await;

        Ok(s)
    }

    async fn connect_datagram(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
    ) -> io::Result<BoxedInstrumentedDatagram> {
        let fastest = self.fastest(false).await.ok_or_else(|| {
            io::Error::other(format!("no proxy found for {}", self.name()))
        })?;
        let d = fastest.connect_datagram(sess, resolver).await?;

        d.append_to_chain(self.name()).await;

        Ok(d)
    }

    async fn support_connector(&self) -> ConnectorType {
        match self.fastest(false).await {
            Some(fastest) => fastest.support_connector().await,
            None => ConnectorType::Tcp,
        }
    }

    async fn connect_stream_with_connector(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
        connector: &dyn RemoteConnector,
    ) -> io::Result<BoxedInstrumentedStream> {
        let s = self
            .fastest(true)
            .await
            .ok_or_else(|| {
                io::Error::other(format!("no proxy found for {}", self.name()))
            })?
            .connect_stream_with_connector(sess, resolver, connector)
            .await?;

        s.append_to_chain(self.name()).await;
        Ok(s)
    }

    async fn connect_datagram_with_connector(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
        connector: &dyn RemoteConnector,
    ) -> io::Result<BoxedInstrumentedDatagram> {
        self.fastest(true)
            .await
            .ok_or_else(|| {
                io::Error::other(format!("no proxy found for {}", self.name()))
            })?
            .connect_datagram_with_connector(sess, resolver, connector)
            .await
    }

    fn try_as_group_handler(&self) -> Option<&dyn GroupProxyAPIResponse> {
        Some(self as _)
    }
}

#[async_trait]
impl GroupProxyAPIResponse for Handler {
    async fn get_proxies(&self) -> Vec<AnyOutboundHandler> {
        Handler::get_proxies(self, false).await
    }

    async fn get_active_proxy(&self) -> Option<AnyOutboundHandler> {
        self.fastest(false).await
    }

    fn get_latency_test_url(&self) -> Option<String> {
        self.opts.common_opts.url.clone()
    }

    fn icon(&self) -> Option<String> {
        self.opts.common_opts.icon.clone()
    }

    /// 手动测速后设置强制切换标志
    /// 下次 fastest() 调用时将忽略 tolerance, 直接选择最低延迟节点
    fn force_fastest(&self) {
        self.force_switch.store(true, Ordering::Relaxed);
        warn!("force_fastest: flag set, will switch on next fastest() call");
    }
}

#[async_trait]
impl SelectorControl for Handler {
    /// 手动选择节点 (锁定到指定节点)
    /// PUT /proxies/AUTO {"name": "JP01"} 会调用此方法
    /// 锁定后 fastest() 将始终返回该节点, 不自动切换
    /// 传入空字符串 "" 或不存在的 "auto"/"default" 恢复自动模式
    async fn select(&self, name: &str) -> Result<(), Error> {
        let proxies = self.get_proxies(false).await;
        if name.is_empty()
            || (!proxies.iter().any(|p| p.name() == name)
                && (name.eq_ignore_ascii_case("auto")
                    || name.eq_ignore_ascii_case("default")))
        {
            if let Ok(mut lock) = self.manual_lock.lock() {
                *lock = None;
                warn!("manual_lock: cleared, resuming auto mode");
                return Ok(());
            } else {
                return Err(Error::Operation("manual_lock poisoned".to_string()));
            }
        }

        if let Some((idx, proxy)) =
            proxies.iter().enumerate().find(|(_, p)| p.name() == name)
        {
            if let Ok(mut lock) = self.manual_lock.lock() {
                *lock = Some(proxy.name().to_string());
                self.fastest_proxy_index
                    .store(idx as u16, Ordering::Relaxed);
                warn!(node = name, "manual_lock: locked to node");
                Ok(())
            } else {
                Err(Error::Operation("manual_lock poisoned".to_string()))
            }
        } else {
            Err(Error::Operation(format!("proxy {name} not found")))
        }
    }

    #[cfg(test)]
    async fn current(&self) -> String {
        let proxies = self.get_proxies(false).await;
        let idx = self.fastest_proxy_index.load(Ordering::Relaxed) as usize;
        proxies
            .get(idx)
            .map(|p| p.name().to_string())
            .unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use std::{sync::Arc, time::Duration};

    use crate::{
        app::remote_content_manager::ProxyManager,
        proxy::{
            AnyOutboundHandler,
            group::GroupProxyAPIResponse,
            mocks::MockDummyProxyProvider,
            utils::test_utils::noop::{NoopOutboundHandler, NoopResolver},
        },
    };

    #[tokio::test]
    async fn test_empty_provider_returns_none_active_proxy() {
        let mut provider = MockDummyProxyProvider::new();
        provider.expect_name().return_const("provider1".to_owned());
        provider.expect_proxies().returning(Vec::new);

        let proxy_manager = ProxyManager::new(Arc::new(NoopResolver), None);
        let handler = super::Handler::new(
            super::HandlerOptions {
                name: "test".to_owned(),
                udp: true,
                ..Default::default()
            },
            0,
            vec![Arc::new(provider)],
            proxy_manager,
        );

        assert!(handler.get_active_proxy().await.is_none());
    }

    #[tokio::test]
    async fn test_tolerance_and_liveness_select_proxy() {
        let proxies: Vec<AnyOutboundHandler> = vec![
            Arc::new(NoopOutboundHandler { name: "a".into() }),
            Arc::new(NoopOutboundHandler { name: "b".into() }),
        ];
        let mut provider = MockDummyProxyProvider::new();
        provider.expect_proxies().returning({
            let proxies = proxies.clone();
            move || proxies.clone()
        });

        let proxy_manager = ProxyManager::new(Arc::new(NoopResolver), None);
        proxy_manager
            .report_delay("a", true, Duration::from_millis(100))
            .await;
        proxy_manager
            .report_delay("b", true, Duration::from_millis(50))
            .await;
        let handler = super::Handler::new(
            super::HandlerOptions {
                name: "url-test".to_owned(),
                ..Default::default()
            },
            20,
            vec![Arc::new(provider)],
            proxy_manager.clone(),
        );

        assert_eq!(handler.get_active_proxy().await.unwrap().name(), "b");

        proxy_manager
            .report_delay("a", true, Duration::from_millis(40))
            .await;
        assert_eq!(handler.get_active_proxy().await.unwrap().name(), "b");

        proxy_manager
            .report_delay("a", true, Duration::from_millis(20))
            .await;
        assert_eq!(handler.get_active_proxy().await.unwrap().name(), "a");

        proxy_manager
            .report_delay("a", false, Duration::from_millis(20))
            .await;
        assert_eq!(handler.get_active_proxy().await.unwrap().name(), "b");

        proxy_manager
            .report_delay("b", false, Duration::from_millis(50))
            .await;
        assert_eq!(handler.get_active_proxy().await.unwrap().name(), "a");
    }

    #[tokio::test]
    async fn test_force_fastest_ignores_tolerance() {
        let proxies: Vec<AnyOutboundHandler> = vec![
            Arc::new(NoopOutboundHandler { name: "a".into() }),
            Arc::new(NoopOutboundHandler { name: "b".into() }),
        ];
        let mut provider = MockDummyProxyProvider::new();
        provider.expect_proxies().returning({
            let proxies = proxies.clone();
            move || proxies.clone()
        });

        let proxy_manager = ProxyManager::new(Arc::new(NoopResolver), None);
        // a=100ms, b=110ms, tolerance=50ms → 正常不切换, 选 a
        proxy_manager
            .report_delay("a", true, Duration::from_millis(100))
            .await;
        proxy_manager
            .report_delay("b", true, Duration::from_millis(110))
            .await;
        let handler = super::Handler::new(
            super::HandlerOptions {
                name: "url-test".to_owned(),
                ..Default::default()
            },
            50,
            vec![Arc::new(provider)],
            proxy_manager.clone(),
        );

        // 初始选择 a (延迟最低)
        assert_eq!(handler.get_active_proxy().await.unwrap().name(), "a");

        // b 变成 95ms (差值 5ms < tolerance 50ms, 正常不切换)
        proxy_manager
            .report_delay("b", true, Duration::from_millis(95))
            .await;
        assert_eq!(handler.get_active_proxy().await.unwrap().name(), "a");

        // 手动测速触发强制切换 → 选 b (现在最快)
        handler.force_fastest();
        assert_eq!(handler.get_active_proxy().await.unwrap().name(), "b");
    }

    #[tokio::test]
    async fn test_manual_lock_by_name_and_unlock() {
        use crate::proxy::group::selector::SelectorControl;

        let proxies: Vec<AnyOutboundHandler> = vec![
            Arc::new(NoopOutboundHandler { name: "a".into() }),
            Arc::new(NoopOutboundHandler { name: "b".into() }),
        ];
        let mut provider = MockDummyProxyProvider::new();
        provider.expect_proxies().returning({
            let proxies = proxies.clone();
            move || proxies.clone()
        });

        let proxy_manager = ProxyManager::new(Arc::new(NoopResolver), None);
        // a=100ms, b=50ms -> b is faster
        proxy_manager
            .report_delay("a", true, Duration::from_millis(100))
            .await;
        proxy_manager
            .report_delay("b", true, Duration::from_millis(50))
            .await;
        let handler = super::Handler::new(
            super::HandlerOptions {
                name: "url-test".to_owned(),
                ..Default::default()
            },
            20,
            vec![Arc::new(provider)],
            proxy_manager.clone(),
        );

        // Initially b is chosen
        assert_eq!(handler.get_active_proxy().await.unwrap().name(), "b");

        // Manually lock to "a"
        handler.select("a").await.unwrap();
        assert_eq!(handler.get_active_proxy().await.unwrap().name(), "a");

        // force_fastest() should NOT clear manual_lock
        handler.force_fastest();
        assert_eq!(handler.get_active_proxy().await.unwrap().name(), "a");

        // Unlock by selecting empty string or "auto"
        handler.select("").await.unwrap();
        assert_eq!(handler.get_active_proxy().await.unwrap().name(), "b");
    }
}
