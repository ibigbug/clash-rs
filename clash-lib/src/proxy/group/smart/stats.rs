//! Statistics and preference tracking for smart proxy group
//!
//! This module provides comprehensive statistics tracking and site preference
//! management, leveraging session traffic stats from the existing
//! infrastructure.

use std::{
    collections::{HashMap, VecDeque},
    time::{Duration, Instant},
};

use crate::{
    app::remote_content_manager::TrafficStats, common::utils::current_timestamp_secs,
};
use serde::{Deserialize, Serialize};

/// Unified site statistics and preference tracking
///
/// Combines performance metrics and site preference functionality,
/// utilizing traffic statistics from session data when available.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SiteStats {
    /// History of connection delays (milliseconds) - Public for bincode
    /// serialization
    pub delay_history: Vec<f64>,
    /// Track connection success/failure history - Public for bincode
    /// serialization
    pub success_history: Vec<bool>,
    /// Last time this site was accessed (Unix timestamp seconds)
    last_attempt_secs: u64,
}

const MAX_HISTORY_SIZE: usize = 10;

impl SiteStats {
    /// Create a new SiteStats instance
    pub fn new() -> Self {
        Self {
            delay_history: Vec::with_capacity(MAX_HISTORY_SIZE),
            success_history: Vec::with_capacity(MAX_HISTORY_SIZE),
            last_attempt_secs: current_timestamp_secs(),
        }
    }

    /// Calculate success rate for this site
    pub fn success_rate(&self) -> f64 {
        if self.success_history.is_empty() {
            return 1.0; // Optimistic default for new sites with no history
        }
        let success_count = self.success_history.iter().filter(|&&x| x).count();
        // Use integer arithmetic to avoid floating-point precision issues
        (success_count as f64) / (self.success_history.len() as f64)
    }

    /// Add a new connection result with optional session data
    ///
    /// Enhanced to utilize traffic statistics from session when available
    pub fn add_result(&mut self, delay: f64, success: bool) {
        // Update delay history (only for successful connections)
        if success {
            if self.delay_history.len() >= MAX_HISTORY_SIZE {
                self.delay_history.remove(0);
            }
            self.delay_history.push(delay);
        }

        // Update success history
        if self.success_history.len() >= MAX_HISTORY_SIZE {
            self.success_history.remove(0);
        }
        self.success_history.push(success);

        self.last_attempt_secs = current_timestamp_secs();
    }

    /// Check if stats are stale and should be cleaned up
    pub fn is_stale(&self) -> bool {
        let now_secs = current_timestamp_secs();
        // Use saturating_sub for u64 subtraction
        now_secs.saturating_sub(self.last_attempt_secs) > 300 // 5 minutes
    }

    /// Calculate weighted delay score considering recent history and success
    /// rate
    pub fn get_delay_score(&self) -> f64 {
        if self.delay_history.is_empty() {
            return 9999.0;
        }

        // Simple average of recorded delays.  The previous implementation used
        // a time_weight based on last_attempt_secs, but since delay_history
        // stores only values (not timestamps), every sample shared the same
        // age, making time_weight a constant scalar with no effect on the
        // relative weighting.  A plain average is the correct approach until
        // per-sample timestamps are tracked.
        let sum: f64 = self.delay_history.iter().sum();
        let avg_delay = sum / self.delay_history.len() as f64;

        // Adjust based on success rate
        let success_rate = self.success_rate();
        avg_delay * (2.0 - success_rate) // Higher success rate reduces effective delay
    }

    /// Get recent performance trend
    /// Calculate trend using linear regression for more accurate prediction
    pub fn get_trend(&self) -> i8 {
        if self.delay_history.len() < 3 {
            return 0; // Not enough data
        }

        // Calculate linear regression slope for delay history
        let mut sum_x = 0.0;
        let mut sum_y = 0.0;
        let mut sum_xy = 0.0;
        let mut sum_x2 = 0.0;
        let n = self.delay_history.len() as f64;

        for (i, &y) in self.delay_history.iter().enumerate() {
            let x = i as f64;
            sum_x += x;
            sum_y += y;
            sum_xy += x * y;
            sum_x2 += x * x;
        }

        let slope = (n * sum_xy - sum_x * sum_y) / (n * sum_x2 - sum_x * sum_x);

        // Determine trend based on slope
        if slope < -0.5 {
            1 // Improving: significant negative slope
        } else if slope > 0.5 {
            -1 // Degrading: significant positive slope
        } else {
            0 // Stable
        }
    }

    /// Calculate standard deviation of latency for stability metric
    pub fn latency_stability(&self) -> f64 {
        if self.delay_history.is_empty() {
            return 0.0;
        }

        let mean =
            self.delay_history.iter().sum::<f64>() / self.delay_history.len() as f64;
        let variance = self
            .delay_history
            .iter()
            .map(|&d| (d - mean).powi(2))
            .sum::<f64>()
            / self.delay_history.len() as f64;

        variance.sqrt()
    }
}

impl Default for SiteStats {
    fn default() -> Self {
        Self::new()
    }
}

/// Traffic statistics collector for real-time monitoring
///
/// Tracks traffic patterns, throughput, and connection characteristics
/// to support traffic-aware proxy selection decisions.
pub struct TrafficStatsCollector {
    /// Connection start time for duration calculation
    connection_start: HashMap<String, Instant>,
    /// Accumulated bytes per session (uploaded, downloaded)
    session_bytes: HashMap<String, (u64, u64)>,
    /// Request frequency tracking
    request_counts: HashMap<String, VecDeque<Instant>>,
    /// Throughput samples for bandwidth analysis
    throughput_samples: HashMap<String, VecDeque<(Instant, f64)>>,
}

impl TrafficStatsCollector {
    /// Create a new traffic statistics collector
    ///
    /// # Returns
    /// New TrafficStatsCollector instance
    pub fn new() -> Self {
        Self {
            connection_start: HashMap::new(),
            session_bytes: HashMap::new(),
            request_counts: HashMap::new(),
            throughput_samples: HashMap::new(),
        }
    }

    /// Start tracking a new session
    ///
    /// Initializes tracking data structures for a new connection session.
    /// Only initializes on first encounter — re-entering an existing session
    /// (e.g. during adaptive retry) preserves accumulated data.
    ///
    /// # Arguments
    /// * `session_id` - Unique identifier for the session
    pub fn start_session(&mut self, session_id: &str) {
        if self.connection_start.contains_key(session_id) {
            return; // Already tracking this session, preserve existing data
        }
        self.connection_start
            .insert(session_id.to_string(), Instant::now());
        self.session_bytes.insert(session_id.to_string(), (0, 0));
        self.request_counts
            .insert(session_id.to_string(), VecDeque::new());
        self.throughput_samples
            .insert(session_id.to_string(), VecDeque::new());
    }

    /// Record data transfer for a session
    ///
    /// Updates byte counters and calculates current throughput.
    ///
    /// # Arguments
    /// * `session_id` - Session identifier
    /// * `uploaded` - Bytes uploaded in this transfer
    /// * `downloaded` - Bytes downloaded in this transfer
    #[allow(dead_code)]
    pub fn record_transfer(
        &mut self,
        session_id: &str,
        uploaded: u64,
        downloaded: u64,
    ) {
        if let Some((up, down)) = self.session_bytes.get_mut(session_id) {
            *up += uploaded;
            *down += downloaded;

            // Calculate and record current throughput
            if let Some(start_time) = self.connection_start.get(session_id) {
                let elapsed = start_time.elapsed().as_secs_f64();
                if elapsed > 0.0 {
                    let current_throughput =
                        (uploaded + downloaded) as f64 / elapsed;
                    if let Some(samples) =
                        self.throughput_samples.get_mut(session_id)
                    {
                        samples.push_back((Instant::now(), current_throughput));
                        // Keep only last 10 samples
                        if samples.len() > 10 {
                            samples.pop_front();
                        }
                    }
                }
            }
        }
    }

    /// Record a request event for frequency calculation
    ///
    /// Tracks individual requests to calculate request frequency patterns.
    ///
    /// # Arguments
    /// * `session_id` - Session identifier
    pub fn record_request(&mut self, session_id: &str) {
        if let Some(requests) = self.request_counts.get_mut(session_id) {
            requests.push_back(Instant::now());
            // Keep only requests from last 60 seconds
            let cutoff = Instant::now() - Duration::from_secs(60);
            while let Some(&front_time) = requests.front() {
                if front_time < cutoff {
                    requests.pop_front();
                } else {
                    break;
                }
            }
        }
    }

    /// Generate traffic statistics for a session
    ///
    /// Compiles comprehensive traffic statistics including throughput,
    /// request frequency, and traffic characteristics.
    ///
    /// # Arguments
    /// * `session_id` - Session identifier
    ///
    /// # Returns
    /// `Some(TrafficStats)` if session exists, `None` otherwise
    pub fn get_stats(&self, session_id: &str) -> Option<TrafficStats> {
        let start_time = self.connection_start.get(session_id)?;
        let (uploaded, downloaded) = self.session_bytes.get(session_id)?;
        let connection_duration = start_time.elapsed();

        // Calculate average throughput
        let total_bytes = uploaded + downloaded;
        let average_throughput = if connection_duration.as_secs_f64() > 0.0 {
            total_bytes as f64 / connection_duration.as_secs_f64()
        } else {
            0.0
        };

        // Calculate peak throughput
        let peak_throughput = self
            .throughput_samples
            .get(session_id)
            .map(|samples| {
                samples
                    .iter()
                    .map(|(_, throughput)| *throughput)
                    .fold(0.0, f64::max)
            })
            .unwrap_or(0.0);

        // Calculate request frequency (requests per second)
        let request_frequency = self.request_counts.get(session_id)
            .map(|requests| requests.len() as f64 / 60.0) // requests per minute -> per second
            .unwrap_or(0.0);

        // Determine if traffic is bidirectional
        let is_bidirectional = if total_bytes > 0 {
            let upload_ratio = *uploaded as f64 / total_bytes as f64;
            upload_ratio > 0.1 && upload_ratio < 0.9 // Neither extremely upload nor download heavy
        } else {
            false
        };

        Some(TrafficStats {
            bytes_uploaded: *uploaded,
            bytes_downloaded: *downloaded,
            connection_duration,
            average_throughput,
            peak_throughput,
            request_frequency,
            is_bidirectional,
        })
    }

    /// Clean up old sessions to prevent memory leaks
    ///
    /// Removes session data older than 5 minutes to prevent
    /// unbounded memory growth.
    pub fn cleanup_old_sessions(&mut self) {
        let cutoff = Instant::now() - Duration::from_secs(300); // 5 minutes

        self.connection_start
            .retain(|_, start_time| *start_time > cutoff);
        self.session_bytes
            .retain(|session_id, _| self.connection_start.contains_key(session_id));
        self.request_counts
            .retain(|session_id, _| self.connection_start.contains_key(session_id));
        self.throughput_samples
            .retain(|session_id, _| self.connection_start.contains_key(session_id));
    }
}

impl Default for TrafficStatsCollector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_site_stats_success_rate() {
        let mut stats = SiteStats::new();

        stats.add_result(100.0, true);
        stats.add_result(150.0, true);
        stats.add_result(200.0, false);

        assert_eq!(stats.success_rate(), 2.0 / 3.0);
        assert!(stats.get_delay_score() > 0.0);
    }

    #[test]
    fn test_site_stats_delay_score() {
        let mut stats = SiteStats::new();

        stats.add_result(100.0, true);
        stats.add_result(200.0, true);
        stats.add_result(300.0, false); // Should not affect delay average

        // Delay score should be calculated from successful connections only
        let score = stats.get_delay_score();
        assert!(score > 0.0);
        assert!(score < 9999.0); // Should not be the default high value
    }

    #[test]
    fn test_site_stats_trend() {
        let mut stats = SiteStats::new();

        // Add older failures (not added to delay history)
        stats.add_result(100.0, false);
        stats.add_result(100.0, false);

        // Add recent successes with decreasing delays
        stats.add_result(150.0, true); // high delay
        stats.add_result(120.0, true); // medium delay
        stats.add_result(100.0, true); // low delay

        assert_eq!(stats.get_trend(), 1); // Improving
    }

    #[test]
    fn test_traffic_collector() {
        let mut collector = TrafficStatsCollector::new();

        collector.start_session("test-session");
        collector.record_transfer("test-session", 1000, 2000);
        collector.record_request("test-session");

        let stats = collector.get_stats("test-session");
        assert!(stats.is_some());

        let stats = stats.unwrap();
        assert_eq!(stats.bytes_uploaded, 1000);
        assert_eq!(stats.bytes_downloaded, 2000);
    }
}
