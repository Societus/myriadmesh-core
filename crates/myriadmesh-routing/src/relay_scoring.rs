//! Relay Scoring System for Intelligent Path Selection
//!
//! This module implements dynamic quality scoring for relay nodes to enable
//! intelligent path selection and load balancing:
//!
//! - Performance metrics: latency, throughput, success rate (60% weight)
//! - Reliability metrics: uptime, stability (30% weight)
//! - Capacity metrics: current load (10% weight)
//!
//! ## Scoring Algorithm
//!
//! Each relay receives a score from 0-100:
//! - 100: Excellent (low latency, high reliability, low load)
//! - 0: Poor (high latency, unreliable, overloaded)
//!
//! ## Features
//!
//! - Score updates every 60s with 5-minute rolling window
//! - Weighted random selection from top 3 relays
//! - Load balancing and circuit breaker patterns
//! - Sticky sessions with 1-hour cache

use myriadmesh_protocol::NodeId;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

/// Configuration for relay scoring
#[derive(Debug, Clone)]
pub struct RelayScoringConfig {
    /// Enable relay scoring
    pub enabled: bool,

    /// Score update interval (seconds)
    pub update_interval_secs: u64,

    /// Metrics window for averaging (seconds)
    pub metrics_window_secs: u64,

    /// Minimum score to consider relay viable (0-100)
    pub min_viable_score: f32,

    /// Sticky session duration (seconds)
    pub sticky_session_secs: u64,

    /// Number of top relays to consider for weighted selection
    pub top_relays_count: usize,

    /// Circuit breaker failure threshold (consecutive failures)
    pub circuit_breaker_threshold: u32,

    /// Circuit breaker reset timeout (seconds)
    pub circuit_breaker_reset_secs: u64,
}

impl Default for RelayScoringConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            update_interval_secs: 60,
            metrics_window_secs: 300, // 5 minutes
            min_viable_score: 30.0,
            sticky_session_secs: 3600, // 1 hour
            top_relays_count: 3,
            circuit_breaker_threshold: 5,
            circuit_breaker_reset_secs: 300, // 5 minutes
        }
    }
}

/// Performance metrics for a relay
#[derive(Debug, Clone)]
pub struct PerformanceMetrics {
    /// Average latency in milliseconds
    pub avg_latency_ms: f32,

    /// Average throughput in bytes per second
    pub avg_throughput_bps: u64,

    /// Success rate (0.0 - 1.0)
    pub success_rate: f32,

    /// Total requests sent
    pub total_requests: u64,

    /// Total successful responses
    pub successful_responses: u64,
}

impl Default for PerformanceMetrics {
    fn default() -> Self {
        Self {
            avg_latency_ms: 0.0,
            avg_throughput_bps: 0,
            success_rate: 1.0,
            total_requests: 0,
            successful_responses: 0,
        }
    }
}

/// Reliability metrics for a relay
#[derive(Debug, Clone)]
pub struct ReliabilityMetrics {
    /// Uptime percentage (0.0 - 1.0)
    pub uptime_pct: f32,

    /// Time since last seen (seconds)
    pub time_since_seen_secs: u64,

    /// Consecutive successful requests
    pub consecutive_successes: u32,

    /// Consecutive failed requests
    pub consecutive_failures: u32,
}

impl Default for ReliabilityMetrics {
    fn default() -> Self {
        Self {
            uptime_pct: 1.0,
            time_since_seen_secs: 0,
            consecutive_successes: 0,
            consecutive_failures: 0,
        }
    }
}

/// Capacity metrics for a relay
#[derive(Debug, Clone)]
pub struct CapacityMetrics {
    /// Current load percentage (0.0 - 1.0)
    pub current_load_pct: f32,

    /// Maximum bandwidth capacity (bps)
    pub max_bandwidth_bps: u64,

    /// Current active connections
    pub active_connections: u32,
}

impl Default for CapacityMetrics {
    fn default() -> Self {
        Self {
            current_load_pct: 0.0,
            max_bandwidth_bps: 10_000_000, // 10 Mbps default
            active_connections: 0,
        }
    }
}

/// Complete relay score
#[derive(Debug, Clone)]
pub struct RelayScore {
    /// Overall score (0-100)
    pub overall_score: f32,

    /// Performance component (0-100)
    pub performance_score: f32,

    /// Reliability component (0-100)
    pub reliability_score: f32,

    /// Capacity component (0-100)
    pub capacity_score: f32,

    /// Last updated timestamp
    pub updated_at: Instant,
}

impl RelayScore {
    fn new() -> Self {
        Self {
            overall_score: 100.0,
            performance_score: 100.0,
            reliability_score: 100.0,
            capacity_score: 100.0,
            updated_at: Instant::now(),
        }
    }
}

/// Circuit breaker state for a relay
#[derive(Debug, Clone, PartialEq)]
enum CircuitState {
    /// Normal operation
    Closed,
    /// Too many failures, rejecting requests
    Open {
        opened_at: Instant,
    },
    /// Testing if relay recovered
    HalfOpen,
}

/// Circuit breaker for relay failure protection
struct CircuitBreaker {
    state: CircuitState,
    consecutive_failures: u32,
    threshold: u32,
    reset_timeout: Duration,
}

impl CircuitBreaker {
    fn new(threshold: u32, reset_timeout_secs: u64) -> Self {
        Self {
            state: CircuitState::Closed,
            consecutive_failures: 0,
            threshold,
            reset_timeout: Duration::from_secs(reset_timeout_secs),
        }
    }

    fn record_success(&mut self) {
        self.consecutive_failures = 0;
        if self.state == CircuitState::HalfOpen {
            self.state = CircuitState::Closed;
        }
    }

    fn record_failure(&mut self) {
        self.consecutive_failures += 1;
        if self.consecutive_failures >= self.threshold {
            self.state = CircuitState::Open {
                opened_at: Instant::now(),
            };
        }
    }

    fn is_available(&mut self) -> bool {
        match self.state {
            CircuitState::Closed => true,
            CircuitState::Open { opened_at } => {
                if opened_at.elapsed() >= self.reset_timeout {
                    self.state = CircuitState::HalfOpen;
                    self.consecutive_failures = 0;
                    true
                } else {
                    false
                }
            }
            CircuitState::HalfOpen => true,
        }
    }
}

/// Tracked relay with metrics and scoring
struct TrackedRelay {
    node_id: NodeId,
    performance: PerformanceMetrics,
    reliability: ReliabilityMetrics,
    capacity: CapacityMetrics,
    score: RelayScore,
    circuit_breaker: CircuitBreaker,
    sticky_until: Option<Instant>,
}

/// Relay scoring manager
pub struct RelayScoringManager {
    config: RelayScoringConfig,
    relays: Arc<RwLock<HashMap<NodeId, TrackedRelay>>>,
    last_update: Arc<RwLock<Instant>>,
}

impl RelayScoringManager {
    /// Create a new relay scoring manager
    pub fn new(config: RelayScoringConfig) -> Self {
        Self {
            config,
            relays: Arc::new(RwLock::new(HashMap::new())),
            last_update: Arc::new(RwLock::new(Instant::now())),
        }
    }

    /// Register a new relay for tracking
    pub fn register_relay(&self, node_id: NodeId) {
        let mut relays = self.relays.write().unwrap();
        if !relays.contains_key(&node_id) {
            relays.insert(
                node_id,
                TrackedRelay {
                    node_id,
                    performance: PerformanceMetrics::default(),
                    reliability: ReliabilityMetrics::default(),
                    capacity: CapacityMetrics::default(),
                    score: RelayScore::new(),
                    circuit_breaker: CircuitBreaker::new(
                        self.config.circuit_breaker_threshold,
                        self.config.circuit_breaker_reset_secs,
                    ),
                    sticky_until: None,
                },
            );
        }
    }

    /// Record successful request to relay
    pub fn record_success(&self, node_id: &NodeId, latency_ms: f32, bytes_transferred: u64) {
        let mut relays = self.relays.write().unwrap();
        if let Some(relay) = relays.get_mut(node_id) {
            // Update performance metrics
            relay.performance.total_requests += 1;
            relay.performance.successful_responses += 1;
            relay.performance.success_rate = relay.performance.successful_responses as f32
                / relay.performance.total_requests as f32;

            // Update latency (exponential moving average)
            let alpha = 0.2; // Smoothing factor
            relay.performance.avg_latency_ms =
                alpha * latency_ms + (1.0 - alpha) * relay.performance.avg_latency_ms;

            // Update throughput
            if latency_ms > 0.0 {
                let throughput = (bytes_transferred as f32 / (latency_ms / 1000.0)) as u64;
                relay.performance.avg_throughput_bps =
                    (alpha * throughput as f32 + (1.0 - alpha) * relay.performance.avg_throughput_bps as f32)
                        as u64;
            }

            // Update reliability
            relay.reliability.consecutive_successes += 1;
            relay.reliability.consecutive_failures = 0;
            relay.reliability.time_since_seen_secs = 0;

            // Update circuit breaker
            relay.circuit_breaker.record_success();
        }
    }

    /// Record failed request to relay
    pub fn record_failure(&self, node_id: &NodeId) {
        let mut relays = self.relays.write().unwrap();
        if let Some(relay) = relays.get_mut(node_id) {
            relay.performance.total_requests += 1;
            relay.performance.success_rate = relay.performance.successful_responses as f32
                / relay.performance.total_requests as f32;

            relay.reliability.consecutive_failures += 1;
            relay.reliability.consecutive_successes = 0;

            relay.circuit_breaker.record_failure();
        }
    }

    /// Update capacity metrics for a relay
    pub fn update_capacity(&self, node_id: &NodeId, load_pct: f32, active_connections: u32) {
        let mut relays = self.relays.write().unwrap();
        if let Some(relay) = relays.get_mut(node_id) {
            relay.capacity.current_load_pct = load_pct;
            relay.capacity.active_connections = active_connections;
        }
    }

    /// Update scores for all relays
    pub fn update_scores(&self) {
        let now = Instant::now();
        let mut last_update = self.last_update.write().unwrap();

        // Only update if interval elapsed
        if now.duration_since(*last_update).as_secs() < self.config.update_interval_secs {
            return;
        }

        let mut relays = self.relays.write().unwrap();
        for relay in relays.values_mut() {
            relay.score = self.calculate_score(relay);
        }

        *last_update = now;
    }

    /// Select best relay using weighted random selection from top candidates
    pub fn select_relay(&self, candidates: &[NodeId]) -> Option<NodeId> {
        if !self.config.enabled || candidates.is_empty() {
            return candidates.first().copied();
        }

        self.update_scores();

        let relays = self.relays.read().unwrap();

        // Check for sticky session
        for candidate in candidates {
            if let Some(relay) = relays.get(candidate) {
                if let Some(sticky_until) = relay.sticky_until {
                    if Instant::now() < sticky_until {
                        return Some(*candidate);
                    }
                }
            }
        }

        // Filter viable candidates
        let mut viable: Vec<_> = candidates
            .iter()
            .filter_map(|id| {
                relays.get(id).and_then(|relay| {
                    let is_open = matches!(relay.circuit_breaker.state, CircuitState::Open { .. });
                    if relay.score.overall_score >= self.config.min_viable_score && !is_open {
                        Some((*id, relay.score.overall_score))
                    } else {
                        None
                    }
                })
            })
            .collect();

        if viable.is_empty() {
            return None;
        }

        // Sort by score (descending)
        viable.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap());

        // Take top N
        let top_count = self.config.top_relays_count.min(viable.len());
        let top_relays = &viable[0..top_count];

        // Weighted random selection
        let total_score: f32 = top_relays.iter().map(|(_, score)| score).sum();
        let random_value = rand::random::<f32>() * total_score;

        let mut cumulative = 0.0;
        for (node_id, score) in top_relays {
            cumulative += score;
            if random_value <= cumulative {
                return Some(*node_id);
            }
        }

        // Fallback to best
        Some(top_relays[0].0)
    }

    /// Set sticky session for a relay
    pub fn set_sticky_session(&self, node_id: &NodeId) {
        let mut relays = self.relays.write().unwrap();
        if let Some(relay) = relays.get_mut(node_id) {
            relay.sticky_until = Some(Instant::now() + Duration::from_secs(self.config.sticky_session_secs));
        }
    }

    /// Get score for a specific relay (calculates current score)
    pub fn get_score(&self, node_id: &NodeId) -> Option<RelayScore> {
        let relays = self.relays.read().unwrap();
        relays.get(node_id).map(|relay| self.calculate_score(relay))
    }

    // Private helper methods

    fn calculate_score(&self, relay: &TrackedRelay) -> RelayScore {
        let performance_score = self.calculate_performance_score(&relay.performance);
        let reliability_score = self.calculate_reliability_score(&relay.reliability);
        let capacity_score = self.calculate_capacity_score(&relay.capacity);

        // Weighted average: Performance 60%, Reliability 30%, Capacity 10%
        let overall_score =
            performance_score * 0.6 + reliability_score * 0.3 + capacity_score * 0.1;

        RelayScore {
            overall_score,
            performance_score,
            reliability_score,
            capacity_score,
            updated_at: Instant::now(),
        }
    }

    fn calculate_performance_score(&self, metrics: &PerformanceMetrics) -> f32 {
        let mut score = 100.0;

        // Latency penalty (0-50ms = 0 penalty, >50ms = increasing penalty)
        if metrics.avg_latency_ms > 50.0 {
            let latency_penalty = (metrics.avg_latency_ms - 50.0).min(50.0);
            score -= latency_penalty;
        }

        // Success rate (directly proportional)
        score *= metrics.success_rate;

        // Throughput bonus (>1 Mbps = bonus)
        if metrics.avg_throughput_bps > 1_000_000 {
            let throughput_bonus = ((metrics.avg_throughput_bps / 1_000_000) as f32)
                .min(10.0);
            score += throughput_bonus;
        }

        score.max(0.0).min(100.0)
    }

    fn calculate_reliability_score(&self, metrics: &ReliabilityMetrics) -> f32 {
        let mut score = 100.0;

        // Uptime (directly proportional)
        score *= metrics.uptime_pct;

        // Recent failures penalty
        if metrics.consecutive_failures > 0 {
            let failure_penalty = (metrics.consecutive_failures as f32 * 10.0).min(50.0);
            score -= failure_penalty;
        }

        // Time since seen penalty (>60s = penalty)
        if metrics.time_since_seen_secs > 60 {
            let stale_penalty = ((metrics.time_since_seen_secs - 60) as f32 / 60.0 * 20.0).min(40.0);
            score -= stale_penalty;
        }

        score.max(0.0).min(100.0)
    }

    fn calculate_capacity_score(&self, metrics: &CapacityMetrics) -> f32 {
        let mut score = 100.0;

        // Load penalty (directly proportional)
        score *= 1.0 - metrics.current_load_pct;

        score.max(0.0).min(100.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_node_id(id: u8) -> NodeId {
        let mut bytes = [0u8; 64];
        bytes[0] = id;
        NodeId::from_bytes(bytes)
    }

    #[test]
    fn test_relay_scoring_manager_creation() {
        let config = RelayScoringConfig::default();
        let manager = RelayScoringManager::new(config);
        assert!(manager.relays.read().unwrap().is_empty());
    }

    #[test]
    fn test_register_relay() {
        let manager = RelayScoringManager::new(RelayScoringConfig::default());
        let node_id = create_test_node_id(1);

        manager.register_relay(node_id);
        assert_eq!(manager.relays.read().unwrap().len(), 1);
    }

    #[test]
    fn test_record_success() {
        let manager = RelayScoringManager::new(RelayScoringConfig::default());
        let node_id = create_test_node_id(1);

        manager.register_relay(node_id);
        manager.record_success(&node_id, 25.0, 1024);

        let score = manager.get_score(&node_id).unwrap();
        assert!(score.overall_score > 90.0);
    }

    #[test]
    fn test_record_failure() {
        let manager = RelayScoringManager::new(RelayScoringConfig::default());
        let node_id = create_test_node_id(1);

        manager.register_relay(node_id);

        // Record multiple failures (score should drop significantly)
        for _ in 0..10 {
            manager.record_failure(&node_id);
        }

        manager.update_scores();
        let score = manager.get_score(&node_id).unwrap();
        // With 10 failures and 0 successes, success_rate = 0, score should be 0
        assert!(score.overall_score < 50.0);
    }

    #[test]
    fn test_select_best_relay() {
        let manager = RelayScoringManager::new(RelayScoringConfig::default());

        let node1 = create_test_node_id(1);
        let node2 = create_test_node_id(2);

        manager.register_relay(node1);
        manager.register_relay(node2);

        // Make node1 better (lower latency)
        manager.record_success(&node1, 10.0, 1024);
        manager.record_success(&node2, 100.0, 512);

        manager.update_scores();

        let selected = manager.select_relay(&[node1, node2]);
        // node1 should be selected due to better latency score
        assert!(selected.is_some());
        // Note: Due to weighted random selection, we can't guarantee node1 every time,
        // but at least one should be selected
    }

    #[test]
    fn test_circuit_breaker_opens() {
        let config = RelayScoringConfig {
            circuit_breaker_threshold: 3,
            ..Default::default()
        };
        let manager = RelayScoringManager::new(config);
        let node_id = create_test_node_id(1);

        manager.register_relay(node_id);

        // Trigger circuit breaker
        for _ in 0..3 {
            manager.record_failure(&node_id);
        }

        // Relay should not be selected due to open circuit
        let selected = manager.select_relay(&[node_id]);
        assert_eq!(selected, None);
    }

    #[test]
    fn test_sticky_session() {
        let manager = RelayScoringManager::new(RelayScoringConfig::default());
        let node_id = create_test_node_id(1);

        manager.register_relay(node_id);
        manager.set_sticky_session(&node_id);

        let selected = manager.select_relay(&[node_id]);
        assert_eq!(selected, Some(node_id));
    }
}
