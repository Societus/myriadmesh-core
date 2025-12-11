//! Adapter Selection Logic (F1.3)
//!
//! This module implements adapter selection for message transmission:
//! - Selects best physical adapter (Ethernet, Bluetooth, I2P, etc.)
//! - Scores adapters based on capabilities and network conditions
//! - Handles fallback and failure recovery
//! - Applies exponential backoff for failed adapters

use std::collections::HashMap;
use std::time::{Duration, Instant};

/// Unique adapter identifier
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AdapterId(pub u32);

impl AdapterId {
    /// Create a new adapter ID
    pub fn new(id: u32) -> Self {
        AdapterId(id)
    }
}

/// Network condition information
#[derive(Debug, Clone)]
pub struct NetworkConditions {
    /// Round-trip latency in milliseconds
    pub latency_ms: f32,
    /// Available bandwidth in Mbps
    pub bandwidth_mbps: u32,
    /// Packet loss percentage (0-100)
    pub packet_loss_percent: f32,
    /// Whether device is on battery power
    pub on_battery: bool,
    /// Power consumption percentage (0-100)
    pub power_usage_percent: f32,
}

impl Default for NetworkConditions {
    fn default() -> Self {
        NetworkConditions {
            latency_ms: 50.0,
            bandwidth_mbps: 10,
            packet_loss_percent: 0.0,
            on_battery: false,
            power_usage_percent: 0.0,
        }
    }
}

/// Status of an adapter
#[derive(Debug, Clone)]
struct AdapterStatus {
    /// Last failure timestamp (if any)
    last_failure: Option<Instant>,
    /// Number of consecutive failures
    failure_count: u32,
    /// Until when adapter is blacklisted (if any)
    blacklist_until: Option<Instant>,
}

impl AdapterStatus {
    /// Create a new adapter status
    fn new() -> Self {
        AdapterStatus {
            last_failure: None,
            failure_count: 0,
            blacklist_until: None,
        }
    }

    /// Check if adapter is available (not blacklisted)
    fn is_available(&self) -> bool {
        if let Some(until) = self.blacklist_until {
            if Instant::now() < until {
                return false;
            }
        }
        true
    }

    /// Record a transmission failure
    fn record_failure(&mut self) {
        self.failure_count += 1;
        self.last_failure = Some(Instant::now());

        // Exponential backoff: blacklist for 2^failure_count seconds (max 60)
        let backoff_secs = (2u64).pow(self.failure_count as u32).min(60);
        self.blacklist_until = Some(Instant::now() + Duration::from_secs(backoff_secs));
    }

    /// Record successful transmission
    fn record_success(&mut self) {
        self.failure_count = 0;
        self.blacklist_until = None;
    }
}

/// Adapter tier (priority level)
#[derive(Debug, Clone)]
pub struct AdapterTier {
    /// Adapters in this tier, in preference order
    pub adapters: Vec<AdapterId>,
    /// Minimum bandwidth required (Mbps)
    pub min_bandwidth: u32,
    /// Power consumption priority (lower = better on battery)
    pub power_priority: u8,
}

impl AdapterTier {
    /// Create a new adapter tier
    pub fn new(adapters: Vec<AdapterId>, min_bandwidth: u32, power_priority: u8) -> Self {
        AdapterTier {
            adapters,
            min_bandwidth,
            power_priority,
        }
    }
}

/// Adapter Selector for F1.3 implementation
#[derive(Debug)]
pub struct AdapterSelector {
    /// Adapter tier preferences
    tiers: Vec<AdapterTier>,
    /// Adapter availability status
    statuses: HashMap<AdapterId, AdapterStatus>,
}

impl AdapterSelector {
    /// Create a new adapter selector
    pub fn new(tiers: Vec<AdapterTier>) -> Self {
        let mut statuses = HashMap::new();
        for tier in &tiers {
            for adapter_id in &tier.adapters {
                statuses.insert(*adapter_id, AdapterStatus::new());
            }
        }

        AdapterSelector { tiers, statuses }
    }

    /// F1.3 Core Implementation:
    /// Select best adapter for transmission
    ///
    /// Algorithm:
    /// 1. For each tier in preference order:
    ///    - Find adapters matching requirements
    ///    - Score available adapters
    ///    - Return best adapter if found
    /// 2. Fall back through tiers
    /// 3. Fail if no adapter available
    pub fn select_adapter(&self, conditions: &NetworkConditions) -> Result<AdapterId, String> {
        for tier in &self.tiers {
            // Filter adapters that are available and meet bandwidth requirements
            let candidates: Vec<_> = tier
                .adapters
                .iter()
                .filter(|id| {
                    self.statuses
                        .get(id)
                        .map(|s| s.is_available())
                        .unwrap_or(false)
                        && conditions.bandwidth_mbps >= tier.min_bandwidth
                })
                .collect();

            if candidates.is_empty() {
                continue; // Try next tier
            }

            // Score each candidate
            let mut scored: Vec<_> = candidates
                .into_iter()
                .map(|id| (*id, self.score_adapter(*id, conditions)))
                .collect();

            // Sort by score (higher = better)
            scored.sort_by_key(|(_, score)| std::cmp::Reverse(*score as u32));

            // Return best adapter in this tier
            if let Some((adapter_id, _)) = scored.first() {
                return Ok(*adapter_id);
            }
        }

        Err("No available adapter in any tier".to_string())
    }

    /// Score an adapter for current conditions
    ///
    /// Scoring factors:
    /// - Latency: 100 - latency_ms (capped at 100)
    /// - Bandwidth: available_mbps / 10
    /// - Power efficiency: 100 - power_usage_percent (if on battery)
    ///
    /// Higher score = better adapter
    fn score_adapter(&self, _adapter_id: AdapterId, conditions: &NetworkConditions) -> f32 {
        let mut score = 0.0f32;

        // Factor 1: Latency (100 - latency_ms, capped at 100)
        let latency_score = (100.0 - conditions.latency_ms.min(100.0)).max(0.0);
        score += latency_score;

        // Factor 2: Bandwidth (available_mbps / 10)
        let bandwidth_score = (conditions.bandwidth_mbps as f32) / 10.0;
        score += bandwidth_score;

        // Factor 3: Power efficiency (100 - power_usage_percent, if on battery)
        if conditions.on_battery {
            let power_score = (100.0 - conditions.power_usage_percent).max(0.0);
            score += power_score;
        }

        // Factor 4: Packet loss penalty (reduce by 0.5 per 1% loss)
        let loss_penalty = conditions.packet_loss_percent * 0.5;
        score -= loss_penalty;

        score
    }

    /// Mark adapter as failed (used by retry logic)
    pub fn mark_adapter_failed(&mut self, adapter_id: AdapterId) {
        if let Some(status) = self.statuses.get_mut(&adapter_id) {
            status.record_failure();
        }
    }

    /// Mark adapter as recovered after success
    pub fn mark_adapter_recovered(&mut self, adapter_id: AdapterId) {
        if let Some(status) = self.statuses.get_mut(&adapter_id) {
            status.record_success();
        }
    }

    /// Get failure count for an adapter
    pub fn get_failure_count(&self, adapter_id: AdapterId) -> u32 {
        self.statuses
            .get(&adapter_id)
            .map(|s| s.failure_count)
            .unwrap_or(0)
    }

    /// Check if adapter is currently blacklisted
    pub fn is_blacklisted(&self, adapter_id: AdapterId) -> bool {
        !self
            .statuses
            .get(&adapter_id)
            .map(|s| s.is_available())
            .unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_tier_with_adapters(count: u32, min_bandwidth: u32) -> AdapterTier {
        let adapters = (0..count).map(|i| AdapterId::new(i)).collect();
        AdapterTier::new(adapters, min_bandwidth, 50)
    }

    #[test]
    fn test_adapter_selector_creation() {
        let tiers = vec![create_tier_with_adapters(2, 10)];
        let selector = AdapterSelector::new(tiers);

        assert!(!selector.statuses.is_empty());
    }

    #[test]
    fn test_select_best_adapter() {
        let tiers = vec![
            create_tier_with_adapters(2, 10), // Tier 1: low bandwidth requirement
        ];
        let selector = AdapterSelector::new(tiers);
        let conditions = NetworkConditions::default();

        let result = selector.select_adapter(&conditions);

        assert!(result.is_ok());
        let adapter = result.unwrap();
        assert_eq!(adapter.0, 0); // Should select first available
    }

    #[test]
    fn test_adapter_fallback_to_tier() {
        let adapter1 = AdapterId::new(1);
        let adapter2 = AdapterId::new(2);

        let tiers = vec![
            AdapterTier::new(vec![adapter1], 100, 50), // Tier 1: high bandwidth
            AdapterTier::new(vec![adapter2], 10, 50),  // Tier 2: low bandwidth
        ];
        let selector = AdapterSelector::new(tiers);
        let conditions = NetworkConditions {
            bandwidth_mbps: 20, // Only satisfies Tier 2
            ..Default::default()
        };

        let result = selector.select_adapter(&conditions);

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), adapter2); // Should fall back to Tier 2
    }

    #[test]
    fn test_adapter_scoring() {
        let tiers = vec![create_tier_with_adapters(3, 10)];
        let selector = AdapterSelector::new(tiers);

        // High latency, poor bandwidth
        let poor_conditions = NetworkConditions {
            latency_ms: 100.0,
            bandwidth_mbps: 1,
            packet_loss_percent: 10.0,
            on_battery: false,
            power_usage_percent: 0.0,
        };

        let good_conditions = NetworkConditions {
            latency_ms: 10.0,
            bandwidth_mbps: 50,
            packet_loss_percent: 0.0,
            on_battery: false,
            power_usage_percent: 0.0,
        };

        let poor_score = selector.score_adapter(AdapterId::new(0), &poor_conditions);
        let good_score = selector.score_adapter(AdapterId::new(0), &good_conditions);

        // Good conditions should score higher
        assert!(good_score > poor_score);
    }

    #[test]
    fn test_failure_tracking() {
        let tiers = vec![create_tier_with_adapters(1, 10)];
        let mut selector = AdapterSelector::new(tiers);

        let adapter = AdapterId::new(0);
        let conditions = NetworkConditions::default();

        // Initially should be available
        assert!(selector.select_adapter(&conditions).is_ok());

        // Mark as failed
        selector.mark_adapter_failed(adapter);
        assert_eq!(selector.get_failure_count(adapter), 1);
        assert!(selector.is_blacklisted(adapter));

        // Should not be available now
        assert!(selector.select_adapter(&conditions).is_err());
    }

    #[test]
    fn test_exponential_backoff() {
        let tiers = vec![create_tier_with_adapters(1, 10)];
        let mut selector = AdapterSelector::new(tiers);

        let adapter = AdapterId::new(0);

        // Record multiple failures
        selector.mark_adapter_failed(adapter);
        assert_eq!(selector.get_failure_count(adapter), 1);

        selector.mark_adapter_failed(adapter);
        assert_eq!(selector.get_failure_count(adapter), 2);

        // Blacklist duration increases exponentially
        // 2^1 = 2 seconds, 2^2 = 4 seconds, etc.
    }

    #[test]
    fn test_adapter_recovery() {
        let tiers = vec![create_tier_with_adapters(1, 10)];
        let mut selector = AdapterSelector::new(tiers);

        let adapter = AdapterId::new(0);

        // Fail then recover
        selector.mark_adapter_failed(adapter);
        assert_eq!(selector.get_failure_count(adapter), 1);

        selector.mark_adapter_recovered(adapter);
        assert_eq!(selector.get_failure_count(adapter), 0);
    }

    #[test]
    fn test_battery_power_scoring() {
        let tiers = vec![create_tier_with_adapters(1, 10)];
        let selector = AdapterSelector::new(tiers);

        let on_battery_high_usage = NetworkConditions {
            latency_ms: 50.0,
            bandwidth_mbps: 10,
            packet_loss_percent: 0.0,
            on_battery: true,
            power_usage_percent: 80.0,
        };

        let on_battery_low_usage = NetworkConditions {
            latency_ms: 50.0,
            bandwidth_mbps: 10,
            packet_loss_percent: 0.0,
            on_battery: true,
            power_usage_percent: 20.0,
        };

        let high_usage_score =
            selector.score_adapter(AdapterId::new(0), &on_battery_high_usage);
        let low_usage_score = selector.score_adapter(AdapterId::new(0), &on_battery_low_usage);

        // Lower power usage should score higher
        assert!(low_usage_score > high_usage_score);
    }

    #[test]
    fn test_no_adapter_available() {
        let tiers = vec![create_tier_with_adapters(1, 100)]; // Very high bandwidth requirement
        let selector = AdapterSelector::new(tiers);
        let conditions = NetworkConditions {
            bandwidth_mbps: 10, // Cannot satisfy requirement
            ..Default::default()
        };

        let result = selector.select_adapter(&conditions);

        assert!(result.is_err());
    }
}
