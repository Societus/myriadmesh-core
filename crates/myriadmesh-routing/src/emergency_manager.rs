//! Emergency message validation and abuse prevention
//!
//! This module implements the EmergencyManager component which validates emergency
//! messages against a 7-step process including realm validation, legitimacy exemptions,
//! bandwidth-aware exemptions, quota enforcement, and size-based penalty modulation.

use crate::bandwidth_monitor::BandwidthMonitor;
use crate::consensus_validator::ConsensusValidator;
use crate::error::{Result, RoutingError};
use crate::reputation::ReputationScore;
use myriadmesh_protocol::{EmergencyRealm, Message, NodeId, RealmTier};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

/// Configuration for EmergencyManager
#[derive(Debug, Clone)]
pub struct EmergencyManagerConfig {
    /// Enable emergency message validation
    pub enabled: bool,

    /// Enable size-based penalty modulation
    pub size_modulation_enabled: bool,

    /// Number of emergencies per day before quota enforcement applies
    /// Default: 3 (first 3 emergencies bypass quotas)
    pub infrequent_allowance: u32,

    /// Reputation threshold for automatic approval
    /// Default: 0.8 (nodes with score >0.8 bypass quotas)
    pub high_reputation_threshold: f64,

    /// Enable bandwidth-aware exemptions for Individual/Family realms
    pub bandwidth_exemption_enabled: bool,

    /// Minimum bandwidth (bps) for high-speed exemption eligibility
    /// Default: 10 Mbps
    pub high_speed_threshold_bps: u64,

    /// Maximum bandwidth utilization for exemption eligibility
    /// Default: 0.4 (40% utilized = 60% unused)
    pub unused_bandwidth_threshold: f64,
}

impl Default for EmergencyManagerConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            size_modulation_enabled: true,
            infrequent_allowance: 3,
            high_reputation_threshold: 0.8,
            bandwidth_exemption_enabled: true,
            high_speed_threshold_bps: 10_000_000, // 10 Mbps
            unused_bandwidth_threshold: 0.4,       // 40% utilized
        }
    }
}

/// Result of emergency message validation
#[derive(Debug, Clone, PartialEq)]
pub enum EmergencyValidation {
    /// Allow the emergency message to proceed
    Allow,

    /// Allow with bandwidth exemption (quota bypassed)
    AllowBandwidthExemption {
        adapter_name: String,
        utilization: f64,
    },

    /// Downgrade to High priority (quota exceeded but not rejected)
    Downgrade { reason: String },

    /// Reject the emergency message
    Reject { reason: String },
}

/// Per-realm quota tracking
#[derive(Debug, Clone)]
struct RealmQuotaUsage {
    /// Messages sent in current hour
    count: u32,
    /// Start of current hour window
    window_start: Instant,
}

impl RealmQuotaUsage {
    fn new() -> Self {
        Self {
            count: 0,
            window_start: Instant::now(),
        }
    }

    fn reset_if_expired(&mut self) {
        if self.window_start.elapsed() >= Duration::from_secs(3600) {
            self.count = 0;
            self.window_start = Instant::now();
        }
    }

    fn increment(&mut self) {
        self.reset_if_expired();
        self.count += 1;
    }

    fn get_count(&mut self) -> u32 {
        self.reset_if_expired();
        self.count
    }
}

/// Emergency message usage tracking per node
#[derive(Debug, Clone)]
struct EmergencyUsage {
    /// Per-realm quota usage (RealmTier → usage)
    realm_quotas: HashMap<u8, RealmQuotaUsage>,

    /// Total emergencies sent today
    total_today: u32,

    /// Start of current day
    day_start: Instant,

    /// Abuse score (0.0 = clean, 1.0 = heavy abuse)
    abuse_score: f64,
}

impl EmergencyUsage {
    fn new() -> Self {
        Self {
            realm_quotas: HashMap::new(),
            total_today: 0,
            day_start: Instant::now(),
            abuse_score: 0.0,
        }
    }

    fn reset_daily_if_expired(&mut self) {
        if self.day_start.elapsed() >= Duration::from_secs(86400) {
            self.total_today = 0;
            self.day_start = Instant::now();
            // Decay abuse score by 50% daily
            self.abuse_score *= 0.5;
        }
    }

    fn record_emergency(&mut self, realm: &RealmTier) {
        self.reset_daily_if_expired();
        self.total_today += 1;

        let tier = *realm as u8;
        let quota = self.realm_quotas.entry(tier).or_insert_with(RealmQuotaUsage::new);
        quota.increment();
    }

    fn is_quota_exceeded(&mut self, realm: &RealmTier, limit: u32) -> bool {
        let tier = *realm as u8;
        let quota = self.realm_quotas.entry(tier).or_insert_with(RealmQuotaUsage::new);
        quota.get_count() >= limit
    }

    fn get_total_today(&mut self) -> u32 {
        self.reset_daily_if_expired();
        self.total_today
    }

    fn increase_abuse_score(&mut self, penalty: f64) {
        self.abuse_score = (self.abuse_score + penalty).min(1.0);
    }
}

/// Statistics for emergency message processing
#[derive(Debug, Clone, Default)]
pub struct EmergencyStats {
    /// Total emergency messages validated
    pub total_validated: u64,

    /// Messages allowed
    pub total_allowed: u64,

    /// Messages allowed via bandwidth exemption
    pub total_bandwidth_exemptions: u64,

    /// Messages downgraded to High priority
    pub total_downgrades: u64,

    /// Messages rejected
    pub total_rejected: u64,

    /// Messages bypassed via high reputation
    pub reputation_bypasses: u64,

    /// Messages bypassed via infrequent usage
    pub infrequent_bypasses: u64,
}

/// Emergency message validation and abuse prevention manager
pub struct EmergencyManager {
    config: EmergencyManagerConfig,
    usage_tracker: Arc<RwLock<HashMap<NodeId, EmergencyUsage>>>,
    stats: Arc<RwLock<EmergencyStats>>,
    reputation: Option<Arc<RwLock<ReputationScore>>>,
    bandwidth_monitor: Option<Arc<BandwidthMonitor>>,
    consensus_validator: Option<Arc<ConsensusValidator>>,
}

impl EmergencyManager {
    /// Create a new EmergencyManager
    pub fn new(config: EmergencyManagerConfig) -> Self {
        Self {
            config,
            usage_tracker: Arc::new(RwLock::new(HashMap::new())),
            stats: Arc::new(RwLock::new(EmergencyStats::default())),
            reputation: None,
            bandwidth_monitor: None,
            consensus_validator: None,
        }
    }

    /// Set the reputation scoring system
    pub fn set_reputation(&mut self, reputation: Arc<RwLock<ReputationScore>>) {
        self.reputation = Some(reputation);
    }

    /// Set the bandwidth monitor
    pub fn set_bandwidth_monitor(&mut self, bandwidth_monitor: Arc<BandwidthMonitor>) {
        self.bandwidth_monitor = Some(bandwidth_monitor);
    }

    /// Set the consensus validator
    pub fn set_consensus_validator(&mut self, consensus_validator: Arc<ConsensusValidator>) {
        self.consensus_validator = Some(consensus_validator);
    }

    /// Get current statistics
    pub fn get_stats(&self) -> EmergencyStats {
        self.stats.read().unwrap().clone()
    }

    /// Validate an emergency message using the 7-step validation process
    ///
    /// # Arguments
    /// * `message` - The emergency message to validate
    /// * `adapter_id` - Optional adapter ID for bandwidth exemption checks
    /// * `adapter_max_bps` - Optional adapter maximum bandwidth for exemption checks
    ///
    /// # Returns
    /// * `Ok(EmergencyValidation)` - Validation result (Allow, AllowBandwidthExemption, Downgrade, Reject)
    /// * `Err(RoutingError)` - Validation error
    pub fn validate_emergency_message(
        &self,
        message: &Message,
        adapter_id: Option<&str>,
        adapter_max_bps: Option<u64>,
    ) -> Result<EmergencyValidation> {
        // Update statistics
        {
            let mut stats = self.stats.write().unwrap();
            stats.total_validated += 1;
        }

        if !self.config.enabled {
            return Ok(EmergencyValidation::Allow);
        }

        // ===== STEP 1: Extract and validate realm metadata =====
        let realm = message.emergency_realm.as_ref().ok_or_else(|| {
            RoutingError::InvalidMessage("Emergency message missing realm metadata".to_string())
        })?;

        // Validate declared realm matches actual destination count
        let actual_tier = RealmTier::from_destination_count(realm.destination_count);
        if actual_tier != realm.realm {
            // Realm manipulation detected - downgrade
            let reason = format!(
                "Realm manipulation: declared {:?} but actual {:?}",
                realm.realm, actual_tier
            );
            self.record_result(&EmergencyValidation::Downgrade {
                reason: reason.clone(),
            });
            return Ok(EmergencyValidation::Downgrade { reason });
        }

        // ===== STEP 2: Check Global realm consensus (MUST be before exemptions) =====
        // Global realm ALWAYS requires consensus, even for high reputation nodes
        if matches!(realm.realm, RealmTier::Global) {
            if let Some(cv) = &self.consensus_validator {
                let consensus_result = cv.request_consensus(message)?;
                if !consensus_result.approved {
                    let reason = format!(
                        "Global realm consensus not achieved ({}/{} confirmations)",
                        consensus_result.confirmations, consensus_result.validators_queried
                    );
                    let result = EmergencyValidation::Reject { reason };
                    self.record_result(&result);
                    return Ok(result);
                }
                // Consensus achieved, allow the message to proceed
            } else {
                // No consensus validator configured
                let reason = "Global realm requires consensus but validator not configured".to_string();
                let result = EmergencyValidation::Reject { reason };
                self.record_result(&result);
                return Ok(result);
            }
        }

        // ===== STEP 3: Check legitimacy exemptions =====

        // Check high reputation
        if let Some(rep) = &self.reputation {
            let score = rep.read().unwrap().get_score(&message.source);
            if score >= self.config.high_reputation_threshold {
                let result = EmergencyValidation::Allow;
                self.record_result(&result);
                {
                    let mut stats = self.stats.write().unwrap();
                    stats.reputation_bypasses += 1;
                }
                return Ok(result);
            }
        }

        // Check infrequent usage
        {
            let mut tracker = self.usage_tracker.write().unwrap();
            let usage = tracker
                .entry(message.source)
                .or_insert_with(EmergencyUsage::new);
            let total_today = usage.get_total_today();

            if total_today < self.config.infrequent_allowance {
                // Record the emergency first
                usage.record_emergency(&realm.realm);
                let result = EmergencyValidation::Allow;
                self.record_result(&result);
                {
                    let mut stats = self.stats.write().unwrap();
                    stats.infrequent_bypasses += 1;
                }
                return Ok(result);
            }
        }

        // ===== STEP 4: Bandwidth exemption check (CRITICAL) =====
        if self.config.bandwidth_exemption_enabled && realm.realm.is_bandwidth_exempt_eligible() {
            if let (Some(bw), Some(aid), Some(max_bps)) =
                (&self.bandwidth_monitor, adapter_id, adapter_max_bps)
            {
                // Check if adapter qualifies for bandwidth exemption using the BandwidthMonitor's logic
                if bw.is_bandwidth_exemption_eligible(aid, max_bps) {
                    // Get utilization for logging
                    let util_result = bw.get_utilization(aid, max_bps).unwrap();

                    // Bandwidth exemption granted!
                    let result = EmergencyValidation::AllowBandwidthExemption {
                        adapter_name: aid.to_string(),
                        utilization: util_result.current_utilization,
                    };

                    // Still record the emergency for statistics
                    {
                        let mut tracker = self.usage_tracker.write().unwrap();
                        let usage = tracker
                            .entry(message.source)
                            .or_insert_with(EmergencyUsage::new);
                        usage.record_emergency(&realm.realm);
                    }

                    self.record_result(&result);
                    return Ok(result);
                }
            }
        }

        // ===== STEP 5: Check realm quota =====
        if let Some(quota) = realm.realm.quota_per_hour() {
            let mut tracker = self.usage_tracker.write().unwrap();
            let usage = tracker
                .entry(message.source)
                .or_insert_with(EmergencyUsage::new);

            if usage.is_quota_exceeded(&realm.realm, quota) {
                // Quota exceeded - downgrade to High priority
                let reason = format!(
                    "Quota exceeded for {:?} realm ({}/hour limit)",
                    realm.realm, quota
                );
                let result = EmergencyValidation::Downgrade { reason };
                self.record_result(&result);
                return Ok(result);
            }

            // Record the emergency
            usage.record_emergency(&realm.realm);
        } else {
            // Individual realm (no quota) or already handled by exemptions
            let mut tracker = self.usage_tracker.write().unwrap();
            let usage = tracker
                .entry(message.source)
                .or_insert_with(EmergencyUsage::new);
            usage.record_emergency(&realm.realm);
        }

        // ===== STEP 6: Apply size-based penalty modulation =====
        if self.config.size_modulation_enabled {
            let size_penalty = Self::calculate_size_penalty(message.payload.len());

            // Record abuse for large payloads
            if size_penalty > 0.5 {
                let mut tracker = self.usage_tracker.write().unwrap();
                if let Some(usage) = tracker.get_mut(&message.source) {
                    usage.increase_abuse_score(size_penalty * 0.1); // 10% penalty per large message
                }

                // Also record in reputation if available
                if let Some(rep) = &self.reputation {
                    let mut rep_guard = rep.write().unwrap();
                    // Reputation system doesn't have emergency abuse tracking yet,
                    // but we can record a failed transaction as a proxy
                    if size_penalty >= 1.0 {
                        rep_guard.record_failed_transaction(&message.source);
                    }
                }
            }
        }

        // ===== STEP 7: Return validation decision =====
        let result = EmergencyValidation::Allow;
        self.record_result(&result);
        Ok(result)
    }

    /// Calculate size penalty for payload
    ///
    /// Returns:
    /// * 0.1 - Small text messages (<512B)
    /// * 0.3 - Small media (512B-5KB)
    /// * 0.6 - Medium media (5KB-50KB)
    /// * 1.0 - Large media (>50KB)
    fn calculate_size_penalty(payload_size: usize) -> f64 {
        match payload_size {
            0..=512 => 0.1,
            513..=5120 => 0.3,
            5121..=51200 => 0.6,
            _ => 1.0,
        }
    }

    /// Record validation result in statistics
    fn record_result(&self, result: &EmergencyValidation) {
        let mut stats = self.stats.write().unwrap();
        match result {
            EmergencyValidation::Allow => stats.total_allowed += 1,
            EmergencyValidation::AllowBandwidthExemption { .. } => {
                stats.total_allowed += 1;
                stats.total_bandwidth_exemptions += 1;
            }
            EmergencyValidation::Downgrade { .. } => stats.total_downgrades += 1,
            EmergencyValidation::Reject { .. } => stats.total_rejected += 1,
        }
    }

    /// Cleanup stale tracking entries (should be called periodically)
    pub fn cleanup_stale(&self) {
        let mut tracker = self.usage_tracker.write().unwrap();

        // Remove entries with very old day_start (>7 days) and low abuse scores
        tracker.retain(|_, usage| {
            usage.day_start.elapsed() < Duration::from_secs(7 * 86400) || usage.abuse_score > 0.1
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use myriadmesh_protocol::{MessageType, Priority};

    fn create_test_node_id(byte: u8) -> NodeId {
        NodeId::from_bytes([byte; 64])
    }

    fn create_test_message(
        source: NodeId,
        realm: RealmTier,
        dest_count: u32,
        payload_size: usize,
    ) -> Message {
        let mut msg = Message::new(
            source,
            create_test_node_id(2),
            MessageType::Data,
            vec![0u8; payload_size],
        )
        .unwrap();
        msg.priority = Priority::emergency();
        msg.emergency_realm = Some(EmergencyRealm {
            realm,
            destination_count: dest_count,
            authority_signature: None,
            authority_key_id: None,
        });
        msg
    }

    #[test]
    fn test_emergency_manager_creation() {
        let manager = EmergencyManager::new(EmergencyManagerConfig::default());
        let stats = manager.get_stats();
        assert_eq!(stats.total_validated, 0);
        assert_eq!(stats.total_allowed, 0);
    }

    #[test]
    fn test_realm_validation_matches_destination_count() {
        let manager = EmergencyManager::new(EmergencyManagerConfig::default());
        let source = create_test_node_id(1);

        // Valid Individual realm (1 destination)
        let msg = create_test_message(source, RealmTier::Individual, 1, 100);
        let result = manager.validate_emergency_message(&msg, None, None).unwrap();
        assert!(matches!(result, EmergencyValidation::Allow));
    }

    #[test]
    fn test_realm_manipulation_detected() {
        let manager = EmergencyManager::new(EmergencyManagerConfig::default());
        let source = create_test_node_id(1);

        // Declared Individual but actual Family (10 destinations)
        let msg = create_test_message(source, RealmTier::Individual, 10, 100);
        let result = manager.validate_emergency_message(&msg, None, None).unwrap();

        match result {
            EmergencyValidation::Downgrade { reason } => {
                assert!(reason.contains("Realm manipulation"));
            }
            _ => panic!("Expected Downgrade for realm manipulation"),
        }
    }

    #[test]
    fn test_infrequent_usage_bypass() {
        let config = EmergencyManagerConfig {
            infrequent_allowance: 3,
            ..Default::default()
        };
        let manager = EmergencyManager::new(config);
        let source = create_test_node_id(1);

        // First 3 emergencies should bypass quota checks
        for i in 0..3 {
            let msg = create_test_message(source, RealmTier::Family, 5, 100);
            let result = manager.validate_emergency_message(&msg, None, None).unwrap();
            assert!(
                matches!(result, EmergencyValidation::Allow),
                "Emergency {} should be allowed via infrequent bypass",
                i + 1
            );
        }

        let stats = manager.get_stats();
        assert_eq!(stats.infrequent_bypasses, 3);
    }

    #[test]
    fn test_quota_enforcement_family_realm() {
        let config = EmergencyManagerConfig {
            infrequent_allowance: 0, // Disable infrequent bypass
            ..Default::default()
        };
        let manager = EmergencyManager::new(config);
        let source = create_test_node_id(1);

        // Family realm has 10/hour quota
        // Send 11 messages - 10th should pass, 11th should be downgraded
        for i in 0..10 {
            let msg = create_test_message(source, RealmTier::Family, 5, 100);
            let result = manager.validate_emergency_message(&msg, None, None).unwrap();
            assert!(
                matches!(result, EmergencyValidation::Allow),
                "Message {} should be allowed (within quota)",
                i + 1
            );
        }

        // 11th message should be downgraded
        let msg = create_test_message(source, RealmTier::Family, 5, 100);
        let result = manager.validate_emergency_message(&msg, None, None).unwrap();
        match result {
            EmergencyValidation::Downgrade { reason } => {
                assert!(reason.contains("Quota exceeded"));
            }
            _ => panic!("Expected Downgrade for quota exceeded"),
        }
    }

    #[test]
    fn test_size_penalty_calculation() {
        assert_eq!(EmergencyManager::calculate_size_penalty(100), 0.1); // Small text
        assert_eq!(EmergencyManager::calculate_size_penalty(512), 0.1); // Edge case
        assert_eq!(EmergencyManager::calculate_size_penalty(513), 0.3); // Small media
        assert_eq!(EmergencyManager::calculate_size_penalty(5000), 0.3);
        assert_eq!(EmergencyManager::calculate_size_penalty(5121), 0.6); // Medium media
        assert_eq!(EmergencyManager::calculate_size_penalty(50000), 0.6);
        assert_eq!(EmergencyManager::calculate_size_penalty(51201), 1.0); // Large media
        assert_eq!(EmergencyManager::calculate_size_penalty(100000), 1.0);
    }

    #[test]
    fn test_bandwidth_exemption_individual_realm() {
        use crate::bandwidth_monitor::{BandwidthMonitorConfig, Direction};

        let mut config = EmergencyManagerConfig::default();
        config.infrequent_allowance = 0; // Disable infrequent bypass
        config.bandwidth_exemption_enabled = true;
        config.high_speed_threshold_bps = 10_000_000; // 10 Mbps
        config.unused_bandwidth_threshold = 0.4; // 40% utilized

        let mut manager = EmergencyManager::new(config);

        // Create and register bandwidth monitor
        let bw_config = BandwidthMonitorConfig {
            high_speed_threshold_bps: 10_000_000,
            unused_threshold: 0.6,
            sampling_window_secs: 60,
        };
        let bw_monitor = Arc::new(BandwidthMonitor::new(bw_config));
        bw_monitor.register_adapter("wifi0", 100_000_000); // 100 Mbps adapter

        // Simulate low utilization (~15-20% over 2+ seconds)
        // Record a small transfer, then wait to establish a window with low utilization
        // 100 Mbps = 12,500,000 bytes/sec
        // Record 3.75 MB, then wait 2+ seconds
        // 3.75 MB * 8 bits / 2 sec = 15 Mbps = 15% utilization (well under 40% threshold)
        bw_monitor.record_transfer("wifi0", 3_750_000, Direction::Outbound);
        std::thread::sleep(std::time::Duration::from_millis(2100)); // Wait >2 seconds

        manager.set_bandwidth_monitor(bw_monitor);

        let source = create_test_node_id(1);
        let msg = create_test_message(source, RealmTier::Individual, 1, 100);

        let result = manager
            .validate_emergency_message(&msg, Some("wifi0"), Some(100_000_000))
            .unwrap();

        match result {
            EmergencyValidation::AllowBandwidthExemption {
                adapter_name,
                utilization,
            } => {
                assert_eq!(adapter_name, "wifi0");
                assert!(utilization <= 0.4, "Utilization should be ≤40%, got {}", utilization);
            }
            other => panic!("Expected AllowBandwidthExemption for Individual on high-speed low-util adapter, got {:?}", other),
        }

        let stats = manager.get_stats();
        assert_eq!(stats.total_bandwidth_exemptions, 1);
    }

    #[test]
    fn test_bandwidth_exemption_not_for_group_realm() {
        use crate::bandwidth_monitor::BandwidthMonitorConfig;

        let mut config = EmergencyManagerConfig::default();
        config.infrequent_allowance = 0;
        config.bandwidth_exemption_enabled = true;

        let mut manager = EmergencyManager::new(config);

        let bw_monitor = Arc::new(BandwidthMonitor::new(BandwidthMonitorConfig::default()));
        bw_monitor.register_adapter("wifi0", 100_000_000);
        manager.set_bandwidth_monitor(bw_monitor);

        let source = create_test_node_id(1);
        // Group realm (11-50 destinations) should NOT get bandwidth exemption
        let msg = create_test_message(source, RealmTier::Group, 20, 100);

        let result = manager
            .validate_emergency_message(&msg, Some("wifi0"), Some(100_000_000))
            .unwrap();

        // Should not get bandwidth exemption (Group realm not eligible)
        assert!(
            !matches!(result, EmergencyValidation::AllowBandwidthExemption { .. }),
            "Group realm should not receive bandwidth exemption"
        );
    }

    #[test]
    fn test_bandwidth_exemption_rejected_high_utilization() {
        use crate::bandwidth_monitor::{BandwidthMonitorConfig, Direction};

        let mut config = EmergencyManagerConfig::default();
        config.infrequent_allowance = 0;
        config.bandwidth_exemption_enabled = true;
        config.unused_bandwidth_threshold = 0.4; // Max 40% utilization

        let mut manager = EmergencyManager::new(config);

        let bw_monitor = Arc::new(BandwidthMonitor::new(BandwidthMonitorConfig::default()));
        bw_monitor.register_adapter("wifi0", 100_000_000);

        // Simulate 90% utilization (too high for exemption)
        // 90 Mbps = 11,250,000 bytes/sec * 60 = 675,000,000 bytes
        for _ in 0..675 {
            bw_monitor.record_transfer("wifi0", 1_000_000, Direction::Outbound);
        }

        manager.set_bandwidth_monitor(bw_monitor);

        let source = create_test_node_id(1);
        let msg = create_test_message(source, RealmTier::Individual, 1, 100);

        let result = manager
            .validate_emergency_message(&msg, Some("wifi0"), Some(100_000_000))
            .unwrap();

        // Should NOT get bandwidth exemption due to high utilization
        assert!(
            !matches!(result, EmergencyValidation::AllowBandwidthExemption { .. }),
            "Should not get exemption with 90% utilization"
        );

        // Should hit quota limit instead (Individual has no quota, so Allow)
        assert!(matches!(result, EmergencyValidation::Allow));
    }

    #[test]
    fn test_high_reputation_bypass() {
        let config = EmergencyManagerConfig {
            high_reputation_threshold: 0.8,
            infrequent_allowance: 0, // Disable to test reputation specifically
            ..Default::default()
        };
        let mut manager = EmergencyManager::new(config);

        // Create reputation system with high score
        let reputation = Arc::new(RwLock::new(ReputationScore::new()));
        let source = create_test_node_id(1);

        // Record successful transactions to build reputation
        for _ in 0..20 {
            reputation
                .write()
                .unwrap()
                .record_successful_transaction(&source, 50.0);
        }

        manager.set_reputation(reputation);

        let msg = create_test_message(source, RealmTier::Family, 5, 100);
        let result = manager.validate_emergency_message(&msg, None, None).unwrap();

        assert!(matches!(result, EmergencyValidation::Allow));
        let stats = manager.get_stats();
        assert_eq!(stats.reputation_bypasses, 1);
    }

    #[test]
    fn test_global_realm_requires_consensus() {
        use crate::consensus_validator::{ConsensusConfig, ConsensusValidator};

        // Test 1: Without consensus validator - should reject
        let manager = EmergencyManager::new(EmergencyManagerConfig::default());
        let source = create_test_node_id(1);
        let msg = create_test_message(source, RealmTier::Global, 10000, 100);

        let result = manager.validate_emergency_message(&msg, None, None).unwrap();
        match result {
            EmergencyValidation::Reject { reason } => {
                assert!(reason.contains("consensus"));
            }
            _ => panic!("Expected Reject for Global realm without consensus validator"),
        }

        // Test 2: With consensus validator - depends on simulation
        let mut manager2 = EmergencyManager::new(EmergencyManagerConfig::default());
        let consensus_config = ConsensusConfig::default();
        let consensus_validator = Arc::new(ConsensusValidator::new(consensus_config));
        manager2.set_consensus_validator(consensus_validator);

        // Create a message that will get consensus (deterministic simulation)
        let msg2 = create_test_message(source, RealmTier::Global, 10000, 100);
        let result2 = manager2.validate_emergency_message(&msg2, None, None).unwrap();

        // Result depends on deterministic simulation - just verify it ran
        match result2 {
            EmergencyValidation::Allow => {
                // Consensus achieved
            }
            EmergencyValidation::Reject { reason } => {
                // Consensus not achieved
                assert!(reason.contains("consensus"));
            }
            _ => panic!("Expected either Allow or Reject for Global realm"),
        }
    }

    #[test]
    fn test_statistics_tracking() {
        let manager = EmergencyManager::new(EmergencyManagerConfig::default());
        let source = create_test_node_id(1);

        // Validate a few messages
        for _ in 0..3 {
            let msg = create_test_message(source, RealmTier::Individual, 1, 100);
            let _ = manager.validate_emergency_message(&msg, None, None);
        }

        let stats = manager.get_stats();
        assert_eq!(stats.total_validated, 3);
        assert!(stats.total_allowed > 0 || stats.total_downgrades > 0);
    }
}
