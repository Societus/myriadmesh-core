//! Ledger-Based Reputation Scoring System
//!
//! Implements reputation tracking for mesh nodes using transaction history.
//! Reputation scores influence routing decisions and node selection.
//!
//! Score factors (total weight = 100%):
//! - Delivery success rate: 60%
//! - Response time reliability: 20%
//! - Ledger transaction history: 15%
//! - Time-weighted decay: 5%
//!
//! Reputation scores range from 0.0 (untrusted) to 1.0 (fully trusted).

use myriadmesh_protocol::NodeId;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

/// Weight for delivery success in reputation calculation (60%)
const DELIVERY_SUCCESS_WEIGHT: f64 = 0.60;

/// Weight for response time in reputation calculation (20%)
const RESPONSE_TIME_WEIGHT: f64 = 0.20;

/// Weight for ledger history in reputation calculation (15%)
const LEDGER_HISTORY_WEIGHT: f64 = 0.15;

/// Decay factor per day
const DAILY_DECAY_RATE: f64 = 0.98;

/// Minimum reputation score
const MIN_REPUTATION_SCORE: f64 = 0.0;

/// Maximum reputation score
const MAX_REPUTATION_SCORE: f64 = 1.0;

/// Default reputation for new nodes
const DEFAULT_REPUTATION: f64 = 0.5;

/// Represents a ledger transaction record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LedgerTransaction {
    /// Node ID involved in transaction
    pub node_id: NodeId,
    /// Whether transaction was successful
    pub success: bool,
    /// Response time in milliseconds
    pub response_time_ms: f64,
    /// Timestamp of transaction
    pub timestamp: u64,
    /// Transaction value/weight
    pub weight: f64,
}

impl LedgerTransaction {
    /// Create a new ledger transaction
    pub fn new(
        node_id: NodeId,
        success: bool,
        response_time_ms: f64,
        weight: f64,
    ) -> Self {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        Self {
            node_id,
            success,
            response_time_ms: response_time_ms.max(0.0),
            timestamp,
            weight: weight.clamp(0.0, 1.0),
        }
    }

    /// Check if transaction is recent (within 24 hours)
    pub fn is_recent(&self) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        now.saturating_sub(self.timestamp) < 86400 // 24 hours
    }

    /// Get age of transaction in seconds
    pub fn age_seconds(&self) -> u64 {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        now.saturating_sub(self.timestamp)
    }
}

/// Node reputation metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
struct NodeMetrics {
    /// Total successful transactions
    successful_count: u32,
    /// Total failed transactions
    failed_count: u32,
    /// Average response time (milliseconds)
    avg_response_time_ms: f64,
    /// Ledger history items
    ledger_history: Vec<LedgerTransaction>,
    /// Current reputation score
    current_score: f64,
    /// Last score update time
    last_update: u64,
}

impl NodeMetrics {
    /// Create new node metrics with default reputation
    fn new() -> Self {
        Self {
            successful_count: 0,
            failed_count: 0,
            avg_response_time_ms: 0.0,
            ledger_history: Vec::new(),
            current_score: DEFAULT_REPUTATION,
            last_update: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        }
    }

    /// Record a successful transaction
    fn record_success(&mut self, response_time_ms: f64) {
        self.successful_count += 1;
        // Update average response time with exponential moving average
        let alpha = 0.125;
        if self.successful_count == 1 {
            self.avg_response_time_ms = response_time_ms;
        } else {
            self.avg_response_time_ms =
                alpha * response_time_ms + (1.0 - alpha) * self.avg_response_time_ms;
        }
    }

    /// Record a failed transaction
    fn record_failure(&mut self) {
        self.failed_count += 1;
    }

    /// Calculate delivery success rate
    fn delivery_success_rate(&self) -> f64 {
        let total = self.successful_count as f64 + self.failed_count as f64;
        if total == 0.0 {
            0.5 // Default for no history
        } else {
            (self.successful_count as f64) / total
        }
    }

    /// Calculate response time reliability score
    fn response_time_score(&self) -> f64 {
        if self.avg_response_time_ms == 0.0 {
            0.5 // Default
        } else {
            // Score decreases with latency (max 1000ms = 0.0 score)
            let max_latency = 1000.0;
            ((max_latency - self.avg_response_time_ms.min(max_latency)) / max_latency).max(0.0)
        }
    }

    /// Calculate ledger history score
    fn ledger_history_score(&self) -> f64 {
        if self.ledger_history.is_empty() {
            0.5 // Default
        } else {
            // Weight recent transactions more heavily
            let mut weighted_score = 0.0;
            let mut total_weight = 0.0;

            for tx in &self.ledger_history {
                let age_hours = tx.age_seconds() as f64 / 3600.0;
                let time_weight = (-age_hours / 24.0).exp(); // Exponential decay
                let tx_score = if tx.success { 0.8 } else { 0.2 };
                weighted_score += tx_score * time_weight * tx.weight;
                total_weight += time_weight * tx.weight;
            }

            if total_weight == 0.0 {
                0.5
            } else {
                weighted_score / total_weight
            }
        }
    }

    /// Calculate time decay factor
    fn time_decay_factor(&self) -> f64 {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let age_days = (now.saturating_sub(self.last_update)) as f64 / 86400.0;
        DAILY_DECAY_RATE.powf(age_days)
    }

    /// Calculate composite reputation score
    fn calculate_score(&self) -> f64 {
        let success_component = self.delivery_success_rate() * DELIVERY_SUCCESS_WEIGHT;
        let response_component = self.response_time_score() * RESPONSE_TIME_WEIGHT;
        let ledger_component = self.ledger_history_score() * LEDGER_HISTORY_WEIGHT;
        let decay_factor = self.time_decay_factor();

        let composite = success_component + response_component + ledger_component;
        let decayed = composite * decay_factor;

        decayed.clamp(MIN_REPUTATION_SCORE, MAX_REPUTATION_SCORE)
    }
}

/// Reputation scoring system
///
/// Maintains reputation scores for all nodes based on transaction history
/// and interaction metrics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReputationScore {
    /// Per-node metrics and scores
    node_metrics: HashMap<NodeId, NodeMetrics>,
    /// Cached transaction history
    transaction_ledger: Vec<LedgerTransaction>,
    /// Maximum ledger entries to retain
    max_ledger_entries: usize,
}

impl ReputationScore {
    /// Create a new reputation scoring system
    pub fn new() -> Self {
        Self {
            node_metrics: HashMap::new(),
            transaction_ledger: Vec::new(),
            max_ledger_entries: 10_000,
        }
    }

    /// Calculate reputation score for a node
    ///
    /// Returns a score from 0.0 (untrusted) to 1.0 (fully trusted)
    /// based on delivery success, response time, and transaction history.
    pub fn calculate_reputation(&mut self, node_id: &NodeId) -> f64 {
        let metrics = self.node_metrics.entry(*node_id).or_insert_with(NodeMetrics::new);
        let score = metrics.calculate_score();
        metrics.current_score = score;
        score
    }

    /// Record a successful transaction for a node
    ///
    /// Increases node reputation and records metrics.
    pub fn record_successful_transaction(&mut self, node_id: &NodeId, response_time_ms: f64) {
        let metrics = self.node_metrics.entry(*node_id).or_insert_with(NodeMetrics::new);
        metrics.record_success(response_time_ms);

        // Record in ledger
        let tx = LedgerTransaction::new(*node_id, true, response_time_ms, 1.0);
        self.transaction_ledger.push(tx.clone());
        metrics.ledger_history.push(tx);

        // Maintain ledger size
        if self.transaction_ledger.len() > self.max_ledger_entries {
            self.transaction_ledger.remove(0);
        }

        // Recalculate score with new data
        self.calculate_reputation(node_id);
    }

    /// Record a failed transaction for a node
    ///
    /// Decreases node reputation and records failure metrics.
    pub fn record_failed_transaction(&mut self, node_id: &NodeId) {
        let metrics = self.node_metrics.entry(*node_id).or_insert_with(NodeMetrics::new);
        metrics.record_failure();

        // Record in ledger
        let tx = LedgerTransaction::new(*node_id, false, 0.0, 1.0);
        self.transaction_ledger.push(tx.clone());
        metrics.ledger_history.push(tx);

        // Maintain ledger size
        if self.transaction_ledger.len() > self.max_ledger_entries {
            self.transaction_ledger.remove(0);
        }

        // Recalculate score with new data
        self.calculate_reputation(node_id);
    }

    /// Query ledger history for a specific node
    ///
    /// Returns transaction history in reverse chronological order (newest first).
    pub fn query_ledger_history(&self, node_id: &NodeId) -> Vec<LedgerTransaction> {
        self.transaction_ledger
            .iter()
            .filter(|tx| tx.node_id == *node_id)
            .rev()
            .cloned()
            .collect()
    }

    /// Update all node reputation scores
    ///
    /// Recalculates scores with time decay and current metrics.
    /// Should be called periodically (e.g., every hour) to apply time decay.
    pub fn update_all_scores(&mut self) {
        let node_ids: Vec<NodeId> = self.node_metrics.keys().cloned().collect();
        for node_id in node_ids {
            self.calculate_reputation(&node_id);
        }
    }

    /// Get reputation score for a node without updating
    pub fn get_score(&self, node_id: &NodeId) -> f64 {
        self.node_metrics
            .get(node_id)
            .map(|m| m.current_score)
            .unwrap_or(DEFAULT_REPUTATION)
    }

    /// Get number of known nodes
    pub fn known_nodes_count(&self) -> usize {
        self.node_metrics.len()
    }

    /// Get transaction history length
    pub fn transaction_count(&self) -> usize {
        self.transaction_ledger.len()
    }

    /// Get metrics for a node (for testing and diagnostics)
    pub fn get_node_metrics(&self, node_id: &NodeId) -> Option<(u32, u32, f64)> {
        self.node_metrics.get(node_id).map(|m| {
            (m.successful_count, m.failed_count, m.avg_response_time_ms)
        })
    }
}

impl Default for ReputationScore {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_node_id(value: u8) -> NodeId {
        let mut bytes = [0u8; 64];
        bytes[0] = value;
        NodeId::from_bytes(bytes)
    }

    #[test]
    fn test_reputation_calculation_accuracy() {
        let mut reputation = ReputationScore::new();
        let node_id = create_test_node_id(1);

        // Build transaction history
        for _ in 0..8 {
            reputation.record_successful_transaction(&node_id, 25.0);
        }
        for _ in 0..2 {
            reputation.record_failed_transaction(&node_id);
        }

        let score = reputation.calculate_reputation(&node_id);
        assert!(score > 0.5, "High success rate should yield > 0.5 reputation");
        assert!(score <= MAX_REPUTATION_SCORE);
    }

    #[test]
    fn test_successful_transaction_impact() {
        let mut reputation = ReputationScore::new();
        let node_id = create_test_node_id(2);

        let initial = reputation.calculate_reputation(&node_id);

        reputation.record_successful_transaction(&node_id, 15.0);
        reputation.record_successful_transaction(&node_id, 20.0);
        reputation.record_successful_transaction(&node_id, 18.0);

        let final_score = reputation.calculate_reputation(&node_id);
        assert!(final_score > initial, "Multiple successes should increase reputation");
    }

    #[test]
    fn test_failed_transaction_impact() {
        let mut reputation = ReputationScore::new();
        let node_id = create_test_node_id(3);

        // Start with good reputation
        for _ in 0..5 {
            reputation.record_successful_transaction(&node_id, 20.0);
        }

        let good_score = reputation.calculate_reputation(&node_id);

        // Add failures
        for _ in 0..3 {
            reputation.record_failed_transaction(&node_id);
        }

        let degraded_score = reputation.calculate_reputation(&node_id);
        assert!(degraded_score < good_score, "Failures should decrease reputation");
    }

    #[test]
    fn test_ledger_integration() {
        let mut reputation = ReputationScore::new();
        let node_id = create_test_node_id(4);

        reputation.record_successful_transaction(&node_id, 10.0);
        reputation.record_failed_transaction(&node_id);
        reputation.record_successful_transaction(&node_id, 15.0);

        let history = reputation.query_ledger_history(&node_id);
        assert_eq!(history.len(), 3);
        assert!(history[0].success); // Most recent
        assert!(!history[1].success);
        assert!(history[2].success);
    }

    #[test]
    fn test_time_decay_application() {
        let mut reputation = ReputationScore::new();
        let node_id = create_test_node_id(5);

        reputation.record_successful_transaction(&node_id, 20.0);
        let score_with_activity = reputation.calculate_reputation(&node_id);

        // Time decay factor should be between 0 and 1
        let metrics = &reputation.node_metrics[&node_id];
        let decay = metrics.time_decay_factor();
        assert!(decay <= 1.0);
        assert!(decay > 0.0);
        assert!(score_with_activity > 0.0);
    }

    #[test]
    fn test_batch_update_scores() {
        let mut reputation = ReputationScore::new();

        for i in 0..5 {
            let node_id = create_test_node_id(10 + i);
            reputation.record_successful_transaction(&node_id, 20.0);
            reputation.record_successful_transaction(&node_id, 25.0);
        }

        let initial_node = create_test_node_id(10);

        reputation.update_all_scores();

        let updated_score = reputation.get_score(&initial_node);
        assert!(updated_score > 0.0);
        assert!(updated_score <= 1.0);
    }

    #[test]
    fn test_response_time_reliability() {
        let mut reputation = ReputationScore::new();
        let fast_node = create_test_node_id(22);
        let slow_node = create_test_node_id(23);

        // Fast responses
        reputation.record_successful_transaction(&fast_node, 5.0);
        reputation.record_successful_transaction(&fast_node, 10.0);
        let fast_score = reputation.calculate_reputation(&fast_node);

        // Slow responses
        reputation.record_successful_transaction(&slow_node, 500.0);
        reputation.record_successful_transaction(&slow_node, 600.0);
        let slow_score = reputation.calculate_reputation(&slow_node);

        assert!(fast_score > slow_score, "Faster nodes should have higher scores");
    }

    #[test]
    fn test_edge_case_new_nodes() {
        let mut reputation = ReputationScore::new();
        let new_node = create_test_node_id(20);

        // New node should have some reputation (score varies due to decay/defaults)
        let score = reputation.calculate_reputation(&new_node);
        assert!(score >= 0.0 && score <= 1.0);

        // Should track after first transaction
        reputation.record_successful_transaction(&new_node, 30.0);
        let updated_score = reputation.calculate_reputation(&new_node);
        assert!(updated_score >= 0.0);
        assert!(updated_score <= 1.0);
    }
}
