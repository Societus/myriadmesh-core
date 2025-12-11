//! K-of-N consensus validation for Global realm emergency messages
//!
//! This module implements a distributed consensus protocol for validating
//! Global realm emergency messages (broadcasts). Requires K confirmations
//! from N validators to approve a message.

use crate::error::{Result, RoutingError};
use myriadmesh_protocol::{Message, MessageId, NodeId};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

/// Configuration for consensus validation
#[derive(Debug, Clone)]
pub struct ConsensusConfig {
    /// Enable consensus validation
    pub enabled: bool,

    /// Number of confirmations required (K)
    /// Default: 3
    pub required_confirmations: u32,

    /// Total number of validators to query (N)
    /// Default: 5
    pub total_validators: u32,

    /// Timeout for consensus requests in seconds
    /// Default: 10 seconds
    pub timeout_secs: u64,

    /// Use DHT to discover validators
    /// If false, validators must be manually configured
    pub use_dht_discovery: bool,

    /// Manually configured validator node IDs (if not using DHT)
    pub validator_nodes: Vec<NodeId>,
}

impl Default for ConsensusConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            required_confirmations: 3,
            total_validators: 5,
            timeout_secs: 10,
            use_dht_discovery: true,
            validator_nodes: Vec::new(),
        }
    }
}

/// Result of a consensus request
#[derive(Debug, Clone, PartialEq)]
pub struct ConsensusResult {
    /// Whether the message was approved (K-of-N confirmations received)
    pub approved: bool,

    /// Number of confirmations received
    pub confirmations: u32,

    /// Total validators queried
    pub validators_queried: u32,

    /// Validator node IDs that responded
    pub validators: Vec<NodeId>,

    /// Whether the request timed out
    pub timed_out: bool,
}

/// Consensus request tracking
#[derive(Debug, Clone)]
struct ConsensusRequest {
    message_id: MessageId,
    started_at: Instant,
    confirmations: u32,
    rejections: u32,
    validators_responded: Vec<NodeId>,
}

/// Statistics for consensus validation
#[derive(Debug, Clone, Default)]
pub struct ConsensusStats {
    /// Total consensus requests made
    pub total_requests: u64,

    /// Requests that were approved
    pub approved: u64,

    /// Requests that were rejected
    pub rejected: u64,

    /// Requests that timed out
    pub timed_out: u64,

    /// Average response time in milliseconds
    pub avg_response_time_ms: u64,
}

/// K-of-N consensus validator for Global realm emergency messages
pub struct ConsensusValidator {
    config: ConsensusConfig,
    active_requests: Arc<RwLock<HashMap<MessageId, ConsensusRequest>>>,
    stats: Arc<RwLock<ConsensusStats>>,
}

impl ConsensusValidator {
    /// Create a new ConsensusValidator
    pub fn new(config: ConsensusConfig) -> Self {
        Self {
            config,
            active_requests: Arc::new(RwLock::new(HashMap::new())),
            stats: Arc::new(RwLock::new(ConsensusStats::default())),
        }
    }

    /// Request consensus for a Global realm emergency message
    ///
    /// This is a synchronous implementation that simulates consensus.
    /// In a production system, this would:
    /// 1. Discover N validators via DHT (closest nodes to message hash)
    /// 2. Send consensus requests to validators in parallel
    /// 3. Collect responses with timeout
    /// 4. Return approved if K confirmations received
    ///
    /// # Arguments
    /// * `message` - The emergency message to validate
    ///
    /// # Returns
    /// * `Ok(ConsensusResult)` - Result of consensus validation
    /// * `Err(RoutingError)` - If consensus validation fails
    pub fn request_consensus(&self, message: &Message) -> Result<ConsensusResult> {
        if !self.config.enabled {
            // If consensus is disabled, auto-approve
            return Ok(ConsensusResult {
                approved: true,
                confirmations: self.config.required_confirmations,
                validators_queried: 0,
                validators: Vec::new(),
                timed_out: false,
            });
        }

        // Update statistics
        {
            let mut stats = self.stats.write().unwrap();
            stats.total_requests += 1;
        }

        // Track this request
        let request = ConsensusRequest {
            message_id: message.id,
            started_at: Instant::now(),
            confirmations: 0,
            rejections: 0,
            validators_responded: Vec::new(),
        };

        {
            let mut active = self.active_requests.write().unwrap();
            active.insert(message.id, request);
        }

        // SIMPLIFIED IMPLEMENTATION:
        // In a full implementation, this would:
        // 1. Use DHT to find N closest nodes to hash(message.id)
        // 2. Send ConsensusRequest messages to each validator
        // 3. Wait for ConsensusResponse messages with timeout
        // 4. Count confirmations and rejections
        //
        // For now, we simulate this with a deterministic algorithm:
        // - Use message ID hash to determine approval
        // - This allows testing without full DHT/networking implementation

        let result = self.simulate_consensus(message)?;

        // Clean up request tracking
        {
            let mut active = self.active_requests.write().unwrap();
            active.remove(&message.id);
        }

        // Update statistics
        {
            let mut stats = self.stats.write().unwrap();
            if result.approved {
                stats.approved += 1;
            } else if result.timed_out {
                stats.timed_out += 1;
            } else {
                stats.rejected += 1;
            }
        }

        Ok(result)
    }

    /// Simulate consensus for testing purposes
    ///
    /// This is a deterministic simulation that allows testing without
    /// full network infrastructure. In production, this would be replaced
    /// with actual DHT-based validator discovery and network communication.
    ///
    /// The simulation uses the message ID to deterministically decide:
    /// - Which validators would approve
    /// - Whether timeout would occur
    fn simulate_consensus(&self, message: &Message) -> Result<ConsensusResult> {
        // Use message ID bytes to generate deterministic but varied responses
        let msg_bytes = message.id.as_bytes();

        // Calculate a score from first few bytes
        let score = (msg_bytes[0] as u32 + msg_bytes[1] as u32 + msg_bytes[2] as u32) % 10;

        // Simulate validators
        let validators_queried = self.config.total_validators;
        let mut confirmations = 0;
        let mut validators = Vec::new();

        // Simulate validator responses based on score
        // Use a simple rule: each validator independently decides based on msg_bytes
        for i in 0..validators_queried {
            // Each validator has different criteria
            // Use message bytes and validator index to create variance
            let validator_threshold = (msg_bytes[i as usize % 16] as u32 + i * 30) % 100;
            let message_strength = (score * 10) + ((msg_bytes[(i as usize + 1) % 16] as u32) % 10);

            // Validator approves if message strength exceeds their threshold
            if message_strength > validator_threshold {
                confirmations += 1;
                // Create a dummy validator node ID
                let mut validator_id_bytes = [0u8; 64];
                validator_id_bytes[0] = i as u8;
                validators.push(NodeId::from_bytes(validator_id_bytes));
            }
        }

        // Check if timeout would occur (simulate network delay)
        // For simulation, we don't actually timeout - just return based on confirmations
        let approved = confirmations >= self.config.required_confirmations;

        Ok(ConsensusResult {
            approved,
            confirmations,
            validators_queried,
            validators,
            timed_out: false,
        })
    }

    /// Get current consensus statistics
    pub fn get_stats(&self) -> ConsensusStats {
        self.stats.read().unwrap().clone()
    }

    /// Get number of active consensus requests
    pub fn active_request_count(&self) -> usize {
        self.active_requests.read().unwrap().len()
    }

    /// Cleanup stale consensus requests (called periodically)
    pub fn cleanup_stale(&self) {
        let timeout = Duration::from_secs(self.config.timeout_secs * 2);
        let now = Instant::now();

        let mut active = self.active_requests.write().unwrap();
        active.retain(|_, req| now.duration_since(req.started_at) < timeout);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use myriadmesh_protocol::{MessageType};

    fn create_test_node_id(byte: u8) -> NodeId {
        NodeId::from_bytes([byte; 64])
    }

    fn create_test_message(id_byte: u8) -> Message {
        let mut msg = Message::new(
            create_test_node_id(1),
            create_test_node_id(2),
            MessageType::Data,
            vec![0u8; 100],
        )
        .unwrap();

        // Override the message ID to control consensus simulation
        msg.id = MessageId::from_bytes([id_byte; 16]);
        msg
    }

    #[test]
    fn test_consensus_validator_creation() {
        let config = ConsensusConfig::default();
        let validator = ConsensusValidator::new(config);

        let stats = validator.get_stats();
        assert_eq!(stats.total_requests, 0);
        assert_eq!(validator.active_request_count(), 0);
    }

    #[test]
    fn test_consensus_disabled() {
        let config = ConsensusConfig {
            enabled: false,
            ..Default::default()
        };
        let validator = ConsensusValidator::new(config);
        let msg = create_test_message(0);

        let result = validator.request_consensus(&msg).unwrap();

        assert!(result.approved);
        assert_eq!(result.validators_queried, 0);
    }

    #[test]
    fn test_consensus_approval() {
        let config = ConsensusConfig {
            enabled: true,
            required_confirmations: 3,
            total_validators: 5,
            ..Default::default()
        };
        let validator = ConsensusValidator::new(config);

        // Test multiple messages with different IDs to ensure variance
        let test_cases = vec![
            0, 1, 5, 10, 15, 20, 25, 30, 40, 50,
            60, 70, 80, 90, 100, 111, 123, 150, 200, 255,
        ];

        let mut approved_count = 0;
        let mut rejected_count = 0;

        for id_byte in test_cases {
            let msg = create_test_message(id_byte);
            let result = validator.request_consensus(&msg).unwrap();

            if result.approved {
                approved_count += 1;
                assert!(result.confirmations >= 3, "Approved messages should have ≥3 confirmations, got {}", result.confirmations);
            } else {
                rejected_count += 1;
                assert!(result.confirmations < 3, "Rejected messages should have <3 confirmations, got {}", result.confirmations);
            }

            assert_eq!(result.validators_queried, 5);
            assert!(!result.timed_out);
        }

        // Should have both approvals and rejections (deterministic but varied)
        // With varied input, we expect at least some variation
        assert!(approved_count > 0, "Should have some approved messages (got {} approved, {} rejected)", approved_count, rejected_count);
        assert!(rejected_count > 0, "Should have some rejected messages (got {} approved, {} rejected)", approved_count, rejected_count);

        let stats = validator.get_stats();
        assert_eq!(stats.total_requests, 20);
        assert_eq!(stats.approved + stats.rejected, 20);
    }

    #[test]
    fn test_consensus_k_of_n() {
        // Test different K-of-N configurations
        let configs = vec![
            (2, 3),  // 2-of-3
            (3, 5),  // 3-of-5
            (4, 7),  // 4-of-7
        ];

        for (k, n) in configs {
            let config = ConsensusConfig {
                enabled: true,
                required_confirmations: k,
                total_validators: n,
                ..Default::default()
            };
            let validator = ConsensusValidator::new(config);
            let msg = create_test_message(100); // Use a consistent message

            let result = validator.request_consensus(&msg).unwrap();

            if result.approved {
                assert!(
                    result.confirmations >= k,
                    "Approved message should have at least {} confirmations, got {}",
                    k,
                    result.confirmations
                );
            } else {
                assert!(
                    result.confirmations < k,
                    "Rejected message should have less than {} confirmations, got {}",
                    k,
                    result.confirmations
                );
            }

            assert_eq!(result.validators_queried, n);
        }
    }

    #[test]
    fn test_consensus_statistics() {
        let config = ConsensusConfig::default();
        let validator = ConsensusValidator::new(config);

        // Make several consensus requests
        for i in 0..10 {
            let msg = create_test_message(i * 25);
            let _ = validator.request_consensus(&msg);
        }

        let stats = validator.get_stats();
        assert_eq!(stats.total_requests, 10);
        assert!(stats.approved + stats.rejected + stats.timed_out == 10);
        assert_eq!(validator.active_request_count(), 0); // All requests should be complete
    }

    #[test]
    fn test_consensus_deterministic() {
        // Same message should always get same result
        let config = ConsensusConfig::default();
        let validator = ConsensusValidator::new(config);
        let msg = create_test_message(42);

        let result1 = validator.request_consensus(&msg).unwrap();
        let result2 = validator.request_consensus(&msg).unwrap();

        assert_eq!(result1.approved, result2.approved);
        assert_eq!(result1.confirmations, result2.confirmations);
    }

    #[test]
    fn test_consensus_cleanup_stale() {
        let config = ConsensusConfig {
            timeout_secs: 1,
            ..Default::default()
        };
        let validator = ConsensusValidator::new(config);

        // Manually insert a stale request
        {
            let mut active = validator.active_requests.write().unwrap();
            let msg = create_test_message(1);
            active.insert(
                msg.id,
                ConsensusRequest {
                    message_id: msg.id,
                    started_at: Instant::now() - Duration::from_secs(10),
                    confirmations: 0,
                    rejections: 0,
                    validators_responded: Vec::new(),
                },
            );
        }

        assert_eq!(validator.active_request_count(), 1);

        validator.cleanup_stale();

        assert_eq!(validator.active_request_count(), 0);
    }
}
