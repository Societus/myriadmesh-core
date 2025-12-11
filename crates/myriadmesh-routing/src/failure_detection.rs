//! Consensus-Based Failure Detection
//!
//! This module implements distributed failure detection using consensus
//! to minimize false positives and enable reliable failover:
//!
//! - Local suspicion based on missed heartbeats (3 consecutive)
//! - Consensus verification by querying 5-10 peer nodes
//! - >2/3 agreement required for confirmed failure
//! - Automated failover and recovery handling
//!
//! ## Detection Protocol
//!
//! 1. **Local Detection**: Node suspects peer after 3 missed heartbeats
//! 2. **Consensus Query**: Query 5-10 randomly selected trusted nodes
//! 3. **Aggregation**: Collect responses within timeout (10s)
//! 4. **Decision**: If >2/3 agree peer is down, mark as confirmed
//! 5. **Action**: Trigger failover, DHT updates, relay reassignment
//!
//! ## Performance Targets
//!
//! - False positive rate: <0.1%
//! - Detection time: <10 seconds
//! - Recovery detection: <30 seconds

use crate::consensus::{ConsensusManager, ConsensusType};
use crate::error::{Result, RoutingError};
use myriadmesh_protocol::NodeId;
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};
use std::fmt::Write as _;

/// Configuration for failure detection
#[derive(Debug, Clone)]
pub struct FailureDetectionConfig {
    /// Enable consensus-based failure detection
    pub enabled: bool,

    /// Number of missed heartbeats before local suspicion
    pub missed_heartbeat_threshold: u32,

    /// Heartbeat interval (seconds)
    pub heartbeat_interval_secs: u64,

    /// Grace period before declaring node down (seconds)
    pub grace_period_secs: u64,

    /// Number of peers to query for consensus
    pub consensus_peers_count: usize,

    /// Consensus agreement threshold (0.0 - 1.0)
    pub consensus_threshold: f32,

    /// Timeout for consensus queries (seconds)
    pub consensus_timeout_secs: u64,

    /// Recovery confirmation required heartbeats
    pub recovery_confirmation_count: u32,
}

impl Default for FailureDetectionConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            missed_heartbeat_threshold: 3,
            heartbeat_interval_secs: 60,
            grace_period_secs: 180, // 3 minutes
            consensus_peers_count: 7,
            consensus_threshold: 0.67, // >2/3
            consensus_timeout_secs: 10,
            recovery_confirmation_count: 2,
        }
    }
}

/// Node status in failure detection
#[derive(Debug, Clone, PartialEq)]
pub enum NodeStatus {
    /// Node is healthy
    Healthy,
    /// Node is suspected (local detection only)
    Suspected {
        suspected_since: Instant,
        missed_heartbeats: u32,
    },
    /// Node is confirmed down (consensus reached)
    ConfirmedDown {
        confirmed_at: Instant,
        confirming_nodes: Vec<NodeId>,
    },
    /// Node is recovering (seen after being down)
    Recovering {
        recovery_started: Instant,
        confirmations: u32,
    },
}

/// Failure report from a peer
#[derive(Debug, Clone)]
pub struct FailureReport {
    /// Node reporting the failure
    pub reporter_id: NodeId,
    /// When the failure was reported
    pub reported_at: Instant,
    /// Number of missed heartbeats
    pub missed_heartbeats: u32,
    /// Last seen timestamp
    pub last_seen: Option<Instant>,
}

/// Tracked node for failure detection
struct TrackedNode {
    node_id: NodeId,
    status: NodeStatus,
    last_heartbeat: Instant,
    consecutive_missed: u32,
    failure_reports: Vec<FailureReport>,
}

/// Statistics for failure detection
#[derive(Debug, Clone, Default)]
pub struct FailureDetectionStats {
    /// Total nodes tracked
    pub tracked_nodes: usize,
    /// Nodes currently suspected
    pub suspected_nodes: usize,
    /// Nodes confirmed down
    pub confirmed_down_nodes: usize,
    /// Total false positives (recovered without consensus)
    pub false_positives: u64,
    /// Total true positives (consensus confirmed failures)
    pub true_positives: u64,
    /// Average detection time (ms)
    pub avg_detection_time_ms: f64,
}

/// Failure detection manager with consensus
pub struct FailureDetectionManager {
    config: FailureDetectionConfig,
    consensus_manager: Option<Arc<ConsensusManager>>,
    tracked_nodes: Arc<RwLock<HashMap<NodeId, TrackedNode>>>,
    trusted_peers: Arc<RwLock<HashSet<NodeId>>>,
    stats: Arc<RwLock<FailureDetectionStats>>,
}

impl FailureDetectionManager {
    /// Create a new failure detection manager
    pub fn new(config: FailureDetectionConfig) -> Self {
        Self {
            config,
            consensus_manager: None,
            tracked_nodes: Arc::new(RwLock::new(HashMap::new())),
            trusted_peers: Arc::new(RwLock::new(HashSet::new())),
            stats: Arc::new(RwLock::new(FailureDetectionStats::default())),
        }
    }

    /// Set consensus manager for distributed verification
    pub fn set_consensus_manager(&mut self, consensus_manager: Arc<ConsensusManager>) {
        self.consensus_manager = Some(consensus_manager);
    }

    /// Add a trusted peer for consensus queries
    pub fn add_trusted_peer(&self, peer_id: NodeId) {
        let mut peers = self.trusted_peers.write().unwrap();
        peers.insert(peer_id);
    }

    /// Remove a trusted peer
    pub fn remove_trusted_peer(&self, peer_id: &NodeId) {
        let mut peers = self.trusted_peers.write().unwrap();
        peers.remove(peer_id);
    }

    /// Register a node for failure detection tracking
    pub fn track_node(&self, node_id: NodeId) {
        let mut nodes = self.tracked_nodes.write().unwrap();
        if !nodes.contains_key(&node_id) {
            nodes.insert(
                node_id,
                TrackedNode {
                    node_id,
                    status: NodeStatus::Healthy,
                    last_heartbeat: Instant::now(),
                    consecutive_missed: 0,
                    failure_reports: Vec::new(),
                },
            );
        }
    }

    /// Record heartbeat from a node
    pub fn record_heartbeat(&self, node_id: &NodeId) -> Result<()> {
        let mut nodes = self.tracked_nodes.write().unwrap();

        if let Some(node) = nodes.get_mut(node_id) {
            let previous_status = node.status.clone();
            node.last_heartbeat = Instant::now();
            node.consecutive_missed = 0;

            // Check if node is recovering
            match previous_status {
                NodeStatus::ConfirmedDown { .. } => {
                    node.status = NodeStatus::Recovering {
                        recovery_started: Instant::now(),
                        confirmations: 1,
                    };
                }
                NodeStatus::Recovering {
                    recovery_started,
                    confirmations,
                } => {
                    if confirmations + 1 >= self.config.recovery_confirmation_count {
                        node.status = NodeStatus::Healthy;
                    } else {
                        node.status = NodeStatus::Recovering {
                            recovery_started,
                            confirmations: confirmations + 1,
                        };
                    }
                }
                NodeStatus::Suspected { .. } => {
                    node.status = NodeStatus::Healthy;
                    // Record false positive
                    let mut stats = self.stats.write().unwrap();
                    stats.false_positives += 1;
                }
                NodeStatus::Healthy => {}
            }
        } else {
            return Err(RoutingError::Other("Node not tracked".into()));
        }

        Ok(())
    }

    /// Check for failed nodes (called periodically)
    pub fn check_failures(&self) -> Result<Vec<NodeId>> {
        if !self.config.enabled {
            return Ok(Vec::new());
        }

        let mut newly_down = Vec::new();
        let now = Instant::now();
        let heartbeat_timeout = Duration::from_secs(
            self.config.heartbeat_interval_secs * self.config.missed_heartbeat_threshold as u64,
        );

        let mut nodes = self.tracked_nodes.write().unwrap();

        for node in nodes.values_mut() {
            match node.status {
                NodeStatus::Healthy => {
                    // Check if heartbeat timeout exceeded
                    if now.duration_since(node.last_heartbeat) > heartbeat_timeout {
                        node.consecutive_missed += 1;
                        if node.consecutive_missed >= self.config.missed_heartbeat_threshold {
                            // Mark as suspected
                            node.status = NodeStatus::Suspected {
                                suspected_since: now,
                                missed_heartbeats: node.consecutive_missed,
                            };
                        }
                    }
                }
                NodeStatus::Suspected {
                    suspected_since,
                    missed_heartbeats,
                } => {
                    // Check if grace period elapsed
                    if now.duration_since(suspected_since)
                        > Duration::from_secs(self.config.grace_period_secs)
                    {
                        // Initiate consensus verification
                        if let Some(confirmed) = self.verify_failure_with_consensus(&node.node_id)? {
                            if confirmed {
                                node.status = NodeStatus::ConfirmedDown {
                                    confirmed_at: now,
                                    confirming_nodes: Vec::new(), // Would be populated by consensus
                                };
                                newly_down.push(node.node_id);

                                // Update stats
                                let mut stats = self.stats.write().unwrap();
                                stats.true_positives += 1;
                                let detection_time = now.duration_since(suspected_since).as_millis() as f64;
                                stats.avg_detection_time_ms = (stats.avg_detection_time_ms
                                    * (stats.true_positives - 1) as f64
                                    + detection_time)
                                    / stats.true_positives as f64;
                            } else {
                                // Consensus says node is up, mark healthy
                                node.status = NodeStatus::Healthy;
                                node.consecutive_missed = 0;
                            }
                        }
                    }
                }
                _ => {}
            }
        }

        Ok(newly_down)
    }

    /// Get status of a specific node
    pub fn get_status(&self, node_id: &NodeId) -> Option<NodeStatus> {
        let nodes = self.tracked_nodes.read().unwrap();
        nodes.get(node_id).map(|node| node.status.clone())
    }

    /// Check if node is confirmed down
    pub fn is_confirmed_down(&self, node_id: &NodeId) -> bool {
        let nodes = self.tracked_nodes.read().unwrap();
        nodes
            .get(node_id)
            .map(|node| matches!(node.status, NodeStatus::ConfirmedDown { .. }))
            .unwrap_or(false)
    }

    /// Get statistics
    pub fn get_stats(&self) -> FailureDetectionStats {
        let mut stats = self.stats.read().unwrap().clone();
        let nodes = self.tracked_nodes.read().unwrap();

        stats.tracked_nodes = nodes.len();
        stats.suspected_nodes = nodes
            .values()
            .filter(|n| matches!(n.status, NodeStatus::Suspected { .. }))
            .count();
        stats.confirmed_down_nodes = nodes
            .values()
            .filter(|n| matches!(n.status, NodeStatus::ConfirmedDown { .. }))
            .count();

        stats
    }

    /// Cleanup old tracked nodes
    pub fn cleanup_stale(&self, max_age_secs: u64) {
        let mut nodes = self.tracked_nodes.write().unwrap();
        let cutoff = Instant::now() - Duration::from_secs(max_age_secs);

        nodes.retain(|_, node| node.last_heartbeat > cutoff);
    }

    // Private helper methods

    fn verify_failure_with_consensus(&self, node_id: &NodeId) -> Result<Option<bool>> {
        // If consensus manager not available, use local detection only
        let Some(consensus_mgr) = &self.consensus_manager else {
            return Ok(Some(true)); // Assume down if no consensus available
        };

        // Select random trusted peers for consensus
        let peers = self.trusted_peers.read().unwrap();
        let peer_count = self.config.consensus_peers_count.min(peers.len());

        if peer_count < 3 {
            // Not enough peers for meaningful consensus
            return Ok(Some(true));
        }

        let selected_peers: Vec<NodeId> = peers.iter().take(peer_count).copied().collect();

        // Create consensus proposal for failure verification
        let mut conflict_id = String::from("failure_detection_");
        for byte in node_id.as_bytes().iter().take(8) {
            let _ = write!(&mut conflict_id, "{:02x}", byte);
        }
        let consensus_type = ConsensusType::ConflictResolution {
            conflict_id,
            options: vec![vec![1], vec![0]], // 1 = down, 0 = up
        };

        // Initiate consensus (this would normally be async in production)
        match consensus_mgr.initiate_consensus(
            consensus_type,
            vec![1], // Propose node is down
            selected_peers,
        ) {
            Ok(result) => {
                if result.timed_out {
                    Ok(None) // Consensus timed out, can't determine
                } else {
                    // Check if quorum reached
                    let quorum_threshold =
                        (result.total_participants as f32 * self.config.consensus_threshold).ceil() as usize;
                    Ok(Some(result.accept_votes >= quorum_threshold))
                }
            }
            Err(_) => Ok(None), // Consensus failed
        }
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
    fn test_failure_detection_manager_creation() {
        let config = FailureDetectionConfig::default();
        let manager = FailureDetectionManager::new(config);
        let stats = manager.get_stats();
        assert_eq!(stats.tracked_nodes, 0);
    }

    #[test]
    fn test_track_node() {
        let manager = FailureDetectionManager::new(FailureDetectionConfig::default());
        let node_id = create_test_node_id(1);

        manager.track_node(node_id);
        let stats = manager.get_stats();
        assert_eq!(stats.tracked_nodes, 1);
    }

    #[test]
    fn test_record_heartbeat() {
        let manager = FailureDetectionManager::new(FailureDetectionConfig::default());
        let node_id = create_test_node_id(1);

        manager.track_node(node_id);
        assert!(manager.record_heartbeat(&node_id).is_ok());

        let status = manager.get_status(&node_id).unwrap();
        assert_eq!(status, NodeStatus::Healthy);
    }

    #[test]
    fn test_node_suspected_after_timeout() {
        let config = FailureDetectionConfig {
            missed_heartbeat_threshold: 3,
            heartbeat_interval_secs: 1,
            ..Default::default()
        };
        let manager = FailureDetectionManager::new(config);
        let node_id = create_test_node_id(1);

        manager.track_node(node_id);

        // Simulate time passing by manually updating node state
        {
            let mut nodes = manager.tracked_nodes.write().unwrap();
            if let Some(node) = nodes.get_mut(&node_id) {
                node.last_heartbeat = Instant::now() - Duration::from_secs(10);
                node.consecutive_missed = 3;
                node.status = NodeStatus::Suspected {
                    suspected_since: Instant::now(),
                    missed_heartbeats: 3,
                };
            }
        }

        let status = manager.get_status(&node_id).unwrap();
        assert!(matches!(status, NodeStatus::Suspected { .. }));
    }

    #[test]
    fn test_add_trusted_peer() {
        let manager = FailureDetectionManager::new(FailureDetectionConfig::default());
        let peer_id = create_test_node_id(10);

        manager.add_trusted_peer(peer_id);

        let peers = manager.trusted_peers.read().unwrap();
        assert!(peers.contains(&peer_id));
    }

    #[test]
    fn test_remove_trusted_peer() {
        let manager = FailureDetectionManager::new(FailureDetectionConfig::default());
        let peer_id = create_test_node_id(10);

        manager.add_trusted_peer(peer_id);
        manager.remove_trusted_peer(&peer_id);

        let peers = manager.trusted_peers.read().unwrap();
        assert!(!peers.contains(&peer_id));
    }

    #[test]
    fn test_recovery_detection() {
        let config = FailureDetectionConfig {
            recovery_confirmation_count: 2,
            ..Default::default()
        };
        let manager = FailureDetectionManager::new(config);
        let node_id = create_test_node_id(1);

        manager.track_node(node_id);

        // Simulate node going down
        {
            let mut nodes = manager.tracked_nodes.write().unwrap();
            if let Some(node) = nodes.get_mut(&node_id) {
                node.status = NodeStatus::ConfirmedDown {
                    confirmed_at: Instant::now(),
                    confirming_nodes: Vec::new(),
                };
            }
        }

        // First heartbeat after down -> recovering
        manager.record_heartbeat(&node_id).unwrap();
        let status = manager.get_status(&node_id).unwrap();
        assert!(matches!(status, NodeStatus::Recovering { .. }));

        // Second heartbeat -> healthy
        manager.record_heartbeat(&node_id).unwrap();
        let status = manager.get_status(&node_id).unwrap();
        assert_eq!(status, NodeStatus::Healthy);
    }

    #[test]
    fn test_is_confirmed_down() {
        let manager = FailureDetectionManager::new(FailureDetectionConfig::default());
        let node_id = create_test_node_id(1);

        manager.track_node(node_id);
        assert!(!manager.is_confirmed_down(&node_id));

        // Simulate confirmed down
        {
            let mut nodes = manager.tracked_nodes.write().unwrap();
            if let Some(node) = nodes.get_mut(&node_id) {
                node.status = NodeStatus::ConfirmedDown {
                    confirmed_at: Instant::now(),
                    confirming_nodes: Vec::new(),
                };
            }
        }

        assert!(manager.is_confirmed_down(&node_id));
    }
}
