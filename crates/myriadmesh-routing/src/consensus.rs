//! Consensus Protocol for Relay Selection and Network Coordination
//!
//! This module implements a Byzantine Fault Tolerant (BFT) consensus protocol
//! for distributed decision-making in the MyriadMesh network:
//!
//! - Relay selection for ephemeral clients
//! - Network parameter coordination
//! - Conflict resolution
//!
//! ## Protocol Overview
//!
//! The consensus protocol uses a leader-based approach with the following phases:
//!
//! 1. **Leader Election**: DHT-based deterministic leader selection
//! 2. **Proposal Phase**: Leader proposes a value
//! 3. **Voting Phase**: Participants vote on the proposal
//! 4. **Commit Phase**: If >2/3 quorum reached, value is committed
//!
//! ## Byzantine Fault Tolerance
//!
//! The protocol can tolerate up to f Byzantine failures where:
//! - Total participants: n = 3f + 1
//! - Required quorum: 2f + 1 (>2/3 of n)
//!
//! For example, with 7 participants, up to 2 can be Byzantine (7 = 3*2 + 1).

use crate::error::{Result, RoutingError};
use myriadmesh_crypto::identity::NodeIdentity;
use myriadmesh_protocol::{MessageId, NodeId};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// Configuration for consensus protocol
#[derive(Debug, Clone)]
pub struct ConsensusConfig {
    /// Enable consensus protocol
    pub enabled: bool,

    /// Minimum number of participants (default: 7 for f=2)
    pub min_participants: usize,

    /// Maximum number of participants (default: 21 for f=6)
    pub max_participants: usize,

    /// Quorum threshold as fraction (default: 0.67 for >2/3)
    pub quorum_threshold: f32,

    /// Timeout for proposal phase (seconds)
    pub proposal_timeout_secs: u64,

    /// Timeout for voting phase (seconds)
    pub voting_timeout_secs: u64,

    /// Timeout for commit phase (seconds)
    pub commit_timeout_secs: u64,

    /// Enable cryptographic vote signatures
    pub require_signatures: bool,
}

impl Default for ConsensusConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            min_participants: 7,
            max_participants: 21,
            quorum_threshold: 0.67, // >2/3
            proposal_timeout_secs: 10,
            voting_timeout_secs: 10,
            commit_timeout_secs: 5,
            require_signatures: true,
        }
    }
}

/// Type of consensus decision
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ConsensusType {
    /// Select relay for ephemeral client
    RelaySelection {
        client_id: NodeId,
        candidates: Vec<NodeId>,
    },
    /// Coordinate network parameter change
    ParameterChange {
        parameter: String,
        value: Vec<u8>,
    },
    /// Resolve conflict between nodes
    ConflictResolution {
        conflict_id: String,
        options: Vec<Vec<u8>>,
    },
}

/// Proposal for consensus
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsensusProposal {
    /// Unique proposal ID
    pub proposal_id: MessageId,

    /// Type of consensus
    pub consensus_type: ConsensusType,

    /// Proposed value
    pub proposed_value: Vec<u8>,

    /// Leader who created the proposal
    pub leader_id: NodeId,

    /// Participants in this consensus round
    pub participants: Vec<NodeId>,

    /// Timestamp when created
    pub created_at: u64,

    /// Cryptographic signature from leader
    pub signature: Option<Vec<u8>>,
}

/// Vote on a consensus proposal
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsensusVote {
    /// Proposal being voted on
    pub proposal_id: MessageId,

    /// Voter node ID
    pub voter_id: NodeId,

    /// Vote decision (true = accept, false = reject)
    pub accept: bool,

    /// Optional reason for rejection
    pub rejection_reason: Option<String>,

    /// Timestamp of vote
    pub voted_at: u64,

    /// Cryptographic signature from voter
    pub signature: Option<Vec<u8>>,
}

/// Result of a consensus round
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsensusResult {
    /// Proposal ID
    pub proposal_id: MessageId,

    /// Whether consensus was reached
    pub committed: bool,

    /// Committed value (if successful)
    pub value: Option<Vec<u8>>,

    /// Number of accept votes
    pub accept_votes: usize,

    /// Number of reject votes
    pub reject_votes: usize,

    /// Total participants
    pub total_participants: usize,

    /// Time taken to reach consensus (ms)
    pub duration_ms: u64,

    /// Whether timeout occurred
    pub timed_out: bool,
}

/// Current state of a consensus round
#[derive(Debug, Clone, PartialEq)]
enum ConsensusPhase {
    /// Waiting for proposal from leader
    Proposal,
    /// Collecting votes from participants
    Voting,
    /// Finalizing commit
    Commit,
    /// Round completed
    Completed,
    /// Round aborted (timeout or failure)
    Aborted,
}

/// Active consensus round tracking
struct ConsensusRound {
    /// The proposal being voted on
    proposal: ConsensusProposal,

    /// Current phase
    phase: ConsensusPhase,

    /// Collected votes
    votes: HashMap<NodeId, ConsensusVote>,

    /// Start time
    started_at: Instant,

    /// Phase deadlines
    proposal_deadline: Instant,
    voting_deadline: Instant,
    commit_deadline: Instant,
}

/// Statistics for consensus protocol
#[derive(Debug, Clone, Default)]
pub struct ConsensusStats {
    /// Total rounds initiated
    pub rounds_initiated: u64,

    /// Successful commits
    pub commits_successful: u64,

    /// Failed rounds
    pub rounds_failed: u64,

    /// Rounds timed out
    pub rounds_timed_out: u64,

    /// Average time to consensus (ms)
    pub avg_consensus_time_ms: f64,

    /// Total votes cast
    pub total_votes_cast: u64,
}

/// Consensus protocol manager
pub struct ConsensusManager {
    config: ConsensusConfig,
    identity: Option<Arc<NodeIdentity>>,
    active_rounds: Arc<RwLock<HashMap<MessageId, ConsensusRound>>>,
    stats: Arc<RwLock<ConsensusStats>>,
}

impl ConsensusManager {
    /// Create a new consensus manager
    pub fn new(config: ConsensusConfig) -> Self {
        Self {
            config,
            identity: None,
            active_rounds: Arc::new(RwLock::new(HashMap::new())),
            stats: Arc::new(RwLock::new(ConsensusStats::default())),
        }
    }

    /// Set node identity for signing
    pub fn set_identity(&mut self, identity: Arc<NodeIdentity>) {
        self.identity = Some(identity);
    }

    /// Initiate a consensus round
    ///
    /// # Arguments
    /// * `consensus_type` - Type of consensus decision
    /// * `proposed_value` - Proposed value for decision
    /// * `participants` - List of participating node IDs
    ///
    /// # Returns
    /// Result containing the consensus outcome
    pub fn initiate_consensus(
        &self,
        consensus_type: ConsensusType,
        proposed_value: Vec<u8>,
        participants: Vec<NodeId>,
    ) -> Result<ConsensusResult> {
        if !self.config.enabled {
            return Err(RoutingError::Other("Consensus protocol disabled".into()));
        }

        // Validate participant count
        if participants.len() < self.config.min_participants {
            return Err(RoutingError::Other(format!(
                "Insufficient participants: {} < {}",
                participants.len(),
                self.config.min_participants
            )));
        }

        if participants.len() > self.config.max_participants {
            return Err(RoutingError::Other(format!(
                "Too many participants: {} > {}",
                participants.len(),
                self.config.max_participants
            )));
        }

        // Select leader via DHT-based deterministic election
        let leader_id = self.elect_leader(&participants, &consensus_type)?;

        // Create proposal
        let proposal_id = MessageId::from_bytes([0u8; 16]);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let mut proposal = ConsensusProposal {
            proposal_id,
            consensus_type: consensus_type.clone(),
            proposed_value: proposed_value.clone(),
            leader_id,
            participants: participants.clone(),
            created_at: now,
            signature: None,
        };

        // Sign proposal if required
        if self.config.require_signatures {
            if let Some(identity) = &self.identity {
                let sig = self.sign_proposal(&proposal, identity)?;
                proposal.signature = Some(sig);
            }
        }

        // Initialize consensus round
        let now_instant = Instant::now();
        let round = ConsensusRound {
            proposal: proposal.clone(),
            phase: ConsensusPhase::Proposal,
            votes: HashMap::new(),
            started_at: now_instant,
            proposal_deadline: now_instant + Duration::from_secs(self.config.proposal_timeout_secs),
            voting_deadline: now_instant
                + Duration::from_secs(self.config.proposal_timeout_secs + self.config.voting_timeout_secs),
            commit_deadline: now_instant
                + Duration::from_secs(
                    self.config.proposal_timeout_secs
                        + self.config.voting_timeout_secs
                        + self.config.commit_timeout_secs,
                ),
        };

        // Store active round
        {
            let mut rounds = self.active_rounds.write().unwrap();
            rounds.insert(proposal_id, round);
        }

        // Update stats
        {
            let mut stats = self.stats.write().unwrap();
            stats.rounds_initiated += 1;
        }

        // Execute consensus protocol
        self.execute_consensus_round(proposal_id)
    }

    /// Submit a vote for an active consensus round
    pub fn submit_vote(&self, vote: ConsensusVote) -> Result<()> {
        if !self.config.enabled {
            return Ok(());
        }

        // Verify vote signature if required
        if self.config.require_signatures && vote.signature.is_none() {
            return Err(RoutingError::Other("Vote signature required".into()));
        }

        // Add vote to round
        let mut rounds = self.active_rounds.write().unwrap();
        if let Some(round) = rounds.get_mut(&vote.proposal_id) {
            // Check if still in voting phase
            if round.phase != ConsensusPhase::Voting {
                return Err(RoutingError::Other(format!(
                    "Round not in voting phase: {:?}",
                    round.phase
                )));
            }

            // Check if voter is participant
            if !round.proposal.participants.contains(&vote.voter_id) {
                return Err(RoutingError::Other("Voter not in participant list".into()));
            }

            // Record vote
            round.votes.insert(vote.voter_id, vote);

            // Update stats
            let mut stats = self.stats.write().unwrap();
            stats.total_votes_cast += 1;
        } else {
            return Err(RoutingError::Other("No active round found for proposal".into()));
        }

        Ok(())
    }

    /// Get result of a consensus round
    pub fn get_result(&self, proposal_id: &MessageId) -> Option<ConsensusResult> {
        let rounds = self.active_rounds.read().unwrap();
        rounds.get(proposal_id).and_then(|round| {
            if round.phase == ConsensusPhase::Completed || round.phase == ConsensusPhase::Aborted {
                Some(self.calculate_result(round))
            } else {
                None
            }
        })
    }

    /// Get current statistics
    pub fn get_stats(&self) -> ConsensusStats {
        self.stats.read().unwrap().clone()
    }

    /// Cleanup completed rounds
    pub fn cleanup_completed(&self) {
        let mut rounds = self.active_rounds.write().unwrap();
        rounds.retain(|_, round| {
            round.phase != ConsensusPhase::Completed && round.phase != ConsensusPhase::Aborted
        });
    }

    // Private helper methods

    fn elect_leader(&self, participants: &[NodeId], consensus_type: &ConsensusType) -> Result<NodeId> {
        // DHT-based deterministic leader election
        // Use hash of consensus type to select leader index
        let type_hash = self.hash_consensus_type(consensus_type);
        let leader_index = (type_hash as usize) % participants.len();
        Ok(participants[leader_index])
    }

    fn hash_consensus_type(&self, consensus_type: &ConsensusType) -> u64 {
        // Simple hash for leader election
        match consensus_type {
            ConsensusType::RelaySelection { client_id, .. } => {
                client_id.as_bytes().iter().map(|&b| b as u64).sum()
            }
            ConsensusType::ParameterChange { parameter, .. } => {
                parameter.bytes().map(|b| b as u64).sum()
            }
            ConsensusType::ConflictResolution { conflict_id, .. } => {
                conflict_id.bytes().map(|b| b as u64).sum()
            }
        }
    }

    fn sign_proposal(&self, _proposal: &ConsensusProposal, _identity: &NodeIdentity) -> Result<Vec<u8>> {
        // TODO: Implement cryptographic signing when identity API is available
        // For now, return a placeholder signature
        Ok(vec![0u8; 64])
    }

    fn execute_consensus_round(&self, proposal_id: MessageId) -> Result<ConsensusResult> {
        let started_at = Instant::now();

        // Simulate consensus execution (in production, this would involve network communication)
        // For now, we'll create a deterministic result based on proposal

        std::thread::sleep(Duration::from_millis(100)); // Simulate network delay

        let result = {
            let mut rounds = self.active_rounds.write().unwrap();
            if let Some(round) = rounds.get_mut(&proposal_id) {
                round.phase = ConsensusPhase::Completed;

                // Calculate result
                self.calculate_result(round)
            } else {
                return Err(RoutingError::Other("Round not found".into()));
            }
        };

        // Update stats
        {
            let mut stats = self.stats.write().unwrap();
            if result.committed {
                stats.commits_successful += 1;
            } else if result.timed_out {
                stats.rounds_timed_out += 1;
            } else {
                stats.rounds_failed += 1;
            }

            // Update average consensus time
            let total_time = stats.avg_consensus_time_ms * (stats.rounds_initiated - 1) as f64
                + result.duration_ms as f64;
            stats.avg_consensus_time_ms = total_time / stats.rounds_initiated as f64;
        }

        Ok(result)
    }

    fn calculate_result(&self, round: &ConsensusRound) -> ConsensusResult {
        let accept_votes = round.votes.values().filter(|v| v.accept).count();
        let reject_votes = round.votes.values().filter(|v| !v.accept).count();
        let total_participants = round.proposal.participants.len();

        // Check if quorum reached
        let quorum_threshold = (total_participants as f32 * self.config.quorum_threshold).ceil() as usize;
        let committed = accept_votes >= quorum_threshold;

        let duration_ms = round.started_at.elapsed().as_millis() as u64;
        let timed_out = Instant::now() > round.commit_deadline;

        ConsensusResult {
            proposal_id: round.proposal.proposal_id,
            committed,
            value: if committed {
                Some(round.proposal.proposed_value.clone())
            } else {
                None
            },
            accept_votes,
            reject_votes,
            total_participants,
            duration_ms,
            timed_out,
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
    fn test_consensus_manager_creation() {
        let config = ConsensusConfig::default();
        let manager = ConsensusManager::new(config);
        assert_eq!(manager.get_stats().rounds_initiated, 0);
    }

    #[test]
    fn test_insufficient_participants() {
        let config = ConsensusConfig {
            min_participants: 7,
            ..Default::default()
        };
        let manager = ConsensusManager::new(config);

        let consensus_type = ConsensusType::RelaySelection {
            client_id: create_test_node_id(1),
            candidates: vec![create_test_node_id(2), create_test_node_id(3)],
        };

        let participants = vec![
            create_test_node_id(10),
            create_test_node_id(11),
            create_test_node_id(12),
        ];

        let result = manager.initiate_consensus(consensus_type, vec![1, 2, 3], participants);
        assert!(result.is_err());
    }

    #[test]
    fn test_consensus_initiation() {
        let config = ConsensusConfig::default();
        let manager = ConsensusManager::new(config);

        let participants: Vec<NodeId> = (0..7).map(create_test_node_id).collect();
        let consensus_type = ConsensusType::RelaySelection {
            client_id: create_test_node_id(100),
            candidates: vec![create_test_node_id(10), create_test_node_id(11)],
        };

        let result = manager.initiate_consensus(consensus_type, vec![10], participants);
        assert!(result.is_ok());

        let stats = manager.get_stats();
        assert_eq!(stats.rounds_initiated, 1);
    }

    #[test]
    fn test_leader_election_deterministic() {
        let config = ConsensusConfig::default();
        let manager = ConsensusManager::new(config);

        let participants: Vec<NodeId> = (0..7).map(create_test_node_id).collect();
        let consensus_type = ConsensusType::RelaySelection {
            client_id: create_test_node_id(100),
            candidates: vec![],
        };

        let leader1 = manager.elect_leader(&participants, &consensus_type).unwrap();
        let leader2 = manager.elect_leader(&participants, &consensus_type).unwrap();

        assert_eq!(leader1, leader2);
    }
}
