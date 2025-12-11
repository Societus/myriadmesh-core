//! Iterative DHT lookup algorithms
//!
//! Implements iterative_find_node and iterative_find_value operations
//! following the Kademlia DHT specification.

use crate::error::Result;
use crate::node_info::PublicNodeInfo;
use crate::operations::{FindNodeRequest, FindNodeResponse};
use crate::{ALPHA, K};
use myriadmesh_protocol::NodeId;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::{debug, info};

/// Transport abstraction for DHT RPC calls
///
/// This trait allows the iterative lookup to send queries without being
/// coupled to a specific network implementation.
#[async_trait::async_trait]
pub trait LookupTransport: Send + Sync {
    /// Send a FIND_NODE request and await response
    async fn find_node(
        &self,
        target_node: &NodeId,
        request: FindNodeRequest,
    ) -> Result<FindNodeResponse>;
}

/// Result of an iterative lookup operation
#[derive(Debug, Clone)]
pub enum LookupResult {
    /// Found k closest nodes
    Nodes(Vec<PublicNodeInfo>),

    /// Found the requested value (for FIND_VALUE)
    Value {
        key: [u8; 32],
        value: Vec<u8>,
        signature: Vec<u8>,
    },
}

/// State of a node in the lookup process
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NodeState {
    /// Node has not been queried yet
    Pending,

    /// Query sent, awaiting response
    Queried,

    /// Response received successfully
    Responded,

    /// Query failed or timed out
    Failed,
}

/// Tracks a candidate node during lookup
#[derive(Debug, Clone)]
struct LookupCandidate {
    node: PublicNodeInfo,
    state: NodeState,
    queried_at: Option<Instant>,
    distance: Vec<u8>,
}

/// Manages iterative lookup state
pub struct IterativeLookup {
    /// Target we're looking for (node ID or key hash)
    target: NodeId,

    /// Candidate nodes organized by distance to target
    candidates: HashMap<NodeId, LookupCandidate>,

    /// k value (number of closest nodes to find)
    k: usize,

    /// alpha value (parallel query concurrency)
    alpha: usize,

    /// Maximum number of rounds before giving up
    max_rounds: usize,

    /// Current round number
    current_round: usize,

    /// Whether we've found the exact target (for FIND_NODE)
    found_exact: bool,

    /// Timeout for individual queries
    query_timeout: Duration,
}

impl IterativeLookup {
    /// Create a new iterative lookup
    pub fn new(target: NodeId, initial_nodes: Vec<PublicNodeInfo>) -> Self {
        let mut candidates = HashMap::new();

        for node in initial_nodes {
            let distance = target.distance(&node.node_id).to_vec();
            candidates.insert(
                node.node_id,
                LookupCandidate {
                    node,
                    state: NodeState::Pending,
                    queried_at: None,
                    distance,
                },
            );
        }

        Self {
            target,
            candidates,
            k: K,
            alpha: ALPHA,
            max_rounds: 10,
            current_round: 0,
            found_exact: false,
            query_timeout: Duration::from_secs(5),
        }
    }

    /// Create with custom parameters (for testing)
    pub fn with_params(
        target: NodeId,
        initial_nodes: Vec<PublicNodeInfo>,
        k: usize,
        alpha: usize,
        max_rounds: usize,
    ) -> Self {
        let mut lookup = Self::new(target, initial_nodes);
        lookup.k = k;
        lookup.alpha = alpha;
        lookup.max_rounds = max_rounds;
        lookup
    }

    /// Get the next batch of nodes to query (up to alpha nodes)
    pub fn next_query_batch(&mut self) -> Vec<PublicNodeInfo> {
        // Get pending nodes sorted by distance
        let mut pending: Vec<_> = self
            .candidates
            .values()
            .filter(|c| c.state == NodeState::Pending)
            .collect();

        pending.sort_by(|a, b| a.distance.cmp(&b.distance));

        // Take up to alpha closest pending nodes
        let batch: Vec<PublicNodeInfo> = pending
            .iter()
            .take(self.alpha)
            .map(|c| c.node.clone())
            .collect();

        // Mark them as queried
        let now = Instant::now();
        for node in &batch {
            if let Some(candidate) = self.candidates.get_mut(&node.node_id) {
                candidate.state = NodeState::Queried;
                candidate.queried_at = Some(now);
            }
        }

        batch
    }

    /// Add newly discovered nodes from a response
    pub fn add_discovered_nodes(&mut self, nodes: Vec<PublicNodeInfo>) {
        for node in nodes {
            // Don't add if already known
            if self.candidates.contains_key(&node.node_id) {
                continue;
            }

            let distance = self.target.distance(&node.node_id).to_vec();

            // Check if this is the exact target
            if node.node_id == self.target {
                self.found_exact = true;
            }

            self.candidates.insert(
                node.node_id,
                LookupCandidate {
                    node,
                    state: NodeState::Pending,
                    queried_at: None,
                    distance,
                },
            );
        }
    }

    /// Mark a node as responded successfully
    pub fn mark_responded(&mut self, node_id: &NodeId) {
        if let Some(candidate) = self.candidates.get_mut(node_id) {
            candidate.state = NodeState::Responded;
        }
    }

    /// Mark a node as failed
    pub fn mark_failed(&mut self, node_id: &NodeId) {
        if let Some(candidate) = self.candidates.get_mut(node_id) {
            candidate.state = NodeState::Failed;
        }
    }

    /// Check for timed out queries and mark them as failed
    pub fn check_timeouts(&mut self) {
        let now = Instant::now();
        let timeout = self.query_timeout;

        let timed_out: Vec<NodeId> = self
            .candidates
            .iter()
            .filter(|(_, c)| {
                c.state == NodeState::Queried
                    && c.queried_at
                        .map(|t| now.duration_since(t) > timeout)
                        .unwrap_or(false)
            })
            .map(|(id, _)| *id)
            .collect();

        for node_id in timed_out {
            self.mark_failed(&node_id);
        }
    }

    /// Check if the lookup is complete
    pub fn is_complete(&self) -> bool {
        // Complete if we found the exact target (for FIND_NODE)
        if self.found_exact {
            return true;
        }

        // Complete if we've exceeded max rounds
        if self.current_round >= self.max_rounds {
            return true;
        }

        // Complete if no more nodes to query
        let has_pending = self
            .candidates
            .values()
            .any(|c| c.state == NodeState::Pending);
        let has_queried = self
            .candidates
            .values()
            .any(|c| c.state == NodeState::Queried);

        if !has_pending && !has_queried {
            return true;
        }

        // Complete if we have k responded nodes and no closer pending nodes
        let responded_count = self
            .candidates
            .values()
            .filter(|c| c.state == NodeState::Responded)
            .count();

        if responded_count >= self.k {
            // Get distance of k-th closest responded node
            let mut responded: Vec<_> = self
                .candidates
                .values()
                .filter(|c| c.state == NodeState::Responded)
                .collect();

            responded.sort_by(|a, b| a.distance.cmp(&b.distance));

            if let Some(kth_node) = responded.get(self.k - 1) {
                let kth_distance = &kth_node.distance;

                // Check if all pending nodes are farther than k-th responded node
                let all_pending_farther = self
                    .candidates
                    .values()
                    .filter(|c| c.state == NodeState::Pending)
                    .all(|c| &c.distance > kth_distance);

                if all_pending_farther {
                    return true;
                }
            }
        }

        false
    }

    /// Advance to the next round
    pub fn next_round(&mut self) {
        self.current_round += 1;
    }

    /// Get the k closest nodes that responded
    pub fn get_closest_nodes(&self) -> Vec<PublicNodeInfo> {
        let mut responded: Vec<_> = self
            .candidates
            .values()
            .filter(|c| c.state == NodeState::Responded)
            .collect();

        responded.sort_by(|a, b| a.distance.cmp(&b.distance));

        responded
            .iter()
            .take(self.k)
            .map(|c| c.node.clone())
            .collect()
    }

    /// Get statistics about the lookup
    pub fn stats(&self) -> LookupStats {
        let total = self.candidates.len();
        let pending = self
            .candidates
            .values()
            .filter(|c| c.state == NodeState::Pending)
            .count();
        let queried = self
            .candidates
            .values()
            .filter(|c| c.state == NodeState::Queried)
            .count();
        let responded = self
            .candidates
            .values()
            .filter(|c| c.state == NodeState::Responded)
            .count();
        let failed = self
            .candidates
            .values()
            .filter(|c| c.state == NodeState::Failed)
            .count();

        LookupStats {
            total_candidates: total,
            pending,
            queried,
            responded,
            failed,
            current_round: self.current_round,
            found_exact: self.found_exact,
        }
    }
}

/// Statistics about a lookup operation
#[derive(Debug, Clone, Copy)]
pub struct LookupStats {
    pub total_candidates: usize,
    pub pending: usize,
    pub queried: usize,
    pub responded: usize,
    pub failed: usize,
    pub current_round: usize,
    pub found_exact: bool,
}

/// Perform an iterative FIND_NODE lookup
///
/// This function implements the Kademlia iterative lookup algorithm to find
/// the k closest nodes to a target NodeId.
///
/// # Algorithm
/// 1. Start with initial nodes (typically k closest from local routing table)
/// 2. Query alpha (3) closest unqueried nodes in parallel
/// 3. Add returned nodes to candidate set
/// 4. Repeat until we have k responded nodes closer than any pending
/// 5. Return k closest responded nodes
///
/// # Parameters
/// * `transport` - Transport layer for sending FIND_NODE requests
/// * `requestor` - NodeId of the node performing the lookup (local node)
/// * `target` - Target NodeId we're searching for
/// * `initial_nodes` - Initial set of nodes to start the lookup (from routing table)
///
/// # Returns
/// Vector of up to k closest nodes to the target
///
/// # Example
/// ```ignore
/// let closest = iterative_find_node(
///     transport,
///     my_node_id,
///     target_node_id,
///     initial_nodes,
/// ).await?;
/// ```
pub async fn iterative_find_node(
    transport: Arc<dyn LookupTransport>,
    requestor: NodeId,
    target: NodeId,
    initial_nodes: Vec<PublicNodeInfo>,
) -> Result<Vec<PublicNodeInfo>> {
    info!(
        "Starting iterative_find_node for target {}",
        hex::encode(&target.as_bytes()[0..8])
    );

    if initial_nodes.is_empty() {
        debug!("No initial nodes provided for lookup");
        return Ok(Vec::new());
    }

    debug!("Starting lookup with {} initial nodes", initial_nodes.len());

    // Initialize lookup state machine
    let mut lookup = IterativeLookup::new(target, initial_nodes);

    // Iterative lookup loop
    while !lookup.is_complete() {
        lookup.check_timeouts();

        // Get next batch of nodes to query (up to alpha)
        let batch = lookup.next_query_batch();

        if batch.is_empty() {
            // No more nodes to query, wait a bit for pending responses
            tokio::time::sleep(Duration::from_millis(100)).await;
            continue;
        }

        debug!("Querying batch of {} nodes", batch.len());

        // Query all nodes in batch concurrently
        let query_futures: Vec<_> = batch
            .iter()
            .map(|node| {
                let transport = Arc::clone(&transport);
                let request = FindNodeRequest::new(target, requestor);
                async move { transport.find_node(&node.node_id, request).await }
            })
            .collect();

        // Wait for all queries to complete
        let results = futures::future::join_all(query_futures).await;

        // Process results
        for (node_info, result) in batch.iter().zip(results.iter()) {
            match result {
                Ok(response) => {
                    debug!(
                        "Node {:?} responded with {} nodes",
                        &node_info.node_id.as_bytes()[0..8],
                        response.nodes.len()
                    );
                    lookup.mark_responded(&node_info.node_id);
                    lookup.add_discovered_nodes(response.nodes.clone());
                }
                Err(e) => {
                    debug!(
                        "Node {:?} query failed: {}",
                        &node_info.node_id.as_bytes()[0..8],
                        e
                    );
                    lookup.mark_failed(&node_info.node_id);
                }
            }
        }

        lookup.next_round();

        let stats = lookup.stats();
        debug!(
            "Round {}: {} total, {} pending, {} queried, {} responded, {} failed",
            stats.current_round,
            stats.total_candidates,
            stats.pending,
            stats.queried,
            stats.responded,
            stats.failed
        );
    }

    // Get final results
    let closest_nodes = lookup.get_closest_nodes();
    info!(
        "iterative_find_node complete: found {} nodes",
        closest_nodes.len()
    );

    Ok(closest_nodes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use myriadmesh_protocol::types::NODE_ID_SIZE;

    fn create_test_node_id(value: u8) -> NodeId {
        let mut bytes = [0u8; NODE_ID_SIZE];
        bytes[0] = value;
        NodeId::from_bytes(bytes)
    }

    fn create_test_public_node(id: u8) -> PublicNodeInfo {
        PublicNodeInfo {
            node_id: create_test_node_id(id),
            capabilities: Default::default(),
            reputation: Default::default(),
            last_seen: 0,
            rtt_ms: 0.0,
        }
    }

    #[test]
    fn test_iterative_lookup_creation() {
        let target = create_test_node_id(100);
        let initial_nodes = vec![
            create_test_public_node(1),
            create_test_public_node(2),
            create_test_public_node(3),
        ];

        let lookup = IterativeLookup::new(target, initial_nodes);

        assert_eq!(lookup.candidates.len(), 3);
        assert_eq!(lookup.current_round, 0);
        assert!(!lookup.found_exact);
    }

    #[test]
    fn test_next_query_batch() {
        let target = create_test_node_id(100);
        let initial_nodes = vec![
            create_test_public_node(90), // Closest
            create_test_public_node(80),
            create_test_public_node(70),
            create_test_public_node(60),
            create_test_public_node(50),
        ];

        let mut lookup = IterativeLookup::with_params(target, initial_nodes, 20, 3, 10);

        // First batch should return 3 closest nodes (alpha=3)
        let batch = lookup.next_query_batch();
        assert_eq!(batch.len(), 3);

        // All should be marked as queried now
        let stats = lookup.stats();
        assert_eq!(stats.queried, 3);
        assert_eq!(stats.pending, 2);
    }

    #[test]
    fn test_add_discovered_nodes() {
        let target = create_test_node_id(100);
        let initial_nodes = vec![create_test_public_node(1)];

        let mut lookup = IterativeLookup::new(target, initial_nodes);
        assert_eq!(lookup.candidates.len(), 1);

        // Add new nodes
        let discovered = vec![create_test_public_node(2), create_test_public_node(3)];

        lookup.add_discovered_nodes(discovered);
        assert_eq!(lookup.candidates.len(), 3);
    }

    #[test]
    fn test_found_exact_target() {
        let target = create_test_node_id(100);
        let initial_nodes = vec![create_test_public_node(1)];

        let mut lookup = IterativeLookup::new(target, initial_nodes);
        assert!(!lookup.found_exact);

        // Discover the exact target
        let discovered = vec![create_test_public_node(100)];
        lookup.add_discovered_nodes(discovered);

        assert!(lookup.found_exact);
        assert!(lookup.is_complete());
    }

    #[test]
    fn test_mark_responded() {
        let target = create_test_node_id(100);
        let initial_nodes = vec![create_test_public_node(1)];

        let mut lookup = IterativeLookup::new(target, initial_nodes);
        let node_id = create_test_node_id(1);

        // Query the node
        lookup.next_query_batch();
        assert_eq!(lookup.stats().queried, 1);

        // Mark as responded
        lookup.mark_responded(&node_id);
        assert_eq!(lookup.stats().responded, 1);
        assert_eq!(lookup.stats().queried, 0);
    }

    #[test]
    fn test_get_closest_nodes() {
        let target = create_test_node_id(100);
        let initial_nodes = vec![
            create_test_public_node(90),
            create_test_public_node(80),
            create_test_public_node(110),
        ];

        let mut lookup = IterativeLookup::with_params(target, initial_nodes, 2, 3, 10);

        // Mark all as responded
        for i in [90, 80, 110] {
            lookup.mark_responded(&create_test_node_id(i));
        }

        // Get 2 closest (should be 90 and 110, as they're closest to 100)
        let closest = lookup.get_closest_nodes();
        assert_eq!(closest.len(), 2);
    }

    #[test]
    fn test_is_complete_max_rounds() {
        let target = create_test_node_id(100);
        let initial_nodes = vec![create_test_public_node(1)];

        let mut lookup = IterativeLookup::with_params(target, initial_nodes, 20, 3, 2);

        assert!(!lookup.is_complete());

        lookup.next_round();
        assert!(!lookup.is_complete());

        lookup.next_round();
        assert!(lookup.is_complete()); // Exceeded max_rounds
    }
}
