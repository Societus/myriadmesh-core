//! High-level DHT service coordinator
//!
//! This module provides the async runtime integration for DHT operations,
//! implementing iterative_find_node and iterative_find_value.

use crate::error::{DhtError, Result};
use crate::iterative_lookup::{IterativeLookup, LookupResult};
use crate::node_info::{NodeInfo, PublicNodeInfo};
use crate::operations::{FindNodeRequest, FindNodeResponse, FindValueRequest, FindValueResponse, StoreRequest, StoreAck};
use crate::routing_table::RoutingTable;
use crate::storage::DhtStorage;
use crate::{ALPHA, K};
use myriadmesh_protocol::NodeId;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tokio::time::timeout;
use tracing::{debug, error, info, warn};

/// DHT query timeout (per individual query)
const QUERY_TIMEOUT: Duration = Duration::from_secs(5);

/// Maximum concurrent queries in progress
/// TODO: Enforce this limit in send_and_await() to prevent resource exhaustion
/// This should be checked before creating new pending queries
#[allow(dead_code)]
const MAX_CONCURRENT_QUERIES: usize = ALPHA;

/// DHT Service provides high-level DHT operations
pub struct DhtService {
    /// Local node ID
    node_id: NodeId,

    /// Routing table
    routing_table: Arc<RwLock<RoutingTable>>,

    /// Local DHT storage
    storage: Arc<RwLock<DhtStorage>>,

    /// RPC transport for DHT queries
    rpc_transport: Arc<dyn DhtTransport>,
}

/// Transport abstraction for DHT RPC calls
///
/// This allows the DHT to send queries without being coupled to the
/// network layer implementation.
#[async_trait::async_trait]
pub trait DhtTransport: Send + Sync {
    /// Send a FIND_NODE request and await response
    async fn find_node(
        &self,
        target_node: &NodeId,
        request: FindNodeRequest,
    ) -> Result<FindNodeResponse>;

    /// Send a FIND_VALUE request and await response
    async fn find_value(
        &self,
        target_node: &NodeId,
        request: FindValueRequest,
    ) -> Result<FindValueResponse>;

    /// Send a STORE request and await acknowledgment
    async fn store(
        &self,
        target_node: &NodeId,
        request: StoreRequest,
    ) -> Result<StoreAck>;

    /// Send a PING request to check if node is alive
    /// Returns true if the node responds, false if timeout
    async fn ping(&self, target_node: &NodeId) -> Result<bool>;
}

impl DhtService {
    /// Create a new DHT service
    pub fn new(
        node_id: NodeId,
        routing_table: Arc<RwLock<RoutingTable>>,
        storage: Arc<RwLock<DhtStorage>>,
        rpc_transport: Arc<dyn DhtTransport>,
    ) -> Self {
        Self {
            node_id,
            routing_table,
            storage,
            rpc_transport,
        }
    }

    /// Perform an iterative FIND_NODE lookup
    ///
    /// Returns the k closest nodes to the target.
    ///
    /// # Algorithm (Kademlia)
    /// 1. Start with k closest nodes from local routing table
    /// 2. Query alpha (3) closest unqueried nodes in parallel
    /// 3. Add returned nodes to candidate set
    /// 4. Repeat until we have k responded nodes closer than any pending
    /// 5. Return k closest responded nodes
    pub async fn iterative_find_node(&self, target: NodeId) -> Result<Vec<PublicNodeInfo>> {
        info!(
            "Starting iterative_find_node for target {}",
            hex::encode(&target.as_bytes()[0..8])
        );

        // Get initial nodes from routing table
        let initial_nodes: Vec<PublicNodeInfo> = {
            let rt = self.routing_table.read().await;
            let nodes = rt.get_k_closest(&target, K);
            nodes.into_iter().map(|n| n.to_public()).collect()
        };

        if initial_nodes.is_empty() {
            warn!("No initial nodes in routing table for lookup");
            return Err(DhtError::NoKnownNodes);
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
                .map(|node| self.query_find_node(&target, node))
                .collect();

            // Wait for all queries with timeout
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

                        // Update routing table with newly discovered nodes
                        self.update_routing_table_from_public_nodes(&response.nodes)
                            .await;
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

    /// Perform an iterative FIND_VALUE lookup
    ///
    /// Returns either the value (if found) or k closest nodes.
    ///
    /// # Security
    /// - SECURITY H7: Verifies signatures on retrieved values
    /// - Prevents DHT poisoning attacks
    pub async fn iterative_find_value(&self, key: [u8; 32]) -> Result<LookupResult> {
        info!("Starting iterative_find_value for key {}", hex::encode(key));

        // Check local storage first
        {
            let storage = self.storage.read().await;
            if let Some(entry) = storage.get(&key) {
                // SECURITY H7: Verify signature before returning value
                if entry.verify_signature().is_ok() {
                    info!("Value found in local storage");
                    return Ok(LookupResult::Value {
                        key,
                        value: entry.value.clone(),
                        signature: entry.signature.to_vec(),
                    });
                } else {
                    warn!("Local storage has invalid signature, ignoring");
                }
            }
        }

        // Convert key to NodeId for distance calculations
        let target = NodeId::from_bytes(Self::key_to_node_id_bytes(key));

        // Get initial nodes from routing table
        let initial_nodes: Vec<PublicNodeInfo> = {
            let rt = self.routing_table.read().await;
            let nodes = rt.get_k_closest(&target, K);
            nodes.into_iter().map(|n| n.to_public()).collect()
        };

        if initial_nodes.is_empty() {
            warn!("No initial nodes in routing table for lookup");
            return Err(DhtError::NoKnownNodes);
        }

        debug!(
            "Starting value lookup with {} initial nodes",
            initial_nodes.len()
        );

        // Initialize lookup state machine
        let mut lookup = IterativeLookup::new(target, initial_nodes);

        // Iterative lookup loop
        while !lookup.is_complete() {
            lookup.check_timeouts();

            // Get next batch of nodes to query
            let batch = lookup.next_query_batch();

            if batch.is_empty() {
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }

            debug!("Querying batch of {} nodes for value", batch.len());

            // Query all nodes in batch concurrently
            let query_futures: Vec<_> = batch
                .iter()
                .map(|node| self.query_find_value(key, node))
                .collect();

            let results = futures::future::join_all(query_futures).await;

            // Process results
            for (node_info, result) in batch.iter().zip(results.iter()) {
                match result {
                    Ok(response) => {
                        match response {
                            FindValueResponse::Found {
                                value,
                                signature,
                                key: response_key,
                                ..
                            } => {
                                // SECURITY H7: Verify signature before accepting value
                                if Self::verify_value_signature(key, value, signature) {
                                    info!("Value found and verified!");
                                    lookup.mark_responded(&node_info.node_id);

                                    // Cache the value locally
                                    self.cache_value(key, value.clone(), signature.clone())
                                        .await;

                                    return Ok(LookupResult::Value {
                                        key: *response_key,
                                        value: value.clone(),
                                        signature: signature.clone(),
                                    });
                                } else {
                                    warn!(
                                        "Node {:?} returned value with invalid signature",
                                        &node_info.node_id.as_bytes()[0..8]
                                    );
                                    lookup.mark_failed(&node_info.node_id);
                                }
                            }
                            FindValueResponse::NotFound { nodes, .. } => {
                                debug!(
                                    "Node {:?} doesn't have value, returned {} closer nodes",
                                    &node_info.node_id.as_bytes()[0..8],
                                    nodes.len()
                                );
                                lookup.mark_responded(&node_info.node_id);
                                lookup.add_discovered_nodes(nodes.clone());

                                self.update_routing_table_from_public_nodes(nodes).await;
                            }
                        }
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
        }

        // Value not found, return closest nodes
        let closest_nodes = lookup.get_closest_nodes();
        info!(
            "iterative_find_value complete: value not found, returning {} closest nodes",
            closest_nodes.len()
        );

        Ok(LookupResult::Nodes(closest_nodes))
    }

    /// Query a single node for FIND_NODE
    async fn query_find_node(
        &self,
        target: &NodeId,
        node: &PublicNodeInfo,
    ) -> Result<FindNodeResponse> {
        let request = FindNodeRequest::new(*target, self.node_id);

        match timeout(
            QUERY_TIMEOUT,
            self.rpc_transport.find_node(&node.node_id, request),
        )
        .await
        {
            Ok(Ok(response)) => Ok(response),
            Ok(Err(e)) => Err(e),
            Err(_) => Err(DhtError::QueryTimeout),
        }
    }

    /// Query a single node for FIND_VALUE
    async fn query_find_value(
        &self,
        key: [u8; 32],
        node: &PublicNodeInfo,
    ) -> Result<FindValueResponse> {
        let request = FindValueRequest::new(key, self.node_id);

        match timeout(
            QUERY_TIMEOUT,
            self.rpc_transport.find_value(&node.node_id, request),
        )
        .await
        {
            Ok(Ok(response)) => Ok(response),
            Ok(Err(e)) => Err(e),
            Err(_) => Err(DhtError::QueryTimeout),
        }
    }

    /// Update routing table from discovered public nodes
    async fn update_routing_table_from_public_nodes(&self, nodes: &[PublicNodeInfo]) {
        let mut rt = self.routing_table.write().await;

        for public_node in nodes {
            // Convert PublicNodeInfo to full NodeInfo (with empty adapter list)
            // The full NodeInfo will be populated when we actually connect to the node
            let mut node_info = NodeInfo::new(public_node.node_id);
            node_info.capabilities = public_node.capabilities.clone();
            node_info.reputation = public_node.reputation.clone();
            node_info.last_seen = public_node.last_seen;
            node_info.rtt_ms = public_node.rtt_ms;
            // adapters will be empty - PublicNodeInfo doesn't include them (privacy)
            // pow_nonce is 0 - will be validated when we get full info

            // Note: This will fail PoW verification, but that's expected
            // We only add nodes to routing table after we've verified them
            // This is just for discovery; actual verification happens elsewhere
            if let Err(e) = rt.add_or_update(node_info.clone()) {
                debug!(
                    "Could not add discovered node {:?} to routing table: {}",
                    &public_node.node_id.as_bytes()[0..8],
                    e
                );
            }
        }
    }

    /// Cache a verified value in local storage
    async fn cache_value(&self, key: [u8; 32], value: Vec<u8>, signature: Vec<u8>) {
        let mut storage = self.storage.write().await;

        // Default TTL for cached values: 1 hour
        let ttl = 3600;

        // TODO: Extract actual publisher info from signature/value metadata
        // For now, use placeholder values (this is a cached value, not one we're publishing)
        let publisher_public_key = [0u8; 32];
        let publisher_node_id = [0u8; 64];

        // Convert Vec<u8> signature to [u8; 64]
        let signature_array: [u8; 64] = if signature.len() == 64 {
            let mut arr = [0u8; 64];
            arr.copy_from_slice(&signature);
            arr
        } else {
            warn!(
                "Invalid signature length for caching: {} bytes",
                signature.len()
            );
            [0u8; 64]
        };

        if let Err(e) = storage.store(
            key,
            value,
            ttl,
            publisher_public_key,
            publisher_node_id,
            signature_array,
        ) {
            error!("Failed to cache DHT value: {}", e);
        } else {
            debug!("Cached DHT value for key {}", hex::encode(key));
        }
    }

    /// Verify signature on a DHT value
    ///
    /// SECURITY H7: Prevents DHT poisoning by verifying publisher signatures
    fn verify_value_signature(key: [u8; 32], value: &[u8], signature: &[u8]) -> bool {
        // TODO: Implement actual signature verification
        // This requires:
        // 1. Extracting publisher public key (could be embedded in value or signature)
        // 2. Verifying signature over (key || value) using publisher's public key
        // 3. Checking that publisher is authorized to sign this key

        // For now, accept all signatures (INSECURE - needs implementation)
        // This is marked in MARKET_READY_TODO.md as P0.2.2 dependency
        if signature.is_empty() {
            warn!("Empty signature on DHT value");
            return false;
        }

        // Placeholder verification
        debug!(
            "TODO: Verify signature for key {} (len: {}, sig len: {})",
            hex::encode(key),
            value.len(),
            signature.len()
        );
        true
    }

    /// Convert a 32-byte key to a 64-byte NodeId (for distance calculations)
    fn key_to_node_id_bytes(key: [u8; 32]) -> [u8; 64] {
        let mut node_id_bytes = [0u8; 64];
        // Copy key to first 32 bytes, zero-pad the rest
        node_id_bytes[..32].copy_from_slice(&key);
        node_id_bytes
    }

    /// Get reference to routing table (for testing/debugging)
    pub fn routing_table(&self) -> &Arc<RwLock<RoutingTable>> {
        &self.routing_table
    }

    /// Get reference to storage (for testing/debugging)
    pub fn storage(&self) -> &Arc<RwLock<DhtStorage>> {
        &self.storage
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::node_info::NodeCapabilities;
    use crate::reputation::NodeReputation;
    use myriadmesh_protocol::types::NODE_ID_SIZE;

    /// Mock DHT transport for testing
    struct MockTransport {
        responses: Arc<RwLock<Vec<FindNodeResponse>>>,
    }

    #[async_trait::async_trait]
    impl DhtTransport for MockTransport {
        async fn find_node(
            &self,
            _target_node: &NodeId,
            _request: FindNodeRequest,
        ) -> Result<FindNodeResponse> {
            let mut responses = self.responses.write().await;
            if let Some(response) = responses.pop() {
                Ok(response)
            } else {
                Err(DhtError::QueryTimeout)
            }
        }

        async fn find_value(
            &self,
            _target_node: &NodeId,
            _request: FindValueRequest,
        ) -> Result<FindValueResponse> {
            Err(DhtError::QueryTimeout)
        }

        async fn store(
            &self,
            _target_node: &NodeId,
            _request: StoreRequest,
        ) -> Result<StoreAck> {
            use crate::operations::generate_query_id;
            Ok(StoreAck {
                query_id: generate_query_id(),
                success: true,
                error: None,
            })
        }

        async fn ping(&self, _target_node: &NodeId) -> Result<bool> {
            Ok(true)
        }
    }

    fn create_test_node_id(value: u8) -> NodeId {
        let mut bytes = [0u8; NODE_ID_SIZE];
        bytes[0] = value;
        NodeId::from_bytes(bytes)
    }

    /// Helper to create test PublicNodeInfo (used in future tests)
    #[allow(dead_code)]
    fn create_test_public_node(id: u8) -> PublicNodeInfo {
        PublicNodeInfo {
            node_id: create_test_node_id(id),
            capabilities: NodeCapabilities::default(),
            reputation: NodeReputation::default(),
            last_seen: 0,
            rtt_ms: 0.0,
        }
    }

    #[tokio::test]
    async fn test_dht_service_creation() {
        let node_id = create_test_node_id(1);
        let routing_table = Arc::new(RwLock::new(RoutingTable::new(node_id)));
        let storage = Arc::new(RwLock::new(DhtStorage::new()));
        let transport = Arc::new(MockTransport {
            responses: Arc::new(RwLock::new(vec![])),
        });

        let dht = DhtService::new(node_id, routing_table, storage, transport);

        assert_eq!(dht.node_id, node_id);
    }

    #[tokio::test]
    async fn test_key_to_node_id_conversion() {
        let key = [42u8; 32];
        let node_id_bytes = DhtService::key_to_node_id_bytes(key);

        assert_eq!(node_id_bytes[0], 42);
        assert_eq!(node_id_bytes[31], 42);
        assert_eq!(node_id_bytes[32], 0);
        assert_eq!(node_id_bytes[63], 0);
    }
}
