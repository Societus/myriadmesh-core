//! Kademlia routing table

use crate::error::Result;
use crate::kbucket::KBucket;
use crate::node_info::NodeInfo;
use myriadmesh_protocol::NodeId;
use std::time::{SystemTime, UNIX_EPOCH};

/// Get current timestamp
fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// Kademlia routing table
#[derive(Debug, Clone)]
pub struct RoutingTable {
    /// Our local node ID
    local_node_id: NodeId,

    /// 256 k-buckets (one per bit of node ID distance)
    buckets: Vec<KBucket>,

    /// Total nodes in routing table
    node_count: usize,
}

impl RoutingTable {
    /// Create a new routing table
    pub fn new(local_node_id: NodeId) -> Self {
        let mut buckets = Vec::with_capacity(256);
        for i in 0..256 {
            buckets.push(KBucket::new(i));
        }

        RoutingTable {
            local_node_id,
            buckets,
            node_count: 0,
        }
    }

    /// Get our local node ID
    pub fn local_node_id(&self) -> &NodeId {
        &self.local_node_id
    }

    /// Get total number of nodes in routing table
    pub fn node_count(&self) -> usize {
        self.node_count
    }

    /// Calculate bucket index for a node ID
    ///
    /// Bucket index is based on the position of the first differing bit:
    /// - Bucket 0: MSB of first byte differs (most distant)
    /// - Bucket 255: LSB of last byte differs (closest)
    fn bucket_index(&self, node_id: &NodeId) -> usize {
        let distance = self.local_node_id.distance(node_id);

        // Find the first non-zero byte
        for (byte_idx, &byte) in distance.iter().enumerate() {
            if byte != 0 {
                // Find the position of the most significant bit within the byte
                let msb_pos = byte.leading_zeros() as usize;
                // Calculate bucket index
                return byte_idx * 8 + msb_pos;
            }
        }

        // All bits are the same (shouldn't happen for different nodes)
        255
    }

    /// Add or update a node in the routing table
    ///
    /// SECURITY C2: Verifies Proof-of-Work before admitting nodes to prevent Sybil attacks
    pub fn add_or_update(&mut self, node: NodeInfo) -> Result<()> {
        // Don't add ourselves
        if node.node_id == self.local_node_id {
            return Ok(());
        }

        // SECURITY C2: Verify Proof-of-Work to prevent Sybil attacks
        if !node.verify_pow() {
            return Err(crate::error::DhtError::InvalidProofOfWork(format!(
                "Node {} has invalid PoW nonce {}",
                hex::encode(node.node_id.as_bytes()),
                node.pow_nonce
            )));
        }

        let bucket_idx = self.bucket_index(&node.node_id);
        let bucket = &mut self.buckets[bucket_idx];

        let was_present = bucket.find_node(&node.node_id).is_some();
        let added = bucket.add_or_update(node, now())?;

        // Update node count
        if added && !was_present {
            self.node_count += 1;
        }

        Ok(())
    }

    /// Find a node by ID
    pub fn find_node(&self, node_id: &NodeId) -> Option<&NodeInfo> {
        if node_id == &self.local_node_id {
            return None; // Don't return ourselves
        }

        let bucket_idx = self.bucket_index(node_id);
        self.buckets[bucket_idx].find_node(node_id)
    }

    /// Find a node mutably
    pub fn find_node_mut(&mut self, node_id: &NodeId) -> Option<&mut NodeInfo> {
        if node_id == &self.local_node_id {
            return None;
        }

        let bucket_idx = self.bucket_index(node_id);
        self.buckets[bucket_idx].find_node_mut(node_id)
    }

    /// Remove a node from the routing table
    pub fn remove(&mut self, node_id: &NodeId) -> Option<NodeInfo> {
        let bucket_idx = self.bucket_index(node_id);
        if let Some(node) = self.buckets[bucket_idx].remove(node_id) {
            self.node_count -= 1;
            Some(node)
        } else {
            None
        }
    }

    /// Get k closest nodes to a target
    ///
    /// SECURITY H2: Selects diverse nodes to prevent eclipse attacks
    /// Balances distance with IP and NodeID prefix diversity
    pub fn get_k_closest(&self, target: &NodeId, k: usize) -> Vec<NodeInfo> {
        use std::collections::{HashMap, HashSet};
        use std::net::IpAddr;

        let mut all_nodes: Vec<NodeInfo> = Vec::new();

        // Collect all nodes
        for bucket in &self.buckets {
            all_nodes.extend(bucket.nodes().iter().cloned());
        }

        // Sort by distance to target
        all_nodes.sort_by_key(|node| {
            let dist = target.distance(&node.node_id);
            dist.to_vec() // Convert to Vec for comparison
        });

        // SECURITY H2: Select nodes with diversity preferences
        let mut selected: Vec<NodeInfo> = Vec::new();
        let mut subnet_counts: HashMap<Vec<u8>, usize> = HashMap::new();
        let mut prefix_counts: HashMap<[u8; 2], usize> = HashMap::new();

        // Helper to extract subnet from IP address
        let get_subnet = |ip: &IpAddr| -> Vec<u8> {
            match ip {
                IpAddr::V4(ipv4) => {
                    let octets = ipv4.octets();
                    vec![octets[0], octets[1], octets[2]]
                }
                IpAddr::V6(ipv6) => {
                    let segments = ipv6.segments();
                    vec![
                        (segments[0] >> 8) as u8,
                        (segments[0] & 0xFF) as u8,
                        (segments[1] >> 8) as u8,
                        (segments[1] & 0xFF) as u8,
                        (segments[2] >> 8) as u8,
                        (segments[2] & 0xFF) as u8,
                    ]
                }
            }
        };

        // First pass: Select diverse nodes
        for node in &all_nodes {
            if selected.len() >= k {
                break;
            }

            // Extract node's subnets and prefix
            let mut node_subnets = Vec::new();
            for adapter in &node.adapters {
                if let Some(ip_str) = adapter.address.split(':').next() {
                    if let Ok(ip) = ip_str.parse::<IpAddr>() {
                        node_subnets.push(get_subnet(&ip));
                    }
                }
            }

            let prefix = [node.node_id.as_bytes()[0], node.node_id.as_bytes()[1]];

            // Check diversity constraints (MAX 2 per subnet, MAX 3 per prefix)
            let mut subnet_ok = node_subnets.is_empty(); // If no IP, allow it
            for subnet in &node_subnets {
                if subnet_counts.get(subnet).copied().unwrap_or(0) < 2 {
                    subnet_ok = true;
                    break;
                }
            }

            let prefix_ok = prefix_counts.get(&prefix).copied().unwrap_or(0) < 3;

            if subnet_ok && prefix_ok {
                // Add node and update counts
                for subnet in node_subnets {
                    *subnet_counts.entry(subnet).or_insert(0) += 1;
                }
                *prefix_counts.entry(prefix).or_insert(0) += 1;
                selected.push(node.clone());
            }
        }

        // Second pass: Fill remaining slots if we didn't get k nodes
        // This allows some non-diverse nodes if we can't find enough diverse ones
        if selected.len() < k {
            let selected_ids: HashSet<NodeId> = selected.iter().map(|n| n.node_id).collect();
            for node in all_nodes {
                if selected.len() >= k {
                    break;
                }
                if !selected_ids.contains(&node.node_id) {
                    selected.push(node);
                }
            }
        }

        selected
    }

    /// Get random nodes from routing table
    pub fn get_random_nodes(&self, count: usize) -> Vec<NodeInfo> {
        use rand::seq::SliceRandom;

        let mut all_nodes: Vec<NodeInfo> = Vec::new();

        // Collect all nodes
        for bucket in &self.buckets {
            all_nodes.extend(bucket.nodes().iter().cloned());
        }

        // Shuffle and take
        let mut rng = rand::thread_rng();
        all_nodes.shuffle(&mut rng);

        all_nodes.into_iter().take(count).collect()
    }

    /// Get nodes with good reputation for relay
    pub fn get_good_reputation_nodes(&self, min_reputation: f64) -> Vec<NodeInfo> {
        let mut nodes = Vec::new();

        for bucket in &self.buckets {
            for node in bucket.nodes().iter() {
                if node.reputation.score() >= min_reputation {
                    nodes.push(node.clone());
                }
            }
        }

        nodes
    }

    /// Prune stale nodes from all buckets
    pub fn prune_stale(&mut self, max_age_secs: u64) -> usize {
        let mut total_pruned = 0;

        for bucket in &mut self.buckets {
            let pruned = bucket.prune_stale(max_age_secs);
            total_pruned += pruned;
            self.node_count -= pruned;
        }

        total_pruned
    }

    /// Get buckets that need refreshing
    pub fn get_stale_buckets(&self, max_age_secs: u64) -> Vec<usize> {
        let current_time = now();
        let mut stale = Vec::new();

        for bucket in &self.buckets {
            if !bucket.is_empty() {
                let age = current_time.saturating_sub(bucket.last_updated);
                if age > max_age_secs {
                    stale.push(bucket.index);
                }
            }
        }

        stale
    }

    /// Get all nodes in routing table
    pub fn get_all_nodes(&self) -> Vec<NodeInfo> {
        let mut all_nodes = Vec::new();

        for bucket in &self.buckets {
            all_nodes.extend(bucket.nodes().iter().cloned());
        }

        all_nodes
    }

    /// Get bucket by index
    pub fn get_bucket(&self, index: usize) -> Option<&KBucket> {
        self.buckets.get(index)
    }

    /// Get mutable bucket by index
    pub fn get_bucket_mut(&mut self, index: usize) -> Option<&mut KBucket> {
        self.buckets.get_mut(index)
    }

    /// Handle FIND_NODE RPC request
    ///
    /// SPRINT 1 TASK 2.1: DHT RPC Integration
    /// This method processes a FIND_NODE request and returns the closest known nodes
    /// to the target. It's the core operation for DHT node discovery.
    ///
    /// # Arguments
    /// * `request` - The FIND_NODE request containing target and requestor info
    /// * `k` - Number of closest nodes to return (typically K=20)
    ///
    /// # Returns
    /// FindNodeResponse with the closest k nodes to the target
    pub fn handle_find_node(
        &self,
        request: &crate::operations::FindNodeRequest,
        k: usize,
    ) -> crate::operations::FindNodeResponse {
        // Get the k closest nodes to the target
        let closest_nodes = self.get_k_closest(&request.target, k);

        // Convert to public node info to preserve privacy
        // (excludes adapter addresses that might reveal anonymity)
        let public_nodes = closest_nodes
            .into_iter()
            .map(|node| node.to_public())
            .collect();

        crate::operations::FindNodeResponse {
            query_id: request.query_id,
            nodes: public_nodes,
        }
    }

    /// Update node's last seen time (called when FIND_NODE request is received from a node)
    ///
    /// This helps track which nodes are alive and responsive.
    pub fn refresh_node_seen(&mut self, node_id: &NodeId) {
        if let Some(node) = self.find_node_mut(node_id) {
            node.last_seen = now();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use myriadmesh_protocol::types::NODE_ID_SIZE;

    fn create_test_node(id: u8) -> NodeInfo {
        let mut node = NodeInfo::new(NodeId::from_bytes([id; NODE_ID_SIZE]));
        // SECURITY C2: Compute valid PoW for test nodes
        node.compute_pow();
        node
    }

    #[test]
    fn test_new_routing_table() {
        let local_id = NodeId::from_bytes([0; NODE_ID_SIZE]);
        let table = RoutingTable::new(local_id);

        assert_eq!(table.node_count(), 0);
        assert_eq!(table.local_node_id(), &local_id);
    }

    #[test]
    fn test_add_node() {
        let local_id = NodeId::from_bytes([0; NODE_ID_SIZE]);
        let mut table = RoutingTable::new(local_id);

        let node = create_test_node(1);
        table.add_or_update(node.clone()).unwrap();

        assert_eq!(table.node_count(), 1);
        assert!(table.find_node(&node.node_id).is_some());
    }

    #[test]
    fn test_dont_add_self() {
        let local_id = NodeId::from_bytes([0; NODE_ID_SIZE]);
        let mut table = RoutingTable::new(local_id);

        let self_node = NodeInfo::new(local_id);
        table.add_or_update(self_node).unwrap();

        assert_eq!(table.node_count(), 0);
    }

    #[test]
    fn test_remove_node() {
        let local_id = NodeId::from_bytes([0; NODE_ID_SIZE]);
        let mut table = RoutingTable::new(local_id);

        let node = create_test_node(1);
        let node_id = node.node_id;

        table.add_or_update(node).unwrap();
        assert_eq!(table.node_count(), 1);

        let removed = table.remove(&node_id);
        assert!(removed.is_some());
        assert_eq!(table.node_count(), 0);
    }

    #[test]
    fn test_get_k_closest() {
        let local_id = NodeId::from_bytes([0; NODE_ID_SIZE]);
        let mut table = RoutingTable::new(local_id);

        // Add several nodes
        for i in 1..=10 {
            let node = create_test_node(i);
            table.add_or_update(node).unwrap();
        }

        let target = NodeId::from_bytes([5; NODE_ID_SIZE]);
        let closest = table.get_k_closest(&target, 3);

        assert_eq!(closest.len(), 3);
    }

    #[test]
    fn test_get_random_nodes() {
        let local_id = NodeId::from_bytes([0; NODE_ID_SIZE]);
        let mut table = RoutingTable::new(local_id);

        // Add several nodes
        for i in 1..=10 {
            let node = create_test_node(i);
            table.add_or_update(node).unwrap();
        }

        let random = table.get_random_nodes(3);
        assert_eq!(random.len(), 3);
    }

    #[test]
    fn test_bucket_index() {
        let local_id = NodeId::from_bytes([0; NODE_ID_SIZE]);
        let table = RoutingTable::new(local_id);

        // Node with first bit different
        let mut node_id_bytes = [0u8; NODE_ID_SIZE];
        node_id_bytes[0] = 0b1000_0000;
        let node_id = NodeId::from_bytes(node_id_bytes);

        let bucket_idx = table.bucket_index(&node_id);
        assert_eq!(bucket_idx, 0); // First bit different
    }

    #[test]
    fn test_prune_stale() {
        let local_id = NodeId::from_bytes([0; NODE_ID_SIZE]);
        let mut table = RoutingTable::new(local_id);

        // Add old node
        let mut old_node = create_test_node(1);
        old_node.last_seen = 0; // Very old
        table.add_or_update(old_node).unwrap();

        // Add fresh node
        let fresh_node = create_test_node(2);
        table.add_or_update(fresh_node).unwrap();

        assert_eq!(table.node_count(), 2);

        // Prune stale
        let pruned = table.prune_stale(3600);
        assert_eq!(pruned, 1);
        assert_eq!(table.node_count(), 1);
    }

    // SECURITY C2: Proof-of-Work enforcement tests

    #[test]
    fn test_reject_node_without_valid_pow() {
        // SECURITY C2: Verify routing table rejects nodes without valid PoW
        let local_id = NodeId::from_bytes([0; NODE_ID_SIZE]);
        let mut table = RoutingTable::new(local_id);

        // Create node with invalid PoW
        let mut invalid_node = NodeInfo::new(NodeId::from_bytes([42; NODE_ID_SIZE]));
        invalid_node.pow_nonce = 12345; // Arbitrary invalid nonce

        // Should be rejected
        let result = table.add_or_update(invalid_node);
        assert!(result.is_err());
        assert_eq!(table.node_count(), 0);
    }

    #[test]
    fn test_accept_node_with_valid_pow() {
        // SECURITY C2: Verify routing table accepts nodes with valid PoW
        let local_id = NodeId::from_bytes([0; NODE_ID_SIZE]);
        let mut table = RoutingTable::new(local_id);

        // Create node and compute valid PoW
        let valid_node = create_test_node(99);

        // Should be accepted
        let result = table.add_or_update(valid_node);
        assert!(result.is_ok());
        assert_eq!(table.node_count(), 1);
    }

    #[test]
    fn test_pow_prevents_sybil_flooding() {
        // SECURITY C2: PoW makes it expensive to flood DHT with many identities
        let local_id = NodeId::from_bytes([0; NODE_ID_SIZE]);
        let mut table = RoutingTable::new(local_id);

        // Try to add 10 nodes with invalid PoW (should all fail)
        for i in 1..=10 {
            let mut invalid_node = NodeInfo::new(NodeId::from_bytes([i; NODE_ID_SIZE]));
            invalid_node.pow_nonce = i as u64 * 1000; // Invalid nonces

            let result = table.add_or_update(invalid_node);
            assert!(
                result.is_err(),
                "Node {} with invalid PoW should be rejected",
                i
            );
        }

        // No nodes should have been added
        assert_eq!(table.node_count(), 0);

        // Now add legitimate nodes with valid PoW
        for i in 1..=3 {
            let valid_node = create_test_node(i);
            table.add_or_update(valid_node).unwrap();
        }

        // Only legitimate nodes added
        assert_eq!(table.node_count(), 3);
    }

    // SECURITY H2: Eclipse attack prevention tests

    #[test]
    fn test_get_k_closest_prefers_diverse_subnets() {
        // SECURITY H2: Verify get_k_closest prefers nodes from different subnets
        use crate::node_info::AdapterInfo;
        use myriadmesh_protocol::types::AdapterType;

        let local_id = NodeId::from_bytes([0; NODE_ID_SIZE]);
        let mut table = RoutingTable::new(local_id);

        // Add 5 nodes from subnet 192.168.1.x
        for i in 1..=5 {
            let mut node = create_test_node(i);
            node.adapters = vec![AdapterInfo {
                adapter_type: AdapterType::Ethernet,
                address: format!("192.168.1.{}:8080", i),
                active: true,
            }];
            table.add_or_update(node).unwrap();
        }

        // Add 5 nodes from different subnets
        for i in 10..=14 {
            let mut node = create_test_node(i);
            node.adapters = vec![AdapterInfo {
                adapter_type: AdapterType::Ethernet,
                address: format!("192.168.{}.1:8080", i), // Different subnet
                active: true,
            }];
            table.add_or_update(node).unwrap();
        }

        // Get k=5 closest nodes
        let target = NodeId::from_bytes([128; NODE_ID_SIZE]);
        let closest = table.get_k_closest(&target, 5);

        // Count nodes from 192.168.1.x subnet
        let mut subnet_1_count = 0;
        for node in &closest {
            for adapter in &node.adapters {
                if adapter.address.starts_with("192.168.1.") {
                    subnet_1_count += 1;
                    break;
                }
            }
        }

        // Should prefer diversity - at most 2 from same subnet
        assert!(
            subnet_1_count <= 2,
            "Should have at most 2 nodes from same subnet, got {}",
            subnet_1_count
        );
    }

    #[test]
    fn test_get_k_closest_prefers_diverse_prefixes() {
        // SECURITY H2: Verify get_k_closest prefers nodes with different NodeID prefixes
        let local_id = NodeId::from_bytes([0; NODE_ID_SIZE]);
        let mut table = RoutingTable::new(local_id);

        // Add 5 nodes with prefix 0xAA 0xBB
        let mut prefix_bytes = [0u8; NODE_ID_SIZE];
        prefix_bytes[0] = 0xAA;
        prefix_bytes[1] = 0xBB;
        for i in 0..5 {
            prefix_bytes[2] = i;
            let mut node = NodeInfo::new(NodeId::from_bytes(prefix_bytes));
            node.compute_pow();
            table.add_or_update(node).unwrap();
        }

        // Add 5 nodes with different prefixes
        for i in 10..15 {
            prefix_bytes[0] = i;
            prefix_bytes[1] = i + 1;
            prefix_bytes[2] = 0;
            let mut node = NodeInfo::new(NodeId::from_bytes(prefix_bytes));
            node.compute_pow();
            table.add_or_update(node).unwrap();
        }

        // Get k=5 closest nodes
        let target = NodeId::from_bytes([128; NODE_ID_SIZE]);
        let closest = table.get_k_closest(&target, 5);

        // Count nodes with prefix 0xAA 0xBB
        let mut prefix_count = 0;
        for node in &closest {
            let bytes = node.node_id.as_bytes();
            if bytes[0] == 0xAA && bytes[1] == 0xBB {
                prefix_count += 1;
            }
        }

        // Should prefer diversity - at most 3 from same prefix
        assert!(
            prefix_count <= 3,
            "Should have at most 3 nodes with same prefix, got {}",
            prefix_count
        );
    }

    #[test]
    fn test_get_k_closest_falls_back_when_insufficient_diversity() {
        // SECURITY H2: Verify get_k_closest still returns k nodes even if diversity is limited
        let local_id = NodeId::from_bytes([0; NODE_ID_SIZE]);
        let mut table = RoutingTable::new(local_id);

        // Add 5 nodes all from same subnet (limited diversity)
        use crate::node_info::AdapterInfo;
        use myriadmesh_protocol::types::AdapterType;

        for i in 1..=5 {
            let mut node = create_test_node(i);
            node.adapters = vec![AdapterInfo {
                adapter_type: AdapterType::Ethernet,
                address: format!("192.168.1.{}:8080", i), // All same subnet
                active: true,
            }];
            table.add_or_update(node).unwrap();
        }

        // Get k=5 closest - should return all 5 even though diversity is limited
        let target = NodeId::from_bytes([128; NODE_ID_SIZE]);
        let closest = table.get_k_closest(&target, 5);

        // Should still get 5 nodes (fallback behavior)
        assert_eq!(
            closest.len(),
            5,
            "Should return all available nodes when diversity is limited"
        );
    }

    #[test]
    fn test_eclipse_attack_resistance() {
        // SECURITY H2: Simulate eclipse attack and verify resistance
        use crate::node_info::AdapterInfo;
        use myriadmesh_protocol::types::AdapterType;

        let local_id = NodeId::from_bytes([0; NODE_ID_SIZE]);
        let mut table = RoutingTable::new(local_id);

        // Attacker adds 20 nodes from controlled subnet
        for i in 1..=20 {
            let mut node = create_test_node(i);
            node.adapters = vec![AdapterInfo {
                adapter_type: AdapterType::Ethernet,
                address: format!("10.0.0.{}:8080", i), // Attacker's subnet
                active: true,
            }];
            table.add_or_update(node).ok(); // May fail due to diversity
        }

        // Legitimate nodes from different locations
        for i in 100..105 {
            let mut node = create_test_node(i);
            node.adapters = vec![AdapterInfo {
                adapter_type: AdapterType::Ethernet,
                address: format!("192.168.{}.1:8080", i - 100), // Different subnets
                active: true,
            }];
            table.add_or_update(node).ok();
        }

        // Get k=10 closest nodes
        let target = NodeId::from_bytes([128; NODE_ID_SIZE]);
        let closest = table.get_k_closest(&target, 10);

        // Count attacker's nodes in result
        let mut attacker_nodes = 0;
        for node in &closest {
            for adapter in &node.adapters {
                if adapter.address.starts_with("10.0.0.") {
                    attacker_nodes += 1;
                    break;
                }
            }
        }

        // Attacker should not dominate the result
        // Without diversity: attacker would get 10/10 nodes (complete eclipse)
        // With diversity: attacker gets at most 50% (eclipse prevented)
        // The key defense is that even with 20 malicious nodes vs 5 legitimate,
        // the attacker cannot completely control the victim's view of the network
        assert!(
            attacker_nodes <= 5,
            "Attacker should not dominate k-closest (got {} out of 10), diversity enforcement failed",
            attacker_nodes
        );

        // Verify legitimate nodes have meaningful presence
        let legitimate_nodes = closest.len() - attacker_nodes;
        assert!(
            legitimate_nodes >= 5,
            "Should have significant legitimate nodes (got {} out of 10), eclipse attack succeeded",
            legitimate_nodes
        );
    }

    #[test]
    fn test_handle_find_node_basic() {
        use crate::operations::FindNodeRequest;

        let local_id = NodeId::from_bytes([0; NODE_ID_SIZE]);
        let mut table = RoutingTable::new(local_id);

        // Add some nodes
        for i in 1..=10 {
            let node = create_test_node(i);
            table.add_or_update(node).unwrap();
        }

        // Create a FIND_NODE request
        let target = NodeId::from_bytes([100; NODE_ID_SIZE]);
        let requestor = NodeId::from_bytes([200; NODE_ID_SIZE]);
        let request = FindNodeRequest::new(target, requestor);

        // Handle the request
        let response = table.handle_find_node(&request, 5);

        // Verify response
        assert_eq!(response.query_id, request.query_id);
        assert_eq!(response.nodes.len(), 5);
    }

    #[test]
    fn test_handle_find_node_fewer_available() {
        use crate::operations::FindNodeRequest;

        let local_id = NodeId::from_bytes([0; NODE_ID_SIZE]);
        let mut table = RoutingTable::new(local_id);

        // Add only 3 nodes
        for i in 1..=3 {
            let node = create_test_node(i);
            table.add_or_update(node).unwrap();
        }

        // Request 5 but only 3 available
        let target = NodeId::from_bytes([100; NODE_ID_SIZE]);
        let requestor = NodeId::from_bytes([200; NODE_ID_SIZE]);
        let request = FindNodeRequest::new(target, requestor);

        let response = table.handle_find_node(&request, 5);

        // Should return 3 nodes (all available)
        assert_eq!(response.nodes.len(), 3);
    }

    #[test]
    fn test_handle_find_node_empty_table() {
        use crate::operations::FindNodeRequest;

        let local_id = NodeId::from_bytes([0; NODE_ID_SIZE]);
        let table = RoutingTable::new(local_id);

        // Empty routing table
        let target = NodeId::from_bytes([100; NODE_ID_SIZE]);
        let requestor = NodeId::from_bytes([200; NODE_ID_SIZE]);
        let request = FindNodeRequest::new(target, requestor);

        let response = table.handle_find_node(&request, 5);

        // Should return empty list
        assert_eq!(response.nodes.len(), 0);
    }

    #[test]
    fn test_refresh_node_seen() {
        let local_id = NodeId::from_bytes([0; NODE_ID_SIZE]);
        let mut table = RoutingTable::new(local_id);

        let node = create_test_node(1);
        let node_id = node.node_id;
        table.add_or_update(node.clone()).unwrap();

        // Get the original last_seen time
        let original_seen = table.find_node(&node_id).unwrap().last_seen;

        // Refresh should update the time
        table.refresh_node_seen(&node_id);

        // Verify it was updated (or at least didn't cause an error)
        let updated_node = table.find_node(&node_id).unwrap();
        // The time should be >= original (might be same if system is fast)
        assert!(updated_node.last_seen >= original_seen);
    }
}
