//! K-bucket implementation for Kademlia DHT

use crate::error::Result;
use crate::node_info::NodeInfo;
use crate::K;
use myriadmesh_protocol::NodeId;
use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;

/// SECURITY H2: Maximum nodes from same /24 subnet (Eclipse attack prevention)
/// Limits an attacker's ability to fill buckets with nodes from controlled IP ranges
const MAX_NODES_PER_SUBNET: usize = 2;

/// SECURITY H2: Maximum nodes with same NodeID prefix (first 2 bytes)
/// Prevents attackers from flooding buckets with coordinated NodeIDs
const MAX_NODES_PER_PREFIX: usize = 3;

/// Extract /24 subnet from IP address
/// Returns a tuple of (first 3 octets) for IPv4 or (first 6 bytes) for IPv6
fn get_subnet(ip: &IpAddr) -> Vec<u8> {
    match ip {
        IpAddr::V4(ipv4) => {
            let octets = ipv4.octets();
            vec![octets[0], octets[1], octets[2]]
        }
        IpAddr::V6(ipv6) => {
            let segments = ipv6.segments();
            // Use first 48 bits (3 segments) for IPv6 /48 subnet
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
}

/// Extract IP addresses from NodeInfo adapters
fn extract_ip_addresses(node: &NodeInfo) -> Vec<IpAddr> {
    let mut ips = Vec::new();
    for adapter in &node.adapters {
        // Try to parse address as IP (may include port like "192.168.1.1:8080")
        if let Some(ip_str) = adapter.address.split(':').next() {
            if let Ok(ip) = ip_str.parse::<IpAddr>() {
                ips.push(ip);
            }
        }
    }
    ips
}

/// Get NodeID prefix (first 2 bytes) for diversity tracking
fn get_node_id_prefix(node_id: &NodeId) -> [u8; 2] {
    let bytes = node_id.as_bytes();
    [bytes[0], bytes[1]]
}

/// A k-bucket for storing nodes at a specific distance
#[derive(Debug, Clone)]
pub struct KBucket {
    /// Bucket index (0-255)
    pub index: usize,

    /// Nodes in this bucket (up to k nodes)
    nodes: VecDeque<NodeInfo>,

    /// Replacement cache for when bucket is full
    replacement_cache: VecDeque<NodeInfo>,

    /// Last time this bucket was updated
    pub last_updated: u64,
}

impl KBucket {
    /// Create a new k-bucket
    pub fn new(index: usize) -> Self {
        KBucket {
            index,
            nodes: VecDeque::with_capacity(K),
            replacement_cache: VecDeque::with_capacity(K),
            last_updated: 0,
        }
    }

    /// Get number of nodes in bucket
    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    /// Check if bucket is empty
    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    /// Check if bucket is full
    pub fn is_full(&self) -> bool {
        self.nodes.len() >= K
    }

    /// Get all nodes in bucket
    pub fn nodes(&self) -> &VecDeque<NodeInfo> {
        &self.nodes
    }

    /// Get mutable reference to nodes
    pub fn nodes_mut(&mut self) -> &mut VecDeque<NodeInfo> {
        &mut self.nodes
    }

    /// Find node by ID
    pub fn find_node(&self, node_id: &NodeId) -> Option<&NodeInfo> {
        self.nodes.iter().find(|n| &n.node_id == node_id)
    }

    /// Find node mutably
    pub fn find_node_mut(&mut self, node_id: &NodeId) -> Option<&mut NodeInfo> {
        self.nodes.iter_mut().find(|n| &n.node_id == node_id)
    }

    /// Add or update a node in the bucket
    ///
    /// SECURITY H2: Enforces diversity constraints to prevent eclipse attacks
    /// Returns true if node was added/updated, false if bucket is full or diversity rejected
    pub fn add_or_update(&mut self, node: NodeInfo, current_time: u64) -> Result<bool> {
        let node_id = node.node_id;

        // If node already exists, move to back (most recently seen)
        if let Some(pos) = self.nodes.iter().position(|n| n.node_id == node_id) {
            self.nodes.remove(pos);
            self.nodes.push_back(node);
            self.last_updated = current_time;
            return Ok(true);
        }

        // If bucket not full, check diversity before adding
        if !self.is_full() {
            // SECURITY H2: Check diversity constraints
            if !self.check_diversity(&node) {
                // Diversity check failed - add to replacement cache instead
                self.add_to_replacement_cache(node);
                return Ok(false);
            }

            self.nodes.push_back(node);
            self.last_updated = current_time;
            return Ok(true);
        }

        // Bucket is full - check if we should evict the head
        if let Some(head) = self.nodes.front() {
            // If head node is bad (many failures), replace it
            if head.should_evict(5, 3600) {
                // SECURITY H2: Check diversity before replacing
                if !self.check_diversity(&node) {
                    // Diversity check failed - add to replacement cache instead
                    self.add_to_replacement_cache(node);
                    return Ok(false);
                }

                self.nodes.pop_front();
                self.nodes.push_back(node);
                self.last_updated = current_time;
                return Ok(true);
            }
        }

        // Bucket full and head is good - add to replacement cache
        self.add_to_replacement_cache(node);
        Ok(false)
    }

    /// Add node to replacement cache
    fn add_to_replacement_cache(&mut self, node: NodeInfo) {
        let node_id = node.node_id;

        // Remove if already in cache
        if let Some(pos) = self
            .replacement_cache
            .iter()
            .position(|n| n.node_id == node_id)
        {
            self.replacement_cache.remove(pos);
        }

        // Add to back
        self.replacement_cache.push_back(node);

        // Limit cache size
        if self.replacement_cache.len() > K {
            self.replacement_cache.pop_front();
        }
    }

    /// Remove a node from the bucket
    pub fn remove(&mut self, node_id: &NodeId) -> Option<NodeInfo> {
        if let Some(pos) = self.nodes.iter().position(|n| &n.node_id == node_id) {
            let removed = self.nodes.remove(pos);

            // Try to fill from replacement cache
            if let Some(replacement) = self.replacement_cache.pop_front() {
                self.nodes.push_back(replacement);
            }

            removed
        } else {
            None
        }
    }

    /// Remove stale nodes
    pub fn prune_stale(&mut self, max_age_secs: u64) -> usize {
        let mut removed = 0;

        self.nodes.retain(|node| {
            let should_keep = !node.is_stale(max_age_secs);
            if !should_keep {
                removed += 1;
            }
            should_keep
        });

        // Fill from replacement cache
        while !self.is_full() && !self.replacement_cache.is_empty() {
            if let Some(replacement) = self.replacement_cache.pop_front() {
                self.nodes.push_back(replacement);
            }
        }

        removed
    }

    /// Get replacement cache
    pub fn replacement_cache(&self) -> &VecDeque<NodeInfo> {
        &self.replacement_cache
    }

    /// SECURITY H2: Check if adding a node would violate diversity constraints
    /// Returns true if the node can be added without reducing diversity
    fn check_diversity(&self, new_node: &NodeInfo) -> bool {
        // Extract IP addresses and NodeID prefix from new node
        let new_ips = extract_ip_addresses(new_node);
        let new_prefix = get_node_id_prefix(&new_node.node_id);

        // Count existing nodes from same subnets
        let mut subnet_counts: HashMap<Vec<u8>, usize> = HashMap::new();
        for node in &self.nodes {
            let ips = extract_ip_addresses(node);
            for ip in ips {
                let subnet = get_subnet(&ip);
                *subnet_counts.entry(subnet).or_insert(0) += 1;
            }
        }

        // Check if new node's IPs would exceed subnet limit
        for ip in new_ips {
            let subnet = get_subnet(&ip);
            if let Some(&count) = subnet_counts.get(&subnet) {
                if count >= MAX_NODES_PER_SUBNET {
                    return false; // Too many nodes from this subnet
                }
            }
        }

        // Count existing nodes with same NodeID prefix
        let mut prefix_count = 0;
        for node in &self.nodes {
            let prefix = get_node_id_prefix(&node.node_id);
            if prefix == new_prefix {
                prefix_count += 1;
            }
        }

        if prefix_count >= MAX_NODES_PER_PREFIX {
            return false; // Too many nodes with this prefix
        }

        true // Diversity check passed
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use myriadmesh_protocol::types::NODE_ID_SIZE;

    fn create_test_node(id: u8) -> NodeInfo {
        NodeInfo::new(NodeId::from_bytes([id; NODE_ID_SIZE]))
    }

    #[test]
    fn test_empty_bucket() {
        let bucket = KBucket::new(0);
        assert!(bucket.is_empty());
        assert!(!bucket.is_full());
        assert_eq!(bucket.len(), 0);
    }

    #[test]
    fn test_add_node() {
        let mut bucket = KBucket::new(0);
        let node = create_test_node(1);

        let added = bucket.add_or_update(node, 0).unwrap();
        assert!(added);
        assert_eq!(bucket.len(), 1);
        assert!(!bucket.is_empty());
    }

    #[test]
    fn test_update_existing_node() {
        let mut bucket = KBucket::new(0);
        let node1 = create_test_node(1);
        let node2 = create_test_node(1); // Same ID

        bucket.add_or_update(node1, 0).unwrap();
        bucket.add_or_update(node2, 1).unwrap();

        // Should still have only 1 node
        assert_eq!(bucket.len(), 1);
        assert_eq!(bucket.last_updated, 1);
    }

    #[test]
    fn test_full_bucket() {
        let mut bucket = KBucket::new(0);

        // Fill bucket
        for i in 0..K {
            let node = create_test_node(i as u8);
            bucket.add_or_update(node, 0).unwrap();
        }

        assert!(bucket.is_full());
        assert_eq!(bucket.len(), K);

        // Try to add another node
        let extra_node = create_test_node(99);
        let added = bucket.add_or_update(extra_node, 0).unwrap();
        assert!(!added); // Should not be added

        // Should be in replacement cache
        assert_eq!(bucket.replacement_cache().len(), 1);
    }

    #[test]
    fn test_remove_node() {
        let mut bucket = KBucket::new(0);
        let node = create_test_node(1);
        let node_id = node.node_id;

        bucket.add_or_update(node, 0).unwrap();
        assert_eq!(bucket.len(), 1);

        let removed = bucket.remove(&node_id);
        assert!(removed.is_some());
        assert_eq!(bucket.len(), 0);
    }

    #[test]
    fn test_find_node() {
        let mut bucket = KBucket::new(0);
        let node = create_test_node(1);
        let node_id = node.node_id;

        bucket.add_or_update(node, 0).unwrap();

        let found = bucket.find_node(&node_id);
        assert!(found.is_some());

        let not_found = bucket.find_node(&NodeId::from_bytes([99; NODE_ID_SIZE]));
        assert!(not_found.is_none());
    }

    #[test]
    fn test_prune_stale() {
        let mut bucket = KBucket::new(0);

        // Add old node
        let mut old_node = create_test_node(1);
        old_node.last_seen = 0; // Very old
        bucket.add_or_update(old_node, 0).unwrap();

        // Add fresh node
        let fresh_node = create_test_node(2);
        bucket.add_or_update(fresh_node, 10000).unwrap();

        // Prune stale nodes (max age 1 hour)
        let pruned = bucket.prune_stale(3600);

        // Old node should be pruned
        assert_eq!(pruned, 1);
        assert_eq!(bucket.len(), 1);
    }

    #[test]
    fn test_replacement_cache_fills_bucket() {
        let mut bucket = KBucket::new(0);

        // Fill bucket
        for i in 0..K {
            let node = create_test_node(i as u8);
            bucket.add_or_update(node, 0).unwrap();
        }

        // Add to replacement cache
        let extra_node = create_test_node(99);
        bucket.add_or_update(extra_node, 0).unwrap();

        assert_eq!(bucket.replacement_cache().len(), 1);

        // Remove a node
        let first_node_id = bucket.nodes().front().unwrap().node_id;
        bucket.remove(&first_node_id);

        // Replacement cache should have filled the spot
        assert_eq!(bucket.len(), K);
        assert_eq!(bucket.replacement_cache().len(), 0);
    }

    // SECURITY H2: Eclipse attack prevention tests

    #[test]
    fn test_subnet_diversity_enforcement() {
        // SECURITY H2: Verify that buckets limit nodes from same subnet
        use crate::node_info::AdapterInfo;
        use myriadmesh_protocol::types::AdapterType;

        let mut bucket = KBucket::new(0);

        // Add 2 nodes from 192.168.1.x subnet (should be accepted)
        for i in 1..=2 {
            let mut node = create_test_node(i);
            node.adapters = vec![AdapterInfo {
                adapter_type: AdapterType::Ethernet,
                address: format!("192.168.1.{}:8080", i),
                active: true,
            }];
            let added = bucket.add_or_update(node, 0).unwrap();
            assert!(added, "First 2 nodes from subnet should be accepted");
        }

        // Try to add 3rd node from same subnet (should be rejected)
        let mut node3 = create_test_node(3);
        node3.adapters = vec![AdapterInfo {
            adapter_type: AdapterType::Ethernet,
            address: "192.168.1.100:8080".to_string(),
            active: true,
        }];
        let added = bucket.add_or_update(node3, 0).unwrap();
        assert!(!added, "3rd node from same subnet should be rejected");

        // Should only have 2 nodes in bucket
        assert_eq!(bucket.len(), 2);
    }

    #[test]
    fn test_node_id_prefix_diversity_enforcement() {
        // SECURITY H2: Verify that buckets limit nodes with same NodeID prefix
        let mut bucket = KBucket::new(0);

        // Create nodes with same prefix (first 2 bytes)
        let mut prefix_bytes = [0u8; NODE_ID_SIZE];
        prefix_bytes[0] = 0xAA;
        prefix_bytes[1] = 0xBB;

        // Add 3 nodes with same prefix (should be accepted)
        for i in 0..3 {
            prefix_bytes[2] = i; // Different 3rd byte
            let mut node = NodeInfo::new(NodeId::from_bytes(prefix_bytes));
            node.compute_pow(); // Add valid PoW
            let added = bucket.add_or_update(node, 0).unwrap();
            assert!(added, "First 3 nodes with same prefix should be accepted");
        }

        // Try to add 4th node with same prefix (should be rejected)
        prefix_bytes[2] = 99;
        let mut node4 = NodeInfo::new(NodeId::from_bytes(prefix_bytes));
        node4.compute_pow();
        let added = bucket.add_or_update(node4, 0).unwrap();
        assert!(!added, "4th node with same prefix should be rejected");

        // Should only have 3 nodes
        assert_eq!(bucket.len(), 3);
    }

    #[test]
    fn test_diversity_allows_different_subnets() {
        // SECURITY H2: Verify diverse subnets are allowed
        use crate::node_info::AdapterInfo;
        use myriadmesh_protocol::types::AdapterType;

        let mut bucket = KBucket::new(0);

        // Add nodes from different subnets (should all be accepted)
        for i in 1..=10 {
            let mut node = create_test_node(i);
            node.adapters = vec![AdapterInfo {
                adapter_type: AdapterType::Ethernet,
                address: format!("192.168.{}.1:8080", i), // Different subnet for each
                active: true,
            }];
            let added = bucket.add_or_update(node, 0).unwrap();
            assert!(added, "Nodes from different subnets should be accepted");
        }

        // All 10 should be in bucket
        assert_eq!(bucket.len(), 10);
    }

    #[test]
    fn test_diversity_check_with_no_adapters() {
        // SECURITY H2: Nodes without IP addresses should still be accepted
        let mut bucket = KBucket::new(0);

        // Add many nodes without adapters (should be accepted)
        for i in 1..=10 {
            let node = create_test_node(i); // No adapters
            let added = bucket.add_or_update(node, 0).unwrap();
            assert!(added, "Nodes without adapters should be accepted");
        }

        assert_eq!(bucket.len(), 10);
    }

    #[test]
    fn test_diversity_prevents_eclipse_attack_simulation() {
        // SECURITY H2: Simulate eclipse attack attempt
        use crate::node_info::AdapterInfo;
        use myriadmesh_protocol::types::AdapterType;

        let mut bucket = KBucket::new(0);

        // Attacker tries to fill bucket with nodes from controlled subnet
        let mut accepted = 0;
        let mut rejected = 0;

        for i in 1..=20 {
            let mut node = create_test_node(i);
            node.adapters = vec![AdapterInfo {
                adapter_type: AdapterType::Ethernet,
                address: format!("10.0.0.{}:8080", i), // All from same subnet
                active: true,
            }];

            if bucket.add_or_update(node, 0).unwrap() {
                accepted += 1;
            } else {
                rejected += 1;
            }
        }

        // Should accept MAX_NODES_PER_SUBNET (2), reject the rest
        assert_eq!(
            accepted, 2,
            "Only 2 nodes from same subnet should be accepted"
        );
        assert_eq!(rejected, 18, "Remaining 18 should be rejected");
        assert_eq!(bucket.len(), 2);
    }
}
