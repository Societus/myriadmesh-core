//! Path Selection Algorithm (F1.2)
//!
//! This module implements path selection for routing decisions:
//! - Selects optimal paths to destination
//! - Ranks paths by cost (hop count, latency, geography)
//! - Provides primary + alternative paths for failover

use myriadmesh_dht::{PublicNodeInfo, NodeCapabilities};
use myriadmesh_protocol::NodeId;
use std::collections::HashMap;

/// A candidate routing path
#[derive(Debug, Clone)]
pub struct RoutingPath {
    /// Next hop node ID
    pub next_hop: NodeId,
    /// Hop count from current node to destination
    pub hop_count: u8,
    /// Estimated cost (lower = better)
    pub estimated_cost: f32,
}

/// Result of path selection
#[derive(Debug, Clone)]
pub struct PathSelection {
    /// Primary (best) path
    pub primary: Option<RoutingPath>,
    /// Alternative paths for failover
    pub alternatives: Vec<RoutingPath>,
}

/// Metrics for path optimization
#[derive(Debug, Clone)]
pub struct PathMetrics {
    /// Enable latency-based optimization
    pub enable_latency_optimization: bool,
    /// Enable geographic-based optimization
    pub enable_geographic_optimization: bool,
}

impl Default for PathMetrics {
    fn default() -> Self {
        PathMetrics {
            enable_latency_optimization: true,
            enable_geographic_optimization: false,
        }
    }
}

/// Path Selector for F1.2 implementation
#[derive(Debug, Clone)]
pub struct PathSelector {
    /// Path selection metrics
    metrics: PathMetrics,
    /// Latency cache (optional)
    latency_cache: HashMap<NodeId, f32>,
}

impl PathSelector {
    /// Create a new path selector with default metrics
    pub fn new() -> Self {
        PathSelector {
            metrics: PathMetrics::default(),
            latency_cache: HashMap::new(),
        }
    }

    /// Create a new path selector with custom metrics
    pub fn with_metrics(metrics: PathMetrics) -> Self {
        PathSelector {
            metrics,
            latency_cache: HashMap::new(),
        }
    }

    /// F1.2 Core Implementation:
    /// Select optimal paths to destination
    ///
    /// Algorithm:
    /// 1. Calculate hop count (base cost)
    /// 2. Apply latency optimization (if enabled)
    /// 3. Apply geographic optimization (if enabled)
    /// 4. Rank paths by cost
    /// 5. Return primary + alternatives
    ///
    /// # Arguments
    /// - `target`: Target node ID (for future geographic calculations)
    /// - `candidates`: Candidate next-hop nodes
    ///
    /// # Returns
    /// PathSelection with primary and alternative paths
    pub fn select_paths(
        &self,
        _target: NodeId,
        candidates: Vec<PublicNodeInfo>,
    ) -> PathSelection {
        // Step 1: Calculate base cost for each candidate
        let mut paths = vec![];
        for candidate in candidates {
            let path = RoutingPath {
                next_hop: candidate.node_id,
                hop_count: 1, // Direct hop
                estimated_cost: Self::calculate_base_cost(&candidate),
            };
            paths.push(path);
        }

        // Step 2: Apply optimizations
        let mut paths = paths;
        for path in &mut paths {
            if self.metrics.enable_latency_optimization {
                path.estimated_cost += self.latency_cost(path);
            }
            if self.metrics.enable_geographic_optimization {
                path.estimated_cost += self.geographic_cost(path);
            }
        }

        // Step 3: Sort by cost (lower cost = better)
        paths.sort_by(|a, b| a.estimated_cost.partial_cmp(&b.estimated_cost).unwrap());

        // Step 4: Return primary + alternatives
        let primary = paths.first().cloned();
        let alternatives = if paths.len() > 1 {
            paths[1..].to_vec()
        } else {
            Vec::new()
        };

        PathSelection { primary, alternatives }
    }

    /// Calculate base cost for a path
    /// Lower cost = better path
    ///
    /// Cost is based on node reputation and capabilities
    fn calculate_base_cost(node: &PublicNodeInfo) -> f32 {
        let mut cost = 0.0f32;

        // Factor 1: RTT (lower is better) - typical: 1-100ms
        cost += (node.rtt_ms / 2.0) as f32; // 50ms = 25.0 cost units

        // Factor 2: Relay capability (can_relay) - required for forwarding
        if !node.capabilities.can_relay {
            cost += 50.0; // Penalize non-relay nodes
        }

        // Factor 3: Reputation penalty (higher reputation = lower cost)
        // reputation score ranges 0.0-1.0, higher is better
        let reputation_penalty = (1.0 - node.reputation.score()) * 100.0;
        cost += reputation_penalty as f32;

        cost
    }

    /// Calculate latency cost component
    /// Uses cached latency if available
    fn latency_cost(&self, path: &RoutingPath) -> f32 {
        // TODO: Integration point for latency optimization
        // Query last_known_latency for next hop from network metrics
        if let Some(&latency_ms) = self.latency_cache.get(&path.next_hop) {
            // Convert latency to cost component (1ms = 0.1 cost)
            latency_ms * 0.1
        } else {
            0.0
        }
    }

    /// Calculate geographic cost component
    fn geographic_cost(&self, _path: &RoutingPath) -> f32 {
        // TODO: Integration point for geographic optimization
        // Calculate distance if location info available
        0.0
    }

    /// Update latency cache for a node
    pub fn update_latency(&mut self, node_id: NodeId, latency_ms: f32) {
        self.latency_cache.insert(node_id, latency_ms);
    }

    /// Clear latency cache
    pub fn clear_latency_cache(&mut self) {
        self.latency_cache.clear();
    }

    /// Get number of paths (for testing)
    pub fn cached_metrics_count(&self) -> usize {
        self.latency_cache.len()
    }
}

impl Default for PathSelector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use myriadmesh_protocol::types::NODE_ID_SIZE;

    fn create_test_candidate(id_val: u8, rtt_ms: f64) -> PublicNodeInfo {
        let mut id_bytes = [0u8; NODE_ID_SIZE];
        id_bytes[0] = id_val;
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let node_id = NodeId::from_bytes(id_bytes);
        PublicNodeInfo {
            node_id,
            capabilities: NodeCapabilities {
                can_relay: true,
                can_store: true,
                store_and_forward: false,
                i2p_capable: false,
                tor_capable: false,
                max_message_size: 1024 * 1024,
                available_storage: 100 * 1024 * 1024,
                relay_tier: None,
                max_relay_bandwidth_bps: 10_000_000,
                relay_uptime_pct: 0.9,
                relay_load_pct: 0.3,
            },
            reputation: myriadmesh_dht::NodeReputation::new(),
            last_seen: timestamp,
            rtt_ms,
        }
    }

    #[test]
    fn test_single_path_selection() {
        let selector = PathSelector::new();
        let target = NodeId::from_bytes([0u8; NODE_ID_SIZE]);
        let candidates = vec![create_test_candidate(1, 50.0)]; // 50ms RTT

        let selection = selector.select_paths(target, candidates);

        assert!(selection.primary.is_some());
        assert_eq!(selection.alternatives.len(), 0);

        // Create the expected NodeId the same way the helper does
        let mut expected = [0u8; NODE_ID_SIZE];
        expected[0] = 1;
        assert_eq!(selection.primary.unwrap().next_hop, NodeId::from_bytes(expected));
    }

    #[test]
    fn test_multiple_paths_selection() {
        let selector = PathSelector::new();
        let target = NodeId::from_bytes([0u8; NODE_ID_SIZE]);
        let candidates = vec![
            create_test_candidate(1, 10.0),
            create_test_candidate(2, 30.0),
            create_test_candidate(3, 60.0),
        ];

        let selection = selector.select_paths(target, candidates);

        assert!(selection.primary.is_some());
        assert_eq!(selection.alternatives.len(), 2);

        // Primary should be the path with lowest cost (lowest RTT)
        let primary = selection.primary.unwrap();
        let mut expected = [0u8; NODE_ID_SIZE];
        expected[0] = 1;
        assert_eq!(primary.next_hop, NodeId::from_bytes(expected)); // 10ms = lowest cost
    }

    #[test]
    fn test_path_cost_ordering() {
        let selector = PathSelector::new();
        let target = NodeId::from_bytes([0u8; NODE_ID_SIZE]);
        let candidates = vec![
            create_test_candidate(1, 100.0), // cost = 50.0 + 0 + 0 = 50.0
            create_test_candidate(2, 20.0),  // cost = 10.0 + 0 + 0 = 10.0 (best)
            create_test_candidate(3, 60.0),  // cost = 30.0 + 0 + 0 = 30.0
        ];

        let selection = selector.select_paths(target, candidates);

        let primary = selection.primary.unwrap();
        let mut expected2 = [0u8; NODE_ID_SIZE];
        expected2[0] = 2;
        assert_eq!(primary.next_hop, NodeId::from_bytes(expected2));

        // Verify alternatives are ordered by cost
        let mut expected3 = [0u8; NODE_ID_SIZE];
        expected3[0] = 3;
        assert_eq!(selection.alternatives[0].next_hop, NodeId::from_bytes(expected3));

        let mut expected1 = [0u8; NODE_ID_SIZE];
        expected1[0] = 1;
        assert_eq!(selection.alternatives[1].next_hop, NodeId::from_bytes(expected1));
    }

    #[test]
    fn test_no_paths_available() {
        let selector = PathSelector::new();
        let target = NodeId::from_bytes([0u8; NODE_ID_SIZE]);
        let candidates = vec![];

        let selection = selector.select_paths(target, candidates);

        assert!(selection.primary.is_none());
        assert_eq!(selection.alternatives.len(), 0);
    }

    #[test]
    fn test_latency_optimization() {
        let mut selector = PathSelector::with_metrics(PathMetrics {
            enable_latency_optimization: true,
            enable_geographic_optimization: false,
        });

        let target = NodeId::from_bytes([0u8; NODE_ID_SIZE]);
        let mut node1_bytes = [0u8; NODE_ID_SIZE];
        node1_bytes[0] = 1;
        let node1 = NodeId::from_bytes(node1_bytes);

        let mut node2_bytes = [0u8; NODE_ID_SIZE];
        node2_bytes[0] = 2;
        let node2 = NodeId::from_bytes(node2_bytes);

        // Update latency cache (node1 has 10ms additional, node2 has 50ms additional)
        selector.update_latency(node1, 10.0);
        selector.update_latency(node2, 50.0);

        let candidates = vec![
            create_test_candidate(1, 30.0),
            create_test_candidate(2, 30.0),
        ];

        let selection = selector.select_paths(target, candidates);

        // Primary should be node1 (lower latency optimization bonus)
        let primary = selection.primary.unwrap();
        assert_eq!(primary.next_hop, node1);
    }

    #[test]
    fn test_equal_cost_paths() {
        let selector = PathSelector::new();
        let target = NodeId::from_bytes([0u8; NODE_ID_SIZE]);
        let candidates = vec![
            create_test_candidate(1, 30.0),
            create_test_candidate(2, 30.0),
            create_test_candidate(3, 30.0),
        ];

        let selection = selector.select_paths(target, candidates);

        assert!(selection.primary.is_some());
        assert_eq!(selection.alternatives.len(), 2);
        // All should have same cost
        let primary_cost = selection.primary.as_ref().unwrap().estimated_cost;
        for alt in &selection.alternatives {
            assert!((alt.estimated_cost - primary_cost).abs() < 0.01);
        }
    }

    #[test]
    fn test_path_performance() {
        let selector = PathSelector::new();
        let target = NodeId::from_bytes([0u8; NODE_ID_SIZE]);

        // Generate 100+ candidates
        let candidates: Vec<_> = (1..=100)
            .map(|i| create_test_candidate((i % 256) as u8, 30.0))
            .collect();

        let start = std::time::Instant::now();
        let _selection = selector.select_paths(target, candidates);
        let elapsed = start.elapsed();

        // Should complete in < 50ms
        assert!(elapsed.as_millis() < 50);
    }
}
