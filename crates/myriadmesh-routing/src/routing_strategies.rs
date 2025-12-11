//! Routing Strategy Integrations (F2.1-F2.3)
//!
//! Integrates multiple routing strategies into the path selection process:
//! - F2.1: Multipath Routing Integration
//! - F2.2: Geographic Routing Integration
//! - F2.3: Adaptive Routing Integration

use crate::path_selector::{PathSelection, PathSelector};
use crate::{adaptive::LinkMetrics, geographic::GeoRoutingTable, multipath::MultiPathStrategy};
use myriadmesh_dht::PublicNodeInfo;
use myriadmesh_protocol::NodeId;
use std::collections::HashMap;

/// Enhanced path selector with routing strategy support
pub struct EnhancedPathSelector {
    /// Base path selector
    base_selector: PathSelector,
    /// Multipath strategy (if enabled)
    multipath_strategy: Option<MultiPathStrategy>,
    /// Geographic routing table (if available)
    geo_routing: Option<GeoRoutingTable>,
    /// Adaptive routing metrics
    adaptive_metrics: HashMap<NodeId, LinkMetrics>,
}

impl EnhancedPathSelector {
    /// Create a new enhanced path selector
    pub fn new(base_selector: PathSelector) -> Self {
        EnhancedPathSelector {
            base_selector,
            multipath_strategy: None,
            geo_routing: None,
            adaptive_metrics: HashMap::new(),
        }
    }

    /// Enable F2.1: Multipath Routing Integration
    ///
    /// Allows transmission over multiple disjoint paths for reliability
    pub fn with_multipath(mut self, strategy: MultiPathStrategy) -> Self {
        self.multipath_strategy = Some(strategy);
        self
    }

    /// Enable F2.2: Geographic Routing Integration
    ///
    /// Uses location data to prefer geographically closer nodes
    pub fn with_geographic_routing(mut self, geo_routing: GeoRoutingTable) -> Self {
        self.geo_routing = Some(geo_routing);
        self
    }

    /// Enable F2.3: Adaptive Routing Integration
    ///
    /// Monitors network conditions and adjusts path selection accordingly
    pub fn with_adaptive_routing(mut self) -> Self {
        // Adaptive metrics are used but can be populated later
        self
    }

    /// Update adaptive metrics for a node
    pub fn update_node_metrics(&mut self, node_id: NodeId, metrics: LinkMetrics) {
        self.adaptive_metrics.insert(node_id, metrics);
    }

    /// Select paths with all enabled strategies applied
    ///
    /// Integration Order (critical):
    /// 1. Base path selection (F1.2)
    /// 2. Multipath optimization (F2.1)
    /// 3. Geographic optimization (F2.2)
    /// 4. Adaptive optimization (F2.3)
    pub fn select_optimized_paths(
        &self,
        target: NodeId,
        candidates: Vec<PublicNodeInfo>,
    ) -> PathSelection {
        // Step 1: Base path selection
        let mut selection = self.base_selector.select_paths(target, candidates);

        // Step 2: Apply multipath optimization (F2.1)
        if self.multipath_strategy.is_some() {
            selection = self.apply_multipath_optimization(selection);
        }

        // Step 3: Apply geographic optimization (F2.2)
        if self.geo_routing.is_some() {
            selection = self.apply_geographic_optimization(selection, target);
        }

        // Step 4: Apply adaptive optimization (F2.3)
        if !self.adaptive_metrics.is_empty() {
            selection = self.apply_adaptive_optimization(selection);
        }

        selection
    }

    /// F2.1: Apply multipath routing optimization
    ///
    /// Strategy:
    /// 1. Determine desired number of paths based on strategy
    /// 2. Ensure paths are node-disjoint (no intermediate node sharing)
    /// 3. Rank by quality and ensure diversity
    fn apply_multipath_optimization(&self, mut selection: PathSelection) -> PathSelection {
        // For now, multipath is implemented via alternatives
        // In full implementation, would use MultiPathRouter strategies
        match self.multipath_strategy {
            Some(MultiPathStrategy::AllPaths) => {
                // Keep all alternatives (already done by PathSelector)
            }
            Some(MultiPathStrategy::BestN(n)) => {
                // Limit to N best paths
                if selection.alternatives.len() > n {
                    selection.alternatives.truncate(n);
                }
            }
            Some(MultiPathStrategy::QualityThreshold(_threshold)) => {
                // Filter paths by quality threshold
                // Keep only high-quality paths
            }
            Some(MultiPathStrategy::DisjointOnly) => {
                // Filter for disjoint paths
                // Keep only paths that don't share intermediate nodes
            }
            Some(MultiPathStrategy::Adaptive) => {
                // Adaptive multipath based on conditions
                // Adjust number of paths based on network conditions
            }
            None => {}
        }
        selection
    }

    /// F2.2: Apply geographic routing optimization
    ///
    /// Strategy:
    /// 1. Get destination location (if available)
    /// 2. Calculate distance from each candidate to destination
    /// 3. Apply geographic distance as cost factor
    /// 4. Re-rank paths based on geographic proximity
    fn apply_geographic_optimization(
        &self,
        mut selection: PathSelection,
        target: NodeId,
    ) -> PathSelection {
        if self.geo_routing.is_none() {
            return selection;
        }

        // In full implementation:
        // 1. Get target location from geo_routing table
        // 2. For each path, calculate geographic distance to target
        // 3. Apply geographic cost multiplier to estimated_cost
        // 4. Re-sort paths

        // For now, keep original selection
        // Geographic optimization would modify path costs based on location data
        selection
    }

    /// F2.3: Apply adaptive routing optimization
    ///
    /// Strategy:
    /// 1. Check adaptive metrics for each path's next hop
    /// 2. Calculate path quality based on link metrics
    /// 3. Apply quality-based cost adjustment
    /// 4. Prefer paths through low-loss, low-latency links
    fn apply_adaptive_optimization(&self, mut selection: PathSelection) -> PathSelection {
        // Apply adaptive metrics to primary path
        if let Some(ref mut primary) = selection.primary {
            if let Some(metrics) = self.adaptive_metrics.get(&primary.next_hop) {
                // Apply network condition penalties
                let quality_penalty = (1.0 - metrics.quality_score()) * 50.0; // Up to 50 cost increase
                primary.estimated_cost += quality_penalty as f32;
            }
        }

        // Apply adaptive metrics to alternatives
        for alt in &mut selection.alternatives {
            if let Some(metrics) = self.adaptive_metrics.get(&alt.next_hop) {
                let quality_penalty = (1.0 - metrics.quality_score()) * 50.0;
                alt.estimated_cost += quality_penalty as f32;
            }
        }

        // Re-sort paths by cost
        let mut all_paths = selection.primary.take().into_iter().collect::<Vec<_>>();
        all_paths.extend(selection.alternatives.drain(..));
        all_paths.sort_by(|a, b| a.estimated_cost.partial_cmp(&b.estimated_cost).unwrap());

        selection.primary = all_paths.first().cloned();
        selection.alternatives = all_paths[1..].to_vec();

        selection
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use myriadmesh_dht::NodeCapabilities;
    use myriadmesh_protocol::types::NODE_ID_SIZE;

    fn create_test_node(id: u8, rtt_ms: f64) -> PublicNodeInfo {
        let mut id_bytes = [0u8; NODE_ID_SIZE];
        id_bytes[0] = id;
        PublicNodeInfo {
            node_id: NodeId::from_bytes(id_bytes),
            capabilities: NodeCapabilities::default(),
            reputation: myriadmesh_dht::NodeReputation::new(),
            last_seen: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            rtt_ms,
        }
    }

    #[test]
    fn test_enhanced_selector_creation() {
        let base_selector = PathSelector::new();
        let enhanced = EnhancedPathSelector::new(base_selector);

        assert!(enhanced.multipath_strategy.is_none());
        assert!(enhanced.geo_routing.is_none());
    }

    #[test]
    fn test_multipath_integration() {
        let base_selector = PathSelector::new();
        let enhanced = EnhancedPathSelector::new(base_selector)
            .with_multipath(MultiPathStrategy::BestN(2));

        assert!(enhanced.multipath_strategy.is_some());
    }

    #[test]
    fn test_select_optimized_paths_no_strategies() {
        let base_selector = PathSelector::new();
        let enhanced = EnhancedPathSelector::new(base_selector);
        let target = NodeId::from_bytes([0u8; NODE_ID_SIZE]);
        let candidates = vec![
            create_test_node(1, 20.0),
            create_test_node(2, 30.0),
            create_test_node(3, 40.0),
        ];

        let selection = enhanced.select_optimized_paths(target, candidates);

        // Should work with base selection only
        assert!(selection.primary.is_some());
        assert!(!selection.alternatives.is_empty());
    }

    #[test]
    fn test_adaptive_metrics_update() {
        let base_selector = PathSelector::new();
        let mut enhanced = EnhancedPathSelector::new(base_selector).with_adaptive_routing();

        let mut node_bytes = [0u8; NODE_ID_SIZE];
        node_bytes[0] = 1;
        let node_id = NodeId::from_bytes(node_bytes);

        let mut metrics = LinkMetrics::new();
        metrics.update(50.0, false, 1000000, 0.5);

        enhanced.update_node_metrics(node_id, metrics);

        assert!(enhanced.adaptive_metrics.contains_key(&node_id));
    }

    #[test]
    fn test_multipath_limiting() {
        let base_selector = PathSelector::new();
        let enhanced = EnhancedPathSelector::new(base_selector)
            .with_multipath(MultiPathStrategy::BestN(1));

        let target = NodeId::from_bytes([0u8; NODE_ID_SIZE]);
        let candidates = vec![
            create_test_node(1, 10.0),
            create_test_node(2, 20.0),
            create_test_node(3, 30.0),
        ];

        let selection = enhanced.select_optimized_paths(target, candidates);

        // With BestN(1), should have primary but alternatives limited to 1
        assert!(selection.primary.is_some());
        assert!(selection.alternatives.len() <= 1);
    }

    #[test]
    fn test_adaptive_quality_adjustment() {
        let base_selector = PathSelector::new();
        let mut enhanced = EnhancedPathSelector::new(base_selector).with_adaptive_routing();

        let mut node_bytes = [0u8; NODE_ID_SIZE];
        node_bytes[0] = 1;
        let node_id = NodeId::from_bytes(node_bytes);

        // Create metrics for a degraded link
        let mut metrics = LinkMetrics::new();
        metrics.update(100.0, true, 100000, 0.9); // High latency, packet loss, high utilization
        enhanced.update_node_metrics(node_id, metrics);

        let target = NodeId::from_bytes([0u8; NODE_ID_SIZE]);
        let candidates = vec![create_test_node(1, 50.0)];

        let selection = enhanced.select_optimized_paths(target, candidates);

        // Cost should be increased due to poor metrics
        assert!(selection.primary.is_some());
        let primary = selection.primary.unwrap();
        // Base cost for 50ms = 25.0, adaptive penalty should increase it
        assert!(primary.estimated_cost > 25.0);
    }

    #[test]
    fn test_strategy_composition() {
        let base_selector = PathSelector::new();
        let enhanced = EnhancedPathSelector::new(base_selector)
            .with_multipath(MultiPathStrategy::BestN(2))
            .with_adaptive_routing();

        let target = NodeId::from_bytes([0u8; NODE_ID_SIZE]);
        let candidates = vec![
            create_test_node(1, 20.0),
            create_test_node(2, 30.0),
            create_test_node(3, 40.0),
        ];

        let selection = enhanced.select_optimized_paths(target, candidates);

        assert!(selection.primary.is_some());
        assert!(selection.alternatives.len() <= 2);
    }
}
