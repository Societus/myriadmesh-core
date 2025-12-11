//! Multi-path Routing - Parallel transmission over multiple paths
//!
//! Implements multi-path routing strategies that send copies of messages
//! along multiple disjoint paths to improve reliability and reduce latency.
//! Useful for high-priority messages or unreliable network conditions.

use myriadmesh_protocol::NodeId;
use std::collections::{HashMap, HashSet};

/// Path through the network
#[derive(Debug, Clone)]
pub struct NetworkPath {
    /// Sequence of nodes in the path (including source and destination)
    pub hops: Vec<NodeId>,
    /// Estimated path cost (lower is better)
    pub cost: u32,
    /// Path quality metric (0.0-1.0, higher is better)
    pub quality: f32,
}

impl PartialEq for NetworkPath {
    fn eq(&self, other: &Self) -> bool {
        self.hops == other.hops && self.cost == other.cost
    }
}

impl Eq for NetworkPath {}

impl std::hash::Hash for NetworkPath {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.hops.hash(state);
        self.cost.hash(state);
    }
}

impl NetworkPath {
    /// Create a new path
    pub fn new(hops: Vec<NodeId>) -> Self {
        Self {
            hops,
            cost: 0,
            quality: 1.0,
        }
    }

    /// Create path with cost and quality
    pub fn with_metrics(hops: Vec<NodeId>, cost: u32, quality: f32) -> Self {
        Self {
            hops,
            cost,
            quality,
        }
    }

    /// Get path length (number of hops)
    pub fn length(&self) -> usize {
        if !self.hops.is_empty() {
            self.hops.len() - 1 // Hops = edges = nodes - 1
        } else {
            0
        }
    }

    /// Get next hop from a given node
    pub fn next_hop(&self, current: &NodeId) -> Option<NodeId> {
        for i in 0..self.hops.len() - 1 {
            if &self.hops[i] == current {
                return Some(self.hops[i + 1]);
            }
        }
        None
    }

    /// Check if path contains a node
    pub fn contains(&self, node: &NodeId) -> bool {
        self.hops.contains(node)
    }

    /// Check if paths are node-disjoint (except source and destination)
    pub fn is_disjoint_with(&self, other: &NetworkPath) -> bool {
        if self.hops.is_empty() || other.hops.is_empty() {
            return false;
        }

        // Get intermediate nodes (exclude source and destination)
        let self_intermediate: HashSet<_> = self.hops[1..self.hops.len() - 1].iter().collect();
        let other_intermediate: HashSet<_> = other.hops[1..other.hops.len() - 1].iter().collect();

        // Paths are disjoint if they share no intermediate nodes
        self_intermediate.is_disjoint(&other_intermediate)
    }
}

/// Multi-path routing strategy
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MultiPathStrategy {
    /// Send on all available paths
    AllPaths,
    /// Send on N best paths
    BestN(usize),
    /// Send on paths with quality above threshold
    QualityThreshold(u8), // 0-100
    /// Send on disjoint paths only
    DisjointOnly,
    /// Adaptive based on message priority
    Adaptive,
}

/// Multi-path router
pub struct MultiPathRouter {
    /// Known paths to each destination
    paths: HashMap<NodeId, Vec<NetworkPath>>,
    /// Strategy to use
    strategy: MultiPathStrategy,
    /// Maximum paths to maintain per destination
    max_paths_per_dest: usize,
}

impl MultiPathRouter {
    /// Create a new multi-path router
    pub fn new(strategy: MultiPathStrategy, max_paths_per_dest: usize) -> Self {
        Self {
            paths: HashMap::new(),
            strategy,
            max_paths_per_dest,
        }
    }

    /// Add a path to a destination
    pub fn add_path(&mut self, destination: NodeId, path: NetworkPath) {
        let paths = self.paths.entry(destination).or_default();

        // Add path if not already present
        if !paths.contains(&path) {
            paths.push(path);

            // Sort by cost (lower cost first)
            paths.sort_by_key(|p| p.cost);

            // Limit total paths
            if paths.len() > self.max_paths_per_dest {
                paths.truncate(self.max_paths_per_dest);
            }
        }
    }

    /// Remove a path
    pub fn remove_path(&mut self, destination: &NodeId, path: &NetworkPath) {
        if let Some(paths) = self.paths.get_mut(destination) {
            paths.retain(|p| p != path);
        }
    }

    /// Get all paths to a destination
    pub fn get_paths(&self, destination: &NodeId) -> Option<&Vec<NetworkPath>> {
        self.paths.get(destination)
    }

    /// Select paths to use for a message based on strategy
    pub fn select_paths(
        &self,
        destination: &NodeId,
        priority: u8, // 0-255, higher = more important
    ) -> Vec<NetworkPath> {
        let available_paths = match self.paths.get(destination) {
            Some(paths) => paths,
            None => return Vec::new(),
        };

        match self.strategy {
            MultiPathStrategy::AllPaths => available_paths.clone(),

            MultiPathStrategy::BestN(n) => available_paths.iter().take(n).cloned().collect(),

            MultiPathStrategy::QualityThreshold(threshold) => {
                let threshold_f32 = threshold as f32 / 100.0;
                available_paths
                    .iter()
                    .filter(|p| p.quality >= threshold_f32)
                    .cloned()
                    .collect()
            }

            MultiPathStrategy::DisjointOnly => self.select_disjoint_paths(available_paths),

            MultiPathStrategy::Adaptive => {
                // Adaptive: more paths for higher priority
                let num_paths = match priority {
                    200..=255 => 3, // Urgent: 3 paths
                    150..=199 => 2, // High: 2 paths
                    _ => 1,         // Normal/Low: 1 path
                };
                self.select_disjoint_paths_n(available_paths, num_paths)
            }
        }
    }

    /// Select node-disjoint paths
    fn select_disjoint_paths(&self, available_paths: &[NetworkPath]) -> Vec<NetworkPath> {
        if available_paths.is_empty() {
            return Vec::new();
        }

        let mut selected = Vec::new();
        selected.push(available_paths[0].clone());

        for path in available_paths.iter().skip(1) {
            // Check if this path is disjoint with all selected paths
            if selected.iter().all(|p| path.is_disjoint_with(p)) {
                selected.push(path.clone());
            }
        }

        selected
    }

    /// Select up to N node-disjoint paths
    fn select_disjoint_paths_n(
        &self,
        available_paths: &[NetworkPath],
        n: usize,
    ) -> Vec<NetworkPath> {
        if available_paths.is_empty() || n == 0 {
            return Vec::new();
        }

        let mut selected = Vec::new();
        selected.push(available_paths[0].clone());

        for path in available_paths.iter().skip(1) {
            if selected.len() >= n {
                break;
            }

            // Check if this path is disjoint with all selected paths
            if selected.iter().all(|p| path.is_disjoint_with(p)) {
                selected.push(path.clone());
            }
        }

        selected
    }

    /// Update path quality based on feedback
    pub fn update_path_quality(&mut self, destination: &NodeId, path: &NetworkPath, success: bool) {
        if let Some(paths) = self.paths.get_mut(destination) {
            if let Some(stored_path) = paths.iter_mut().find(|p| p.hops == path.hops) {
                if success {
                    // Increase quality on success
                    stored_path.quality = (stored_path.quality * 0.9 + 0.1).min(1.0);
                } else {
                    // Decrease quality on failure
                    stored_path.quality = (stored_path.quality * 0.8).max(0.0);
                }
            }
        }
    }

    /// Calculate path diversity score (higher = more diverse)
    pub fn path_diversity_score(&self, paths: &[NetworkPath]) -> f32 {
        if paths.len() < 2 {
            return 0.0;
        }

        let mut disjoint_pairs = 0;
        let mut total_pairs = 0;

        for i in 0..paths.len() {
            for j in (i + 1)..paths.len() {
                total_pairs += 1;
                if paths[i].is_disjoint_with(&paths[j]) {
                    disjoint_pairs += 1;
                }
            }
        }

        if total_pairs > 0 {
            disjoint_pairs as f32 / total_pairs as f32
        } else {
            0.0
        }
    }

    /// Get routing statistics
    pub fn stats(&self) -> MultiPathStats {
        let total_destinations = self.paths.len();
        let total_paths: usize = self.paths.values().map(|v| v.len()).sum();
        let avg_paths_per_dest = if total_destinations > 0 {
            total_paths as f32 / total_destinations as f32
        } else {
            0.0
        };

        MultiPathStats {
            total_destinations,
            total_paths,
            avg_paths_per_dest,
        }
    }

    /// Clear all paths for a destination (useful for failover)
    pub fn clear_paths(&mut self, destination: &NodeId) {
        self.paths.remove(destination);
    }

    /// Get best path by quality and cost combination
    pub fn get_best_path(&self, destination: &NodeId) -> Option<NetworkPath> {
        self.paths.get(destination).and_then(|paths| {
            // Score each path: (quality * 0.6) - (cost * 0.4)
            paths
                .iter()
                .max_by(|a, b| {
                    let score_a = (a.quality * 0.6) - ((a.cost as f32) * 0.4 / 1000.0);
                    let score_b = (b.quality * 0.6) - ((b.cost as f32) * 0.4 / 1000.0);
                    score_a.partial_cmp(&score_b).unwrap_or(std::cmp::Ordering::Equal)
                })
                .cloned()
        })
    }

    /// Batch update multiple paths' quality (useful for acknowledgments)
    pub fn update_batch_quality(&mut self, destination: &NodeId, paths: &[NetworkPath], success: bool) {
        for path in paths {
            self.update_path_quality(destination, path, success);
        }
    }
}

/// Multi-path routing statistics
#[derive(Debug, Clone)]
pub struct MultiPathStats {
    pub total_destinations: usize,
    pub total_paths: usize,
    pub avg_paths_per_dest: f32,
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
    fn test_network_path() {
        let path = NetworkPath::new(vec![
            create_test_node_id(1),
            create_test_node_id(2),
            create_test_node_id(3),
        ]);

        assert_eq!(path.length(), 2);
        assert_eq!(
            path.next_hop(&create_test_node_id(1)),
            Some(create_test_node_id(2))
        );
        assert_eq!(
            path.next_hop(&create_test_node_id(2)),
            Some(create_test_node_id(3))
        );
        assert_eq!(path.next_hop(&create_test_node_id(3)), None);
    }

    #[test]
    fn test_path_disjoint() {
        let path1 = NetworkPath::new(vec![
            create_test_node_id(1),
            create_test_node_id(2),
            create_test_node_id(5),
        ]);

        let path2 = NetworkPath::new(vec![
            create_test_node_id(1),
            create_test_node_id(3),
            create_test_node_id(5),
        ]);

        let path3 = NetworkPath::new(vec![
            create_test_node_id(1),
            create_test_node_id(2), // Shares node 2 with path1
            create_test_node_id(4),
            create_test_node_id(5),
        ]);

        assert!(path1.is_disjoint_with(&path2)); // No shared intermediate nodes
        assert!(!path1.is_disjoint_with(&path3)); // Shares node 2
    }

    #[test]
    fn test_multipath_router_add_path() {
        let mut router = MultiPathRouter::new(MultiPathStrategy::AllPaths, 5);
        let dest = create_test_node_id(10);

        let path1 = NetworkPath::with_metrics(
            vec![create_test_node_id(1), create_test_node_id(2), dest],
            10,
            0.9,
        );

        router.add_path(dest, path1.clone());

        let paths = router.get_paths(&dest).unwrap();
        assert_eq!(paths.len(), 1);
        assert_eq!(paths[0], path1);
    }

    #[test]
    fn test_multipath_select_best_n() {
        let mut router = MultiPathRouter::new(MultiPathStrategy::BestN(2), 5);
        let dest = create_test_node_id(10);

        // Add 3 paths with different costs
        router.add_path(
            dest,
            NetworkPath::with_metrics(vec![create_test_node_id(1), dest], 10, 0.9),
        );
        router.add_path(
            dest,
            NetworkPath::with_metrics(vec![create_test_node_id(2), dest], 5, 0.95),
        );
        router.add_path(
            dest,
            NetworkPath::with_metrics(vec![create_test_node_id(3), dest], 20, 0.8),
        );

        let selected = router.select_paths(&dest, 100);
        assert_eq!(selected.len(), 2);
        // Should select 2 lowest cost paths
        assert_eq!(selected[0].cost, 5);
        assert_eq!(selected[1].cost, 10);
    }

    #[test]
    fn test_path_quality_update() {
        let mut router = MultiPathRouter::new(MultiPathStrategy::AllPaths, 5);
        let dest = create_test_node_id(10);

        let path = NetworkPath::with_metrics(
            vec![create_test_node_id(1), create_test_node_id(2), dest],
            10,
            0.5,
        );

        router.add_path(dest, path.clone());

        // Simulate success
        router.update_path_quality(&dest, &path, true);
        let updated = &router.get_paths(&dest).unwrap()[0];
        assert!(updated.quality > 0.5);

        // Simulate failure
        router.update_path_quality(&dest, &path, false);
        router.update_path_quality(&dest, &path, false);
        let updated = &router.get_paths(&dest).unwrap()[0];
        assert!(updated.quality < 0.5);
    }

    #[test]
    fn test_get_best_path() {
        let mut router = MultiPathRouter::new(MultiPathStrategy::AllPaths, 5);
        let dest = create_test_node_id(10);

        // Add 3 paths with different quality and cost
        let path1 = NetworkPath::with_metrics(
            vec![create_test_node_id(1), create_test_node_id(2), dest],
            100,
            0.5,
        );
        let path2 = NetworkPath::with_metrics(
            vec![create_test_node_id(3), create_test_node_id(4), dest],
            50,
            0.8,
        );
        let path3 = NetworkPath::with_metrics(
            vec![create_test_node_id(5), create_test_node_id(6), dest],
            200,
            0.3,
        );

        router.add_path(dest, path1);
        router.add_path(dest, path2.clone());
        router.add_path(dest, path3);

        // Best path should be path2 (good quality, low cost)
        let best = router.get_best_path(&dest).unwrap();
        assert_eq!(best.hops[0], create_test_node_id(3));
    }

    #[test]
    fn test_path_diversity_score() {
        let mut router = MultiPathRouter::new(MultiPathStrategy::DisjointOnly, 5);
        let dest = create_test_node_id(10);

        // Add 2 disjoint paths
        let path1 = NetworkPath::new(vec![
            create_test_node_id(1),
            create_test_node_id(2),
            dest,
        ]);
        let path2 = NetworkPath::new(vec![
            create_test_node_id(1),
            create_test_node_id(3),
            dest,
        ]);

        router.add_path(dest, path1.clone());
        router.add_path(dest, path2.clone());

        let paths = vec![path1, path2];
        let diversity = router.path_diversity_score(&paths);
        // 2 disjoint paths out of 1 pair = 1.0 diversity
        assert_eq!(diversity, 1.0);
    }

    #[test]
    fn test_clear_paths() {
        let mut router = MultiPathRouter::new(MultiPathStrategy::AllPaths, 5);
        let dest = create_test_node_id(10);

        let path = NetworkPath::new(vec![create_test_node_id(1), dest]);
        router.add_path(dest, path);

        assert!(router.get_paths(&dest).is_some());
        router.clear_paths(&dest);
        assert!(router.get_paths(&dest).is_none());
    }

    #[test]
    fn test_batch_quality_update() {
        let mut router = MultiPathRouter::new(MultiPathStrategy::AllPaths, 5);
        let dest = create_test_node_id(10);

        let path1 = NetworkPath::with_metrics(
            vec![create_test_node_id(1), dest],
            10,
            0.5,
        );
        let path2 = NetworkPath::with_metrics(
            vec![create_test_node_id(2), dest],
            10,
            0.5,
        );

        router.add_path(dest, path1.clone());
        router.add_path(dest, path2.clone());

        // Batch update both paths
        router.update_batch_quality(&dest, &[path1.clone(), path2.clone()], true);

        let updated_paths = router.get_paths(&dest).unwrap();
        assert!(updated_paths[0].quality > 0.5);
        assert!(updated_paths[1].quality > 0.5);
    }

    #[test]
    fn test_multipath_for_high_priority() {
        let mut router = MultiPathRouter::new(MultiPathStrategy::Adaptive, 5);
        let dest = create_test_node_id(10);

        // Add 3 disjoint paths
        router.add_path(
            dest,
            NetworkPath::new(vec![create_test_node_id(1), create_test_node_id(2), dest]),
        );
        router.add_path(
            dest,
            NetworkPath::new(vec![create_test_node_id(1), create_test_node_id(3), dest]),
        );
        router.add_path(
            dest,
            NetworkPath::new(vec![create_test_node_id(1), create_test_node_id(4), dest]),
        );

        // High priority (200) should select 3 paths
        let selected = router.select_paths(&dest, 200);
        assert_eq!(selected.len(), 3);

        // Normal priority (100) should select 1 path
        let selected = router.select_paths(&dest, 100);
        assert_eq!(selected.len(), 1);
    }
}
