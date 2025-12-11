//! Rate limiting for message routing

use myriadmesh_protocol::NodeId;
use std::collections::HashMap;
use std::time::{Duration, Instant};

/// Rate limiter for message routing
#[derive(Debug)]
pub struct RateLimiter {
    /// Messages per minute per node
    per_node_limit: u32,

    /// Total messages per minute globally
    global_limit: u32,

    /// Per-node counters (node_id -> (count, window_start))
    node_counters: HashMap<NodeId, (u32, Instant)>,

    /// Global counter (count, window_start)
    global_counter: (u32, Instant),

    /// Window duration
    window: Duration,
}

impl RateLimiter {
    /// Create a new rate limiter
    pub fn new(per_node_limit: u32, global_limit: u32) -> Self {
        RateLimiter {
            per_node_limit,
            global_limit,
            node_counters: HashMap::new(),
            global_counter: (0, Instant::now()),
            window: Duration::from_secs(60), // 1 minute window
        }
    }

    /// Check if a message from a node should be accepted
    ///
    /// SECURITY H12: Global limit is checked FIRST to prevent resource exhaustion
    /// from per-node tracking when global capacity is exhausted
    pub fn check_rate(&mut self, node_id: &NodeId) -> Result<(), RateLimitError> {
        let now = Instant::now();

        // SECURITY H12: Check global limit FIRST before per-node tracking
        // This prevents attackers from exhausting resources by forcing
        // per-node state updates when global capacity is already exceeded
        if now.duration_since(self.global_counter.1) >= self.window {
            self.global_counter = (0, now);
        }

        // Check if incrementing would exceed global limit
        if self.global_counter.0 + 1 > self.global_limit {
            return Err(RateLimitError::GlobalLimitExceeded {
                limit: self.global_limit,
                current: self.global_counter.0 + 1, // What it would be
            });
        }

        // Now check per-node limit
        let entry = self.node_counters.entry(*node_id).or_insert((0, now));

        // Reset counter if window expired
        if now.duration_since(entry.1) >= self.window {
            entry.0 = 0;
            entry.1 = now;
        }

        // Check if incrementing would exceed per-node limit
        if entry.0 + 1 > self.per_node_limit {
            return Err(RateLimitError::PerNodeLimitExceeded {
                node_id: *node_id,
                limit: self.per_node_limit,
                current: entry.0 + 1, // What it would be
            });
        }

        // Both checks passed - increment counters and allow
        entry.0 += 1;
        self.global_counter.0 += 1;

        Ok(())
    }

    /// Get current per-node rate
    pub fn get_node_rate(&self, node_id: &NodeId) -> u32 {
        self.node_counters
            .get(node_id)
            .map(|(count, start)| {
                if Instant::now().duration_since(*start) < self.window {
                    *count
                } else {
                    0
                }
            })
            .unwrap_or(0)
    }

    /// Get current global rate
    pub fn get_global_rate(&self) -> u32 {
        if Instant::now().duration_since(self.global_counter.1) < self.window {
            self.global_counter.0
        } else {
            0
        }
    }

    /// Clear all rate limit counters
    pub fn clear(&mut self) {
        self.node_counters.clear();
        self.global_counter = (0, Instant::now());
    }

    /// Cleanup expired node counters
    pub fn cleanup_expired(&mut self) {
        let now = Instant::now();
        self.node_counters
            .retain(|_, (_, start)| now.duration_since(*start) < self.window);
    }
}

/// Rate limit error
#[derive(Debug, Clone)]
pub enum RateLimitError {
    /// Per-node limit exceeded
    PerNodeLimitExceeded {
        node_id: NodeId,
        limit: u32,
        current: u32,
    },

    /// Global limit exceeded
    GlobalLimitExceeded { limit: u32, current: u32 },
}

impl std::fmt::Display for RateLimitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RateLimitError::PerNodeLimitExceeded {
                node_id,
                limit,
                current,
            } => write!(
                f,
                "Rate limit exceeded for node {}: {}/{} messages/min",
                node_id, current, limit
            ),
            RateLimitError::GlobalLimitExceeded { limit, current } => write!(
                f,
                "Global rate limit exceeded: {}/{} messages/min",
                current, limit
            ),
        }
    }
}

impl std::error::Error for RateLimitError {}

#[cfg(test)]
mod tests {
    use super::*;
    use myriadmesh_protocol::types::NODE_ID_SIZE;

    fn create_test_node_id(byte: u8) -> NodeId {
        NodeId::from_bytes([byte; NODE_ID_SIZE])
    }

    #[test]
    fn test_per_node_limit() {
        let mut limiter = RateLimiter::new(5, 100);
        let node_id = create_test_node_id(1);

        // Should accept first 5 messages
        for _ in 0..5 {
            assert!(limiter.check_rate(&node_id).is_ok());
        }

        // 6th message should fail
        assert!(limiter.check_rate(&node_id).is_err());
    }

    #[test]
    fn test_global_limit() {
        let mut limiter = RateLimiter::new(100, 10);

        let node1 = create_test_node_id(1);
        let node2 = create_test_node_id(2);

        // Use up global limit with multiple nodes
        for _ in 0..5 {
            assert!(limiter.check_rate(&node1).is_ok());
        }

        for _ in 0..5 {
            assert!(limiter.check_rate(&node2).is_ok());
        }

        // 11th message should fail (global limit)
        assert!(limiter.check_rate(&node1).is_err());
    }

    #[test]
    fn test_multiple_nodes() {
        let mut limiter = RateLimiter::new(5, 100);

        let node1 = create_test_node_id(1);
        let node2 = create_test_node_id(2);

        // Each node should have independent limits
        for _ in 0..5 {
            assert!(limiter.check_rate(&node1).is_ok());
        }

        for _ in 0..5 {
            assert!(limiter.check_rate(&node2).is_ok());
        }

        // Both should fail on next message
        assert!(limiter.check_rate(&node1).is_err());
        assert!(limiter.check_rate(&node2).is_err());
    }

    #[test]
    fn test_get_rates() {
        let mut limiter = RateLimiter::new(10, 100);
        let node_id = create_test_node_id(1);

        assert_eq!(limiter.get_node_rate(&node_id), 0);
        assert_eq!(limiter.get_global_rate(), 0);

        limiter.check_rate(&node_id).unwrap();
        limiter.check_rate(&node_id).unwrap();

        assert_eq!(limiter.get_node_rate(&node_id), 2);
        assert_eq!(limiter.get_global_rate(), 2);
    }

    #[test]
    fn test_clear() {
        let mut limiter = RateLimiter::new(5, 100);
        let node_id = create_test_node_id(1);

        for _ in 0..5 {
            limiter.check_rate(&node_id).unwrap();
        }

        assert!(limiter.check_rate(&node_id).is_err());

        limiter.clear();

        // Should work again after clear
        assert!(limiter.check_rate(&node_id).is_ok());
    }

    #[test]
    fn test_cleanup_expired() {
        let mut limiter = RateLimiter::new(10, 100);

        let node1 = create_test_node_id(1);
        let node2 = create_test_node_id(2);

        limiter.check_rate(&node1).unwrap();
        limiter.check_rate(&node2).unwrap();

        assert_eq!(limiter.node_counters.len(), 2);

        // Cleanup shouldn't remove recent entries
        limiter.cleanup_expired();
        assert_eq!(limiter.node_counters.len(), 2);
    }

    #[test]
    fn test_global_limit_checked_first() {
        // SECURITY TEST H12: Verify global limit is checked before per-node tracking
        let mut limiter = RateLimiter::new(100, 10); // High per-node, low global

        let node1 = create_test_node_id(1);
        let node2 = create_test_node_id(2);
        let node3 = create_test_node_id(3);

        // Fill up global limit with node1
        for _ in 0..10 {
            assert!(limiter.check_rate(&node1).is_ok());
        }

        // Global limit should now be exhausted
        assert_eq!(limiter.get_global_rate(), 10);

        // Track how many nodes were tracked before global limit hit
        let nodes_before = limiter.node_counters.len();
        assert_eq!(nodes_before, 1); // Only node1 tracked

        // Try to send from node2 - should fail due to global limit
        // WITHOUT adding node2 to tracking
        let result = limiter.check_rate(&node2);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            RateLimitError::GlobalLimitExceeded { .. }
        ));

        // SECURITY H12: Verify node2 was NOT added to tracking
        // (this prevents resource exhaustion)
        assert_eq!(limiter.node_counters.len(), nodes_before);
        assert!(!limiter.node_counters.contains_key(&node2));

        // Try with node3 too
        let result = limiter.check_rate(&node3);
        assert!(result.is_err());

        // Still no new nodes tracked
        assert_eq!(limiter.node_counters.len(), nodes_before);
        assert!(!limiter.node_counters.contains_key(&node3));
    }

    #[test]
    fn test_no_counter_increment_on_rejection() {
        // SECURITY TEST H12: Verify counters aren't incremented when rate limited
        let mut limiter = RateLimiter::new(5, 20);
        let node = create_test_node_id(1);

        // Use up per-node limit
        for _ in 0..5 {
            limiter.check_rate(&node).unwrap();
        }

        assert_eq!(limiter.get_node_rate(&node), 5);
        assert_eq!(limiter.get_global_rate(), 5);

        // Next attempt should be rejected
        let result = limiter.check_rate(&node);
        assert!(result.is_err());

        // SECURITY H12: Counters should NOT have incremented for rejected request
        assert_eq!(limiter.get_node_rate(&node), 5); // Still 5, not 6
        assert_eq!(limiter.get_global_rate(), 5); // Still 5, not 6
    }

    #[test]
    fn test_global_limit_prevents_node_tracking_dos() {
        // SECURITY TEST H12: Verify global limit prevents DoS via forced node tracking
        let mut limiter = RateLimiter::new(1000, 10); // Very high per-node, low global

        // Exhaust global limit with a single node
        let legit_node = create_test_node_id(1);
        for _ in 0..10 {
            limiter.check_rate(&legit_node).unwrap();
        }

        // Attacker tries to force tracking of many nodes
        let mut attacker_nodes = Vec::new();
        for i in 2..1002 {
            // Try 1000 different nodes
            attacker_nodes.push(create_test_node_id(i as u8));
        }

        for attacker_node in &attacker_nodes {
            let result = limiter.check_rate(attacker_node);
            // All should be rejected due to global limit
            assert!(result.is_err());
        }

        // SECURITY H12: None of the attacker nodes should have been tracked
        // Only the legitimate node should be in the map
        assert_eq!(
            limiter.node_counters.len(),
            1,
            "Attacker forced tracking of {} nodes",
            limiter.node_counters.len() - 1
        );
        assert!(limiter.node_counters.contains_key(&legit_node));
    }

    #[test]
    fn test_boundary_conditions() {
        // SECURITY TEST H12: Test exact limit boundaries
        let mut limiter = RateLimiter::new(5, 10);
        let node1 = create_test_node_id(1);
        let node2 = create_test_node_id(2);

        // Exactly at global limit (10th message) - use two nodes to avoid per-node limit
        for _ in 0..5 {
            assert!(limiter.check_rate(&node1).is_ok());
        }
        for _ in 0..5 {
            assert!(limiter.check_rate(&node2).is_ok());
        }

        // 11th should fail (global limit)
        assert!(limiter.check_rate(&node1).is_err());

        // Clear and test per-node boundary
        limiter.clear();
        for _ in 0..5 {
            assert!(limiter.check_rate(&node1).is_ok());
        }

        // 6th should fail (per-node limit)
        assert!(limiter.check_rate(&node1).is_err());
    }

    #[test]
    fn test_error_messages() {
        // SECURITY TEST H12: Verify error messages are informative
        let mut limiter = RateLimiter::new(2, 10);
        let node = create_test_node_id(1);

        // Hit per-node limit
        limiter.check_rate(&node).unwrap();
        limiter.check_rate(&node).unwrap();
        let err = limiter.check_rate(&node).unwrap_err();

        match err {
            RateLimitError::PerNodeLimitExceeded {
                node_id,
                limit,
                current,
            } => {
                assert_eq!(node_id, node);
                assert_eq!(limit, 2);
                assert_eq!(current, 3); // Would be 3
            }
            _ => panic!("Expected PerNodeLimitExceeded"),
        }

        // Clear and hit global limit with high per-node limit
        let mut limiter2 = RateLimiter::new(100, 5);
        for _ in 0..5 {
            limiter2.check_rate(&node).unwrap();
        }
        let err = limiter2.check_rate(&node).unwrap_err();

        match err {
            RateLimitError::GlobalLimitExceeded { limit, current } => {
                assert_eq!(limit, 5);
                assert_eq!(current, 6); // Would be 6
            }
            _ => panic!("Expected GlobalLimitExceeded"),
        }
    }
}
