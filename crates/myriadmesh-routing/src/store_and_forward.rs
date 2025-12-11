//! Store-and-Forward Integration (F3.1)
//!
//! This module integrates the offline message cache into the routing system:
//! - Caches messages when destinations are offline
//! - Retrieves and delivers cached messages when destinations come online
//! - Manages message expiration and priority-based cleanup
//! - Provides statistics and monitoring capabilities

use crate::offline_cache::OfflineMessageCache;
use myriadmesh_protocol::{message::Message, NodeId};

/// Store-and-forward status
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoreForwardStatus {
    /// Message successfully cached for later delivery
    Cached,
    /// Message was delivered immediately
    Delivered,
    /// Message failed to cache
    CacheFailed(String),
}

/// Store-and-forward statistics
#[derive(Debug, Clone)]
pub struct StoreForwardStats {
    /// Messages cached for offline destinations
    pub messages_cached: u64,
    /// Messages delivered from cache
    pub messages_delivered_from_cache: u64,
    /// Messages expired without delivery
    pub messages_expired: u64,
    /// Current cached message count
    pub current_cached_count: usize,
}

impl Default for StoreForwardStats {
    fn default() -> Self {
        StoreForwardStats {
            messages_cached: 0,
            messages_delivered_from_cache: 0,
            messages_expired: 0,
            current_cached_count: 0,
        }
    }
}

/// Store-and-Forward Manager
///
/// Integrates offline message caching into routing:
/// 1. When transmission fails due to offline node, cache message
/// 2. When node comes online, retrieve and deliver cached messages
/// 3. Automatically clean up expired messages
pub struct StoreAndForwardManager {
    /// Underlying offline message cache
    cache: OfflineMessageCache,
    /// Statistics tracking
    stats: StoreForwardStats,
}

impl StoreAndForwardManager {
    /// Create a new store-and-forward manager
    pub fn new() -> Self {
        StoreAndForwardManager {
            cache: OfflineMessageCache::new(),
            stats: StoreForwardStats::default(),
        }
    }

    /// Create with custom cache limits
    pub fn with_limits(per_node_limit: usize, total_limit: usize) -> Self {
        StoreAndForwardManager {
            cache: OfflineMessageCache::with_limits(per_node_limit, total_limit),
            stats: StoreForwardStats::default(),
        }
    }

    /// F3.1 Integration: Cache message for offline node
    ///
    /// Called when transmission fails because destination is offline
    /// Message is stored with TTL and priority-based expiration
    pub fn cache_for_offline(&mut self, destination: &NodeId, message: Message) -> StoreForwardStatus {
        match self.cache.cache_message(*destination, message.clone(), message.priority) {
            Ok(_) => {
                self.stats.messages_cached += 1;
                self.stats.current_cached_count = self.cache.stats().current_size;
                StoreForwardStatus::Cached
            }
            Err(e) => {
                StoreForwardStatus::CacheFailed(format!("Cache failed: {}", e))
            }
        }
    }

    /// Retrieve cached messages for a node that came online
    ///
    /// Called when a previously offline node becomes reachable
    /// Returns all cached messages for that node
    pub fn retrieve_for_online_node(&mut self, node_id: &NodeId) -> Vec<Message> {
        let messages = self.cache.retrieve_messages(node_id);
        self.stats.messages_delivered_from_cache += messages.len() as u64;
        self.stats.current_cached_count = self.cache.stats().current_size;
        messages
    }

    /// Check if node has cached messages
    pub fn has_cached_messages(&self, node_id: &NodeId) -> bool {
        self.cache.has_messages(node_id)
    }

    /// Get count of cached messages for a node
    pub fn cached_message_count(&self, node_id: &NodeId) -> usize {
        self.cache.message_count(node_id)
    }

    /// Clean up expired messages
    ///
    /// Should be called periodically (e.g., every 5-10 minutes)
    /// Returns number of expired messages removed
    pub fn cleanup_expired_messages(&mut self) -> usize {
        let expired_count = self.cache.cleanup_expired();
        self.stats.messages_expired += expired_count as u64;
        self.stats.current_cached_count = self.cache.stats().current_size;
        expired_count
    }

    /// Get current statistics
    pub fn stats(&self) -> StoreForwardStats {
        StoreForwardStats {
            current_cached_count: self.cache.stats().current_size,
            ..self.stats.clone()
        }
    }

    /// Clear all cached messages
    pub fn clear_all(&mut self) {
        self.cache.clear();
        self.stats.current_cached_count = 0;
    }

    /// Get underlying cache for advanced operations
    pub fn cache(&mut self) -> &mut OfflineMessageCache {
        &mut self.cache
    }
}

impl Default for StoreAndForwardManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use myriadmesh_protocol::types::{NODE_ID_SIZE, Priority};
    use myriadmesh_protocol::MessageType;

    fn create_test_message(src: u8, dst: u8) -> Message {
        let mut src_bytes = [0u8; NODE_ID_SIZE];
        src_bytes[0] = src;
        let mut dst_bytes = [0u8; NODE_ID_SIZE];
        dst_bytes[0] = dst;

        Message::new(
            NodeId::from_bytes(src_bytes),
            NodeId::from_bytes(dst_bytes),
            MessageType::Data,
            b"test message".to_vec(),
        )
        .unwrap()
        .with_priority(Priority::normal())
    }

    fn create_test_node_id(id: u8) -> NodeId {
        let mut bytes = [0u8; NODE_ID_SIZE];
        bytes[0] = id;
        NodeId::from_bytes(bytes)
    }

    #[test]
    fn test_store_forward_creation() {
        let manager = StoreAndForwardManager::new();
        let stats = manager.stats();

        assert_eq!(stats.messages_cached, 0);
        assert_eq!(stats.messages_delivered_from_cache, 0);
        assert_eq!(stats.current_cached_count, 0);
    }

    #[test]
    fn test_cache_for_offline_node() {
        let mut manager = StoreAndForwardManager::new();
        let node_id = create_test_node_id(1);
        let message = create_test_message(2, 1);

        let status = manager.cache_for_offline(&node_id, message);

        assert_eq!(status, StoreForwardStatus::Cached);
        assert_eq!(manager.stats().messages_cached, 1);
        assert!(manager.has_cached_messages(&node_id));
    }

    #[test]
    fn test_retrieve_for_online_node() {
        let mut manager = StoreAndForwardManager::new();
        let node_id = create_test_node_id(1);
        let message1 = create_test_message(2, 1);
        let message2 = create_test_message(3, 1);

        manager.cache_for_offline(&node_id, message1.clone());
        manager.cache_for_offline(&node_id, message2.clone());

        assert_eq!(manager.cached_message_count(&node_id), 2);

        let retrieved = manager.retrieve_for_online_node(&node_id);

        assert_eq!(retrieved.len(), 2);
        assert_eq!(manager.stats().messages_delivered_from_cache, 2);
        assert!(!manager.has_cached_messages(&node_id));
    }

    #[test]
    fn test_cache_multiple_nodes() {
        let mut manager = StoreAndForwardManager::new();
        let node1 = create_test_node_id(1);
        let node2 = create_test_node_id(2);

        let msg1 = create_test_message(10, 1);
        let msg2 = create_test_message(10, 2);
        let msg3 = create_test_message(10, 1);

        manager.cache_for_offline(&node1, msg1);
        manager.cache_for_offline(&node2, msg2);
        manager.cache_for_offline(&node1, msg3);

        assert_eq!(manager.cached_message_count(&node1), 2);
        assert_eq!(manager.cached_message_count(&node2), 1);

        let retrieved1 = manager.retrieve_for_online_node(&node1);
        assert_eq!(retrieved1.len(), 2);

        let retrieved2 = manager.retrieve_for_online_node(&node2);
        assert_eq!(retrieved2.len(), 1);
    }

    #[test]
    fn test_stats_tracking() {
        let mut manager = StoreAndForwardManager::new();
        let node_id = create_test_node_id(1);

        let msg1 = create_test_message(2, 1);
        let msg2 = create_test_message(3, 1);

        manager.cache_for_offline(&node_id, msg1);
        let stats = manager.stats();
        assert_eq!(stats.messages_cached, 1);

        manager.cache_for_offline(&node_id, msg2);
        let stats = manager.stats();
        assert_eq!(stats.messages_cached, 2);

        let _retrieved = manager.retrieve_for_online_node(&node_id);
        let stats = manager.stats();
        assert_eq!(stats.messages_delivered_from_cache, 2);
    }

    #[test]
    fn test_clear_all() {
        let mut manager = StoreAndForwardManager::new();
        let node_id = create_test_node_id(1);

        manager.cache_for_offline(&node_id, create_test_message(2, 1));
        manager.cache_for_offline(&node_id, create_test_message(3, 1));

        assert!(manager.has_cached_messages(&node_id));

        manager.clear_all();

        assert!(!manager.has_cached_messages(&node_id));
        assert_eq!(manager.stats().current_cached_count, 0);
    }

    #[test]
    fn test_with_custom_limits() {
        let manager = StoreAndForwardManager::with_limits(50, 500);

        assert_eq!(manager.stats().current_cached_count, 0);
    }

    #[test]
    fn test_multiple_offline_nodes() {
        let mut manager = StoreAndForwardManager::new();

        // Cache messages for 5 different nodes
        for node_num in 1..=5 {
            let node_id = create_test_node_id(node_num);
            for msg_num in 1..=3 {
                let msg = create_test_message(10, node_num);
                let status = manager.cache_for_offline(&node_id, msg);
                assert_eq!(status, StoreForwardStatus::Cached);
            }
        }

        let stats = manager.stats();
        assert_eq!(stats.messages_cached, 15); // 5 nodes * 3 messages
        assert_eq!(stats.current_cached_count, 15);

        // Retrieve from each node
        let mut total_retrieved = 0;
        for node_num in 1..=5 {
            let node_id = create_test_node_id(node_num);
            let retrieved = manager.retrieve_for_online_node(&node_id);
            total_retrieved += retrieved.len();
        }

        assert_eq!(total_retrieved, 15);
        let stats = manager.stats();
        assert_eq!(stats.messages_delivered_from_cache, 15);
    }

    #[test]
    fn test_store_forward_workflow() {
        let mut manager = StoreAndForwardManager::new();
        let offline_node = create_test_node_id(5);

        // Step 1: Node goes offline, cache messages
        let msg1 = create_test_message(1, 5);
        let msg2 = create_test_message(2, 5);

        manager.cache_for_offline(&offline_node, msg1);
        manager.cache_for_offline(&offline_node, msg2);

        assert_eq!(manager.stats().messages_cached, 2);
        assert!(manager.has_cached_messages(&offline_node));

        // Step 2: Node comes back online, retrieve messages
        let messages = manager.retrieve_for_online_node(&offline_node);

        assert_eq!(messages.len(), 2);
        assert_eq!(manager.stats().messages_delivered_from_cache, 2);
        assert!(!manager.has_cached_messages(&offline_node));
    }

    #[test]
    fn test_cleanup_expired() {
        let mut manager = StoreAndForwardManager::new();
        let node_id = create_test_node_id(1);

        // Cache a message
        manager.cache_for_offline(&node_id, create_test_message(2, 1));
        assert_eq!(manager.stats().current_cached_count, 1);

        // Cleanup should not remove fresh message
        let expired = manager.cleanup_expired_messages();
        assert_eq!(expired, 0); // Message not expired yet
    }
}
