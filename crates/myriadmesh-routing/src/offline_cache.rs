//! Store-and-forward message cache for offline nodes
//!
//! Implements message caching for nodes that are temporarily unreachable.
//! Messages are stored with TTL-based expiration and priority-based eviction.

use crate::RoutingError;
use myriadmesh_protocol::{message::Message, types::Priority, NodeId};
use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

/// Maximum messages to cache per destination node
const DEFAULT_PER_NODE_LIMIT: usize = 100;

/// Maximum total cached messages across all destinations
const DEFAULT_TOTAL_LIMIT: usize = 10_000;

/// Default TTL for cached messages based on priority
fn default_ttl_for_priority(priority: Priority) -> Duration {
    let value = priority.as_u8();
    if value >= Priority::EMERGENCY_MIN {
        Duration::from_secs(86400 * 7) // 7 days
    } else if value >= Priority::HIGH_MIN {
        Duration::from_secs(86400 * 5) // 5 days
    } else if value >= Priority::NORMAL_MIN {
        Duration::from_secs(86400 * 3) // 3 days
    } else if value >= Priority::LOW_MIN {
        Duration::from_secs(86400) // 1 day
    } else {
        Duration::from_secs(3600 * 12) // 12 hours (background)
    }
}

/// A cached message with metadata
#[derive(Debug, Clone)]
struct CachedMessage {
    message: Message,
    cached_at: Instant,
    ttl: Duration,
    priority: Priority,
}

impl CachedMessage {
    fn new(message: Message, priority: Priority) -> Self {
        Self {
            message,
            cached_at: Instant::now(),
            ttl: default_ttl_for_priority(priority),
            priority,
        }
    }

    fn is_expired(&self) -> bool {
        self.cached_at.elapsed() > self.ttl
    }

    #[allow(dead_code)]
    fn remaining_ttl(&self) -> Option<Duration> {
        self.ttl.checked_sub(self.cached_at.elapsed())
    }
}

/// Per-destination message queue
#[derive(Debug)]
struct DestinationQueue {
    messages: VecDeque<CachedMessage>,
    max_capacity: usize,
}

impl DestinationQueue {
    fn new(max_capacity: usize) -> Self {
        Self {
            messages: VecDeque::with_capacity(max_capacity),
            max_capacity,
        }
    }

    /// Add a message to the queue
    fn push(&mut self, cached_msg: CachedMessage) -> Result<(), RoutingError> {
        // Remove expired messages first
        self.evict_expired();

        // Check capacity
        if self.messages.len() >= self.max_capacity {
            // Try to evict lowest priority message
            self.evict_lowest_priority();
        }

        // Still at capacity? Return error
        if self.messages.len() >= self.max_capacity {
            return Err(RoutingError::QueueFull(
                "Destination queue at capacity".to_string(),
            ));
        }

        // Insert message maintaining priority order (highest priority first)
        let insert_pos = self
            .messages
            .iter()
            .position(|m| m.priority < cached_msg.priority)
            .unwrap_or(self.messages.len());

        self.messages.insert(insert_pos, cached_msg);
        Ok(())
    }

    /// Remove and return all messages for delivery
    fn drain_all(&mut self) -> Vec<Message> {
        self.evict_expired();
        self.messages
            .drain(..)
            .map(|cached| cached.message)
            .collect()
    }

    /// Remove expired messages
    fn evict_expired(&mut self) {
        self.messages.retain(|msg| !msg.is_expired());
    }

    /// Remove the lowest priority message
    fn evict_lowest_priority(&mut self) {
        if let Some(pos) = self
            .messages
            .iter()
            .enumerate()
            .min_by_key(|(_, msg)| msg.priority.as_u8())
            .map(|(i, _)| i)
        {
            self.messages.remove(pos);
        }
    }

    /// Get number of cached messages
    fn len(&self) -> usize {
        self.messages.len()
    }

    /// Check if queue is empty
    fn is_empty(&self) -> bool {
        self.messages.is_empty()
    }
}

/// Offline message cache
///
/// Stores messages for offline or unreachable nodes with:
/// - TTL-based expiration per priority level
/// - Per-destination capacity limits
/// - Global capacity limits
/// - Priority-based eviction
pub struct OfflineMessageCache {
    /// Messages indexed by destination NodeId
    queues: HashMap<NodeId, DestinationQueue>,

    /// Maximum messages per destination
    per_node_limit: usize,

    /// Maximum total cached messages
    total_limit: usize,

    /// Statistics
    stats: CacheStats,
}

/// Cache statistics
#[derive(Debug, Default, Clone)]
pub struct CacheStats {
    pub total_cached: u64,
    pub total_delivered: u64,
    pub total_expired: u64,
    pub total_evicted: u64,
    pub current_size: usize,
    pub destinations_count: usize,
}

impl OfflineMessageCache {
    /// Create a new offline message cache
    pub fn new() -> Self {
        Self::with_limits(DEFAULT_PER_NODE_LIMIT, DEFAULT_TOTAL_LIMIT)
    }

    /// Create a cache with custom limits
    pub fn with_limits(per_node_limit: usize, total_limit: usize) -> Self {
        Self {
            queues: HashMap::new(),
            per_node_limit,
            total_limit,
            stats: CacheStats::default(),
        }
    }

    /// Cache a message for an offline destination
    ///
    /// # Arguments
    /// * `destination` - The offline node ID
    /// * `message` - The message to cache
    /// * `priority` - Message priority for TTL and eviction
    ///
    /// # Errors
    /// Returns error if cache is full or destination queue is at capacity
    pub fn cache_message(
        &mut self,
        destination: NodeId,
        message: Message,
        priority: Priority,
    ) -> Result<(), RoutingError> {
        // Check global capacity
        if self.current_size() >= self.total_limit {
            // Try cleanup first
            self.cleanup_expired();

            if self.current_size() >= self.total_limit {
                self.stats.total_evicted += 1;
                return Err(RoutingError::CacheFull);
            }
        }

        // Get or create destination queue
        let queue = self
            .queues
            .entry(destination)
            .or_insert_with(|| DestinationQueue::new(self.per_node_limit));

        // Cache the message
        let cached_msg = CachedMessage::new(message, priority);
        queue.push(cached_msg)?;

        self.stats.total_cached += 1;
        self.update_stats();

        Ok(())
    }

    /// Retrieve all cached messages for a destination (node came online)
    ///
    /// # Arguments
    /// * `destination` - The node that came online
    ///
    /// # Returns
    /// Vector of cached messages, or empty vec if none cached
    pub fn retrieve_messages(&mut self, destination: &NodeId) -> Vec<Message> {
        if let Some(mut queue) = self.queues.remove(destination) {
            let messages = queue.drain_all();
            self.stats.total_delivered += messages.len() as u64;
            self.update_stats();
            messages
        } else {
            Vec::new()
        }
    }

    /// Check if any messages are cached for a destination
    pub fn has_messages(&self, destination: &NodeId) -> bool {
        self.queues
            .get(destination)
            .map(|q| !q.is_empty())
            .unwrap_or(false)
    }

    /// Get number of cached messages for a destination
    pub fn message_count(&self, destination: &NodeId) -> usize {
        self.queues.get(destination).map(|q| q.len()).unwrap_or(0)
    }

    /// Clean up expired messages across all destinations
    pub fn cleanup_expired(&mut self) -> usize {
        let mut expired_count = 0;

        // Clean each queue
        self.queues.retain(|_, queue| {
            let before = queue.len();
            queue.evict_expired();
            expired_count += before - queue.len();
            !queue.is_empty()
        });

        self.stats.total_expired += expired_count as u64;
        self.update_stats();

        expired_count
    }

    /// Get current cache statistics
    pub fn stats(&self) -> &CacheStats {
        &self.stats
    }

    /// Get current total number of cached messages
    fn current_size(&self) -> usize {
        self.queues.values().map(|q| q.len()).sum()
    }

    /// Update statistics
    fn update_stats(&mut self) {
        self.stats.current_size = self.current_size();
        self.stats.destinations_count = self.queues.len();
    }

    /// Clear all cached messages (for testing/shutdown)
    pub fn clear(&mut self) {
        self.queues.clear();
        self.stats.current_size = 0;
        self.stats.destinations_count = 0;
    }
}

impl Default for OfflineMessageCache {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use myriadmesh_protocol::{message::MessageId, types::NODE_ID_SIZE};

    fn create_test_node_id(value: u8) -> NodeId {
        let mut bytes = [value; NODE_ID_SIZE];
        bytes[0] = value; // Make them unique
        NodeId::from_bytes(bytes)
    }

    fn create_test_message(payload: &[u8]) -> Message {
        let source = create_test_node_id(1);
        let destination = create_test_node_id(2);
        let id = MessageId::generate(&source, &destination, payload, 0, 0);

        Message {
            id,
            source,
            destination,
            payload: payload.to_vec(),
            timestamp: 0,
            sequence: 0,
            ttl: 10,
            priority: Priority::normal(),
            message_type: myriadmesh_protocol::MessageType::Data,
            emergency_realm: None,
        }
    }

    #[test]
    fn test_cache_and_retrieve() {
        let mut cache = OfflineMessageCache::new();
        let destination = create_test_node_id(2);
        let message = create_test_message(b"test");

        // Cache message
        cache
            .cache_message(destination, message.clone(), Priority::normal())
            .unwrap();

        assert_eq!(cache.message_count(&destination), 1);
        assert!(cache.has_messages(&destination));

        // Retrieve messages
        let messages = cache.retrieve_messages(&destination);
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].payload, message.payload);

        // Queue should be empty now
        assert!(!cache.has_messages(&destination));
    }

    #[test]
    fn test_per_node_limit() {
        let mut cache = OfflineMessageCache::with_limits(3, 100);
        let destination = create_test_node_id(2);

        // Cache 3 messages (at limit)
        for i in 0..3 {
            let message = create_test_message(&[i]);
            cache
                .cache_message(destination, message, Priority::normal())
                .unwrap();
        }

        assert_eq!(cache.message_count(&destination), 3);

        // 4th message should succeed by evicting lowest priority
        let message = create_test_message(b"fourth");
        cache
            .cache_message(destination, message, Priority::high())
            .unwrap();

        assert_eq!(cache.message_count(&destination), 3);
    }

    #[test]
    fn test_priority_ordering() {
        let mut cache = OfflineMessageCache::new();
        let destination = create_test_node_id(2);

        // Cache messages with different priorities
        cache
            .cache_message(destination, create_test_message(b"low"), Priority::low())
            .unwrap();
        cache
            .cache_message(
                destination,
                create_test_message(b"emergency"),
                Priority::emergency(),
            )
            .unwrap();
        cache
            .cache_message(
                destination,
                create_test_message(b"normal"),
                Priority::normal(),
            )
            .unwrap();

        // Retrieve and check order (emergency should be first)
        let messages = cache.retrieve_messages(&destination);
        assert_eq!(messages.len(), 3);
        assert_eq!(messages[0].payload, b"emergency");
    }

    #[test]
    fn test_global_limit() {
        let mut cache = OfflineMessageCache::with_limits(10, 5);

        // Cache messages to different destinations
        for i in 0..5 {
            let destination = create_test_node_id(i + 10);
            cache
                .cache_message(destination, create_test_message(&[i]), Priority::normal())
                .unwrap();
        }

        assert_eq!(cache.current_size(), 5);

        // 6th message should fail (at global limit)
        let result = cache.cache_message(
            create_test_node_id(20),
            create_test_message(b"sixth"),
            Priority::normal(),
        );

        assert!(result.is_err());
    }

    #[test]
    fn test_cleanup_expired() {
        let mut cache = OfflineMessageCache::new();
        let destination = create_test_node_id(2);

        // Create a message that's already expired (we'll need to manipulate the cache)
        let mut cached = CachedMessage::new(create_test_message(b"test"), Priority::background());
        cached.cached_at = Instant::now() - Duration::from_secs(86400); // 1 day ago
        cached.ttl = Duration::from_secs(3600); // 1 hour TTL

        // Manually insert
        let mut queue = DestinationQueue::new(10);
        queue.messages.push_back(cached);
        cache.queues.insert(destination, queue);

        assert_eq!(cache.message_count(&destination), 1);

        // Cleanup should remove it
        let expired = cache.cleanup_expired();
        assert_eq!(expired, 1);
        assert_eq!(cache.message_count(&destination), 0);
    }

    #[test]
    fn test_stats_tracking() {
        let mut cache = OfflineMessageCache::new();
        let destination = create_test_node_id(2);

        // Cache a message
        cache
            .cache_message(
                destination,
                create_test_message(b"test"),
                Priority::normal(),
            )
            .unwrap();

        let stats = cache.stats();
        assert_eq!(stats.total_cached, 1);
        assert_eq!(stats.current_size, 1);
        assert_eq!(stats.destinations_count, 1);

        // Retrieve messages
        cache.retrieve_messages(&destination);

        let stats = cache.stats();
        assert_eq!(stats.total_delivered, 1);
        assert_eq!(stats.current_size, 0);
        assert_eq!(stats.destinations_count, 0);
    }
}
