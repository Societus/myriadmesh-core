//! Message deduplication cache

use myriadmesh_protocol::MessageId;
use std::collections::{HashMap, VecDeque};
use std::time::{SystemTime, UNIX_EPOCH};

/// Get current timestamp
fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// LRU cache for message deduplication
#[derive(Debug)]
pub struct DeduplicationCache {
    /// Map of message ID to timestamp
    entries: HashMap<MessageId, u64>,

    /// LRU queue for eviction
    lru_queue: VecDeque<MessageId>,

    /// Maximum cache size
    max_size: usize,

    /// TTL for entries (seconds)
    ttl_secs: u64,
}

impl DeduplicationCache {
    /// Create a new deduplication cache
    pub fn new(max_size: usize, ttl_secs: u64) -> Self {
        DeduplicationCache {
            entries: HashMap::with_capacity(max_size),
            lru_queue: VecDeque::with_capacity(max_size),
            max_size,
            ttl_secs,
        }
    }

    /// Check if a message has been seen
    pub fn has_seen(&self, message_id: &MessageId) -> bool {
        if let Some(&seen_at) = self.entries.get(message_id) {
            // Check if entry is still valid (not expired)
            let age = now().saturating_sub(seen_at);
            age < self.ttl_secs
        } else {
            false
        }
    }

    /// Mark a message as seen
    pub fn mark_seen(&mut self, message_id: MessageId) {
        let current_time = now();

        // If already exists, update timestamp and move to back of LRU
        if let std::collections::hash_map::Entry::Occupied(mut e) = self.entries.entry(message_id) {
            e.insert(current_time);

            // Remove from current position in LRU
            if let Some(pos) = self.lru_queue.iter().position(|id| id == &message_id) {
                self.lru_queue.remove(pos);
            }

            // Add to back (most recently used)
            self.lru_queue.push_back(message_id);
            return;
        }

        // If cache is full, evict oldest entry
        if self.entries.len() >= self.max_size {
            if let Some(oldest_id) = self.lru_queue.pop_front() {
                self.entries.remove(&oldest_id);
            }
        }

        // Add new entry
        self.entries.insert(message_id, current_time);
        self.lru_queue.push_back(message_id);
    }

    /// Remove expired entries
    pub fn cleanup_expired(&mut self) -> usize {
        let current_time = now();
        let mut removed = 0;

        // Find expired entries
        let expired: Vec<MessageId> = self
            .entries
            .iter()
            .filter_map(|(id, &seen_at)| {
                let age = current_time.saturating_sub(seen_at);
                if age >= self.ttl_secs {
                    Some(*id)
                } else {
                    None
                }
            })
            .collect();

        // Remove expired entries
        for id in expired {
            self.entries.remove(&id);

            // Remove from LRU queue
            if let Some(pos) = self.lru_queue.iter().position(|i| i == &id) {
                self.lru_queue.remove(pos);
            }

            removed += 1;
        }

        removed
    }

    /// Get number of entries in cache
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Check if cache is empty
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Clear all entries
    pub fn clear(&mut self) {
        self.entries.clear();
        self.lru_queue.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_message_id(byte: u8) -> MessageId {
        MessageId::from_bytes([byte; 16])
    }

    #[test]
    fn test_new_cache() {
        let cache = DeduplicationCache::new(100, 3600);
        assert_eq!(cache.len(), 0);
        assert!(cache.is_empty());
    }

    #[test]
    fn test_mark_and_check_seen() {
        let mut cache = DeduplicationCache::new(100, 3600);
        let id = create_test_message_id(1);

        assert!(!cache.has_seen(&id));

        cache.mark_seen(id);
        assert!(cache.has_seen(&id));
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn test_duplicate_marking() {
        let mut cache = DeduplicationCache::new(100, 3600);
        let id = create_test_message_id(1);

        cache.mark_seen(id);
        cache.mark_seen(id); // Mark again

        // Should still only have 1 entry
        assert_eq!(cache.len(), 1);
        assert!(cache.has_seen(&id));
    }

    #[test]
    fn test_lru_eviction() {
        let mut cache = DeduplicationCache::new(3, 3600);

        let id1 = create_test_message_id(1);
        let id2 = create_test_message_id(2);
        let id3 = create_test_message_id(3);
        let id4 = create_test_message_id(4);

        cache.mark_seen(id1);
        cache.mark_seen(id2);
        cache.mark_seen(id3);

        assert_eq!(cache.len(), 3);

        // Add 4th entry, should evict oldest (id1)
        cache.mark_seen(id4);

        assert_eq!(cache.len(), 3);
        assert!(!cache.has_seen(&id1)); // Evicted
        assert!(cache.has_seen(&id2));
        assert!(cache.has_seen(&id3));
        assert!(cache.has_seen(&id4));
    }

    #[test]
    fn test_expired_entries() {
        let mut cache = DeduplicationCache::new(100, 0); // 0 second TTL

        let id = create_test_message_id(1);
        cache.mark_seen(id);

        // Entry should be immediately expired
        assert!(!cache.has_seen(&id));

        // Cleanup should remove it
        let removed = cache.cleanup_expired();
        assert_eq!(removed, 1);
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn test_clear() {
        let mut cache = DeduplicationCache::new(100, 3600);

        cache.mark_seen(create_test_message_id(1));
        cache.mark_seen(create_test_message_id(2));

        assert_eq!(cache.len(), 2);

        cache.clear();
        assert_eq!(cache.len(), 0);
        assert!(cache.is_empty());
    }

    #[test]
    fn test_lru_update_on_access() {
        let mut cache = DeduplicationCache::new(2, 3600);

        let id1 = create_test_message_id(1);
        let id2 = create_test_message_id(2);
        let id3 = create_test_message_id(3);

        cache.mark_seen(id1);
        cache.mark_seen(id2);

        // Access id1 again (should move to back of LRU)
        cache.mark_seen(id1);

        // Add id3, should evict id2 (not id1)
        cache.mark_seen(id3);

        assert!(cache.has_seen(&id1));
        assert!(!cache.has_seen(&id2)); // Evicted
        assert!(cache.has_seen(&id3));
    }
}
