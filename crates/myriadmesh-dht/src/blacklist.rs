//! DHT Node Blacklist with time-based expiration
//!
//! This module implements a security mechanism to prevent interaction with
//! malicious, non-responsive, or otherwise problematic nodes.

use myriadmesh_protocol::NodeId;
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

/// Get current timestamp in seconds
fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// Reason for blacklisting a node
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlacklistReason {
    /// Node failed to respond to multiple requests
    NonResponsive,

    /// Node sent invalid responses
    InvalidResponse,

    /// Node attempted sybil attack
    SybilAttack,

    /// Node sent malformed messages
    MalformedMessage,

    /// Node exceeded rate limit
    RateLimitExceeded,

    /// Node provided invalid proof-of-work
    InvalidProofOfWork,

    /// Manual blacklist (administrative)
    Manual,
}

impl BlacklistReason {
    /// Get human-readable description
    pub fn description(&self) -> &'static str {
        match self {
            BlacklistReason::NonResponsive => "Non-responsive node",
            BlacklistReason::InvalidResponse => "Invalid response",
            BlacklistReason::SybilAttack => "Sybil attack attempt",
            BlacklistReason::MalformedMessage => "Malformed message",
            BlacklistReason::RateLimitExceeded => "Rate limit exceeded",
            BlacklistReason::InvalidProofOfWork => "Invalid proof-of-work",
            BlacklistReason::Manual => "Manual blacklist",
        }
    }
}

/// Blacklist entry for a node
#[derive(Debug, Clone)]
pub struct BlacklistEntry {
    /// The blacklisted node ID
    pub node_id: NodeId,

    /// Reason for blacklisting
    pub reason: BlacklistReason,

    /// Time the node was blacklisted
    pub blacklisted_at: u64,

    /// Time the blacklist entry expires
    /// Set to u64::MAX for permanent blacklist
    pub expires_at: u64,

    /// Number of times this node violated rules
    pub violation_count: u32,

    /// Optional additional details
    pub details: Option<String>,
}

impl BlacklistEntry {
    /// Create a new blacklist entry with default TTL
    pub fn new(node_id: NodeId, reason: BlacklistReason) -> Self {
        let now = now();
        let default_ttl = 24 * 3600; // 24 hours default

        BlacklistEntry {
            node_id,
            reason,
            blacklisted_at: now,
            expires_at: now + default_ttl,
            violation_count: 1,
            details: None,
        }
    }

    /// Create a permanent blacklist entry (no expiration)
    pub fn permanent(node_id: NodeId, reason: BlacklistReason) -> Self {
        BlacklistEntry {
            node_id,
            reason,
            blacklisted_at: now(),
            expires_at: u64::MAX,
            violation_count: 1,
            details: None,
        }
    }

    /// Create a blacklist entry with custom TTL
    pub fn with_ttl(node_id: NodeId, reason: BlacklistReason, ttl_secs: u64) -> Self {
        let now = now();
        BlacklistEntry {
            node_id,
            reason,
            blacklisted_at: now,
            expires_at: now + ttl_secs,
            violation_count: 1,
            details: None,
        }
    }

    /// Check if this entry has expired
    pub fn is_expired(&self) -> bool {
        now() >= self.expires_at
    }

    /// Get remaining blacklist duration in seconds (0 if expired)
    pub fn time_remaining(&self) -> u64 {
        let current = now();
        if current >= self.expires_at {
            0
        } else {
            self.expires_at - current
        }
    }

    /// Increment violation count
    pub fn increment_violations(&mut self) {
        self.violation_count = self.violation_count.saturating_add(1);
    }

    /// Set additional details
    pub fn with_details(mut self, details: String) -> Self {
        self.details = Some(details);
        self
    }
}

/// DHT Node Blacklist
///
/// SECURITY M2: Malicious Node Protection
/// Maintains a blacklist of nodes to prevent interaction with:
/// - Non-responsive nodes
/// - Nodes with invalid responses
/// - Sybil attackers
/// - Nodes with malformed messages
#[derive(Debug, Clone, Default)]
pub struct NodeBlacklist {
    /// Map of node ID to blacklist entry
    entries: HashMap<NodeId, BlacklistEntry>,

    /// Statistics
    stats: BlacklistStats,
}

/// Blacklist statistics
#[derive(Debug, Clone, Copy, Default)]
pub struct BlacklistStats {
    /// Total nodes blacklisted
    pub total_blacklisted: u64,

    /// Currently active blacklist entries
    pub active_entries: usize,

    /// Expired entries (removed from list)
    pub expired_entries: u64,

    /// Entries by reason
    pub non_responsive: u64,
    pub invalid_response: u64,
    pub sybil_attack: u64,
    pub malformed_message: u64,
    pub rate_limit_exceeded: u64,
    pub invalid_pow: u64,
    pub manual: u64,
}

impl NodeBlacklist {
    /// Create a new blacklist
    pub fn new() -> Self {
        NodeBlacklist {
            entries: HashMap::new(),
            stats: BlacklistStats::default(),
        }
    }

    /// Add a node to the blacklist
    ///
    /// Returns true if the node was newly added, false if already blacklisted
    pub fn add(&mut self, node_id: NodeId, reason: BlacklistReason) -> bool {
        self.add_entry(BlacklistEntry::new(node_id, reason))
    }

    /// Add a node to the blacklist with custom TTL
    pub fn add_with_ttl(&mut self, node_id: NodeId, reason: BlacklistReason, ttl_secs: u64) -> bool {
        self.add_entry(BlacklistEntry::with_ttl(node_id, reason, ttl_secs))
    }

    /// Add a permanent blacklist entry
    pub fn add_permanent(&mut self, node_id: NodeId, reason: BlacklistReason) -> bool {
        self.add_entry(BlacklistEntry::permanent(node_id, reason))
    }

    /// Add a complete blacklist entry
    fn add_entry(&mut self, mut entry: BlacklistEntry) -> bool {
        let is_new = !self.entries.contains_key(&entry.node_id);

        if is_new {
            self.stats.total_blacklisted += 1;
            self.update_reason_stats(entry.reason, 1);
            self.entries.insert(entry.node_id, entry);
        } else if let Some(existing) = self.entries.get_mut(&entry.node_id) {
            // Increment violation count for existing entry, keep original entry
            existing.increment_violations();
        }

        self.stats.active_entries = self.entries.len();
        is_new
    }

    /// Remove a node from the blacklist
    pub fn remove(&mut self, node_id: &NodeId) -> Option<BlacklistEntry> {
        let removed = self.entries.remove(node_id);
        if removed.is_some() {
            self.stats.active_entries = self.entries.len();
        }
        removed
    }

    /// Check if a node is blacklisted (and not expired)
    pub fn is_blacklisted(&self, node_id: &NodeId) -> bool {
        if let Some(entry) = self.entries.get(node_id) {
            !entry.is_expired()
        } else {
            false
        }
    }

    /// Get a blacklist entry if it exists and is not expired
    pub fn get(&self, node_id: &NodeId) -> Option<&BlacklistEntry> {
        self.entries.get(node_id).filter(|e| !e.is_expired())
    }

    /// Clean up expired entries
    ///
    /// Returns the number of entries removed
    pub fn cleanup_expired(&mut self) -> usize {
        let initial_count = self.entries.len();

        self.entries.retain(|_, entry| !entry.is_expired());

        let removed = initial_count - self.entries.len();
        self.stats.expired_entries += removed as u64;
        self.stats.active_entries = self.entries.len();

        removed
    }

    /// Get all non-expired blacklist entries
    pub fn get_all_entries(&self) -> Vec<&BlacklistEntry> {
        self.entries
            .values()
            .filter(|e| !e.is_expired())
            .collect()
    }

    /// Get statistics
    pub fn stats(&self) -> BlacklistStats {
        BlacklistStats {
            active_entries: self.entries.len(),
            ..self.stats
        }
    }

    /// Clear all blacklist entries
    pub fn clear(&mut self) {
        self.entries.clear();
        self.stats = BlacklistStats::default();
    }

    /// Update stats for a reason
    fn update_reason_stats(&mut self, reason: BlacklistReason, delta: u64) {
        match reason {
            BlacklistReason::NonResponsive => self.stats.non_responsive += delta,
            BlacklistReason::InvalidResponse => self.stats.invalid_response += delta,
            BlacklistReason::SybilAttack => self.stats.sybil_attack += delta,
            BlacklistReason::MalformedMessage => self.stats.malformed_message += delta,
            BlacklistReason::RateLimitExceeded => self.stats.rate_limit_exceeded += delta,
            BlacklistReason::InvalidProofOfWork => self.stats.invalid_pow += delta,
            BlacklistReason::Manual => self.stats.manual += delta,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use myriadmesh_protocol::types::NODE_ID_SIZE;

    fn create_test_node_id(byte: u8) -> NodeId {
        NodeId::from_bytes([byte; NODE_ID_SIZE])
    }

    #[test]
    fn test_blacklist_entry_creation() {
        let node_id = create_test_node_id(1);
        let entry = BlacklistEntry::new(node_id, BlacklistReason::NonResponsive);

        assert_eq!(entry.node_id, node_id);
        assert_eq!(entry.reason, BlacklistReason::NonResponsive);
        assert_eq!(entry.violation_count, 1);
        assert!(!entry.is_expired());
    }

    #[test]
    fn test_blacklist_entry_expiration() {
        let node_id = create_test_node_id(1);
        let mut entry = BlacklistEntry::new(node_id, BlacklistReason::NonResponsive);

        // Entry with 0 TTL should expire immediately
        entry.expires_at = now() - 1;
        assert!(entry.is_expired());
    }

    #[test]
    fn test_blacklist_entry_time_remaining() {
        let node_id = create_test_node_id(1);
        let entry = BlacklistEntry::with_ttl(node_id, BlacklistReason::NonResponsive, 3600);

        let remaining = entry.time_remaining();
        assert!(remaining > 3500 && remaining <= 3600);
    }

    #[test]
    fn test_blacklist_permanent_entry() {
        let node_id = create_test_node_id(1);
        let entry = BlacklistEntry::permanent(node_id, BlacklistReason::SybilAttack);

        assert!(!entry.is_expired());
        // Permanent entry should have very large time remaining (near u64::MAX)
        assert!(entry.time_remaining() > u64::MAX / 2);
    }

    #[test]
    fn test_blacklist_add() {
        let mut blacklist = NodeBlacklist::new();
        let node_id = create_test_node_id(1);

        let added = blacklist.add(node_id, BlacklistReason::NonResponsive);
        assert!(added);
        assert!(blacklist.is_blacklisted(&node_id));

        // Adding again should return false
        let added_again = blacklist.add(node_id, BlacklistReason::NonResponsive);
        assert!(!added_again);
    }

    #[test]
    fn test_blacklist_is_blacklisted() {
        let mut blacklist = NodeBlacklist::new();
        let node_id = create_test_node_id(1);

        assert!(!blacklist.is_blacklisted(&node_id));

        blacklist.add(node_id, BlacklistReason::InvalidResponse);
        assert!(blacklist.is_blacklisted(&node_id));
    }

    #[test]
    fn test_blacklist_remove() {
        let mut blacklist = NodeBlacklist::new();
        let node_id = create_test_node_id(1);

        blacklist.add(node_id, BlacklistReason::NonResponsive);
        assert!(blacklist.is_blacklisted(&node_id));

        let removed = blacklist.remove(&node_id);
        assert!(removed.is_some());
        assert!(!blacklist.is_blacklisted(&node_id));
    }

    #[test]
    fn test_blacklist_cleanup_expired() {
        let mut blacklist = NodeBlacklist::new();
        let node1 = create_test_node_id(1);
        let node2 = create_test_node_id(2);

        // Add one node with short TTL and another with long TTL
        let mut entry1 = BlacklistEntry::with_ttl(node1, BlacklistReason::NonResponsive, 1);
        entry1.expires_at = now() - 1; // Already expired
        blacklist.add_entry(entry1);

        blacklist.add(node2, BlacklistReason::InvalidResponse);

        assert_eq!(blacklist.stats().active_entries, 2);

        let cleaned = blacklist.cleanup_expired();
        assert_eq!(cleaned, 1);
        assert_eq!(blacklist.stats().active_entries, 1);
    }

    #[test]
    fn test_blacklist_stats() {
        let mut blacklist = NodeBlacklist::new();

        let node1 = create_test_node_id(1);
        let node2 = create_test_node_id(2);
        let node3 = create_test_node_id(3);

        blacklist.add(node1, BlacklistReason::NonResponsive);
        blacklist.add(node2, BlacklistReason::SybilAttack);
        blacklist.add(node3, BlacklistReason::InvalidResponse);

        let stats = blacklist.stats();
        assert_eq!(stats.total_blacklisted, 3);
        assert_eq!(stats.active_entries, 3);
        assert_eq!(stats.non_responsive, 1);
        assert_eq!(stats.sybil_attack, 1);
        assert_eq!(stats.invalid_response, 1);
    }

    #[test]
    fn test_blacklist_violation_count() {
        let mut blacklist = NodeBlacklist::new();
        let node_id = create_test_node_id(1);

        blacklist.add(node_id, BlacklistReason::NonResponsive);
        blacklist.add(node_id, BlacklistReason::NonResponsive);

        let entry = blacklist.get(&node_id).unwrap();
        assert_eq!(entry.violation_count, 2);
    }

    #[test]
    fn test_blacklist_with_details() {
        let node_id = create_test_node_id(1);
        let entry = BlacklistEntry::new(node_id, BlacklistReason::InvalidResponse)
            .with_details("Invalid FIND_NODE response".to_string());

        assert_eq!(entry.details, Some("Invalid FIND_NODE response".to_string()));
    }

    #[test]
    fn test_blacklist_get_all_entries() {
        let mut blacklist = NodeBlacklist::new();

        for i in 1..=5 {
            blacklist.add(create_test_node_id(i), BlacklistReason::NonResponsive);
        }

        let all_entries = blacklist.get_all_entries();
        assert_eq!(all_entries.len(), 5);
    }

    #[test]
    fn test_blacklist_clear() {
        let mut blacklist = NodeBlacklist::new();

        blacklist.add(create_test_node_id(1), BlacklistReason::NonResponsive);
        blacklist.add(create_test_node_id(2), BlacklistReason::InvalidResponse);

        assert_eq!(blacklist.stats().active_entries, 2);

        blacklist.clear();
        assert_eq!(blacklist.stats().active_entries, 0);
    }
}
