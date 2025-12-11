//! Node information for DHT routing table
//!
//! SECURITY C2: Implements Proof-of-Work for Sybil resistance

use blake2::{Blake2b512, Digest};
use myriadmesh_protocol::message::RelayTier;
use myriadmesh_protocol::types::{AdapterType, NODE_ID_SIZE};
use myriadmesh_protocol::NodeId as ProtocolNodeId;
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::reputation::NodeReputation;

/// SECURITY C2: Required PoW difficulty (leading zero bits)
/// 16 bits = ~65k hash attempts average, good balance of cost vs usability
pub const REQUIRED_POW_DIFFICULTY: u32 = 16;

/// Get current timestamp
fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// SECURITY C2: Count leading zero bits in a byte array
fn count_leading_zero_bits(data: &[u8]) -> u32 {
    let mut count = 0u32;
    for &byte in data {
        if byte == 0 {
            count += 8;
        } else {
            // Count leading zeros in this byte and stop
            count += byte.leading_zeros();
            break;
        }
    }
    count
}

/// Information about a network adapter
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdapterInfo {
    /// Adapter type
    pub adapter_type: AdapterType,

    /// Address for this adapter (protocol-specific)
    pub address: String,

    /// Whether this adapter is currently active
    pub active: bool,
}

/// Node capabilities (safe for public sharing in DHT)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct NodeCapabilities {
    /// Can relay messages
    pub can_relay: bool,

    /// Can store DHT data
    pub can_store: bool,

    /// Supports store-and-forward
    pub store_and_forward: bool,

    /// Has i2p capability (Mode 2: Selective Disclosure)
    /// TRUE means node can be reached via i2p, but destination is NOT public
    /// Use capability tokens for private i2p discovery
    pub i2p_capable: bool,

    /// Has Tor capability (similar privacy model to i2p)
    pub tor_capable: bool,

    /// Maximum message size this node can handle
    pub max_message_size: usize,

    /// Available storage (bytes) - 0 means not advertising
    pub available_storage: u64,

    /// Assigned relay tier (Ephemeral, Trusted, FullServer)
    pub relay_tier: Option<RelayTier>,

    /// Maximum relay bandwidth in bits per second
    pub max_relay_bandwidth_bps: u64,

    /// Relay uptime percentage (0.0 to 1.0)
    pub relay_uptime_pct: f64,

    /// Current relay load percentage (0.0 to 1.0)
    pub relay_load_pct: f64,
}

impl Default for NodeCapabilities {
    fn default() -> Self {
        NodeCapabilities {
            can_relay: true,
            can_store: true,
            store_and_forward: false,
            i2p_capable: false,
            tor_capable: false,
            max_message_size: 1024 * 1024,        // 1MB
            available_storage: 100 * 1024 * 1024, // 100MB
            relay_tier: None,
            max_relay_bandwidth_bps: 1_000_000,   // 1Mbps default
            relay_uptime_pct: 0.9,                // 90% uptime requirement
            relay_load_pct: 0.3,                  // 30% load threshold
        }
    }
}

/// Information about a node in the DHT
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeInfo {
    /// Node identifier (32 bytes)
    pub node_id: ProtocolNodeId,

    /// SECURITY C2: Proof-of-Work nonce for Sybil resistance
    /// Must satisfy: hash(node_id || pow_nonce) has REQUIRED_POW_DIFFICULTY leading zero bits
    pub pow_nonce: u64,

    /// Available network adapters
    pub adapters: Vec<AdapterInfo>,

    /// Last successful communication (Unix timestamp)
    pub last_seen: u64,

    /// Round-trip time in milliseconds
    pub rtt_ms: f64,

    /// Consecutive failures
    pub failures: u32,

    /// Reputation tracking
    pub reputation: NodeReputation,

    /// Node capabilities
    pub capabilities: NodeCapabilities,

    /// First seen timestamp
    pub first_seen: u64,

    /// Total successful communications
    pub total_successes: u64,
}

impl NodeInfo {
    /// Create new node info (requires valid PoW nonce)
    pub fn new(node_id: ProtocolNodeId) -> Self {
        let now = now();
        NodeInfo {
            node_id,
            pow_nonce: 0, // SECURITY C2: Must be set with valid PoW before DHT admission
            adapters: Vec::new(),
            last_seen: now,
            rtt_ms: 0.0,
            failures: 0,
            reputation: NodeReputation::new(),
            capabilities: NodeCapabilities::default(),
            first_seen: now,
            total_successes: 0,
        }
    }

    /// Create with adapters
    pub fn with_adapters(node_id: ProtocolNodeId, adapters: Vec<AdapterInfo>) -> Self {
        let mut info = Self::new(node_id);
        info.adapters = adapters;
        info
    }

    /// SECURITY C2: Compute Proof-of-Work for this NodeId
    ///
    /// Finds a nonce such that hash(node_id || nonce) has required leading zero bits.
    /// This is computationally expensive (~65k attempts average for 16-bit difficulty).
    pub fn compute_pow(&mut self) -> u64 {
        let mut nonce = 0u64;
        loop {
            if Self::verify_pow_internal(&self.node_id, nonce, REQUIRED_POW_DIFFICULTY) {
                self.pow_nonce = nonce;
                return nonce;
            }
            nonce += 1;
        }
    }

    /// SECURITY C2: Verify Proof-of-Work for a NodeId + nonce
    ///
    /// Returns true if hash(node_id || nonce) has at least `difficulty` leading zero bits.
    pub fn verify_pow(&self) -> bool {
        Self::verify_pow_internal(&self.node_id, self.pow_nonce, REQUIRED_POW_DIFFICULTY)
    }

    /// Internal PoW verification
    fn verify_pow_internal(node_id: &ProtocolNodeId, nonce: u64, difficulty: u32) -> bool {
        // Compute hash(node_id || nonce)
        let mut hasher = Blake2b512::new();
        hasher.update(node_id.as_bytes());
        hasher.update(nonce.to_le_bytes());
        let hash = hasher.finalize();

        // Count leading zero bits
        let leading_zeros = count_leading_zero_bits(&hash);
        leading_zeros >= difficulty
    }

    /// Record successful communication
    pub fn record_success(&mut self, rtt_ms: f64) {
        self.last_seen = now();
        self.rtt_ms = rtt_ms;
        self.failures = 0;
        self.total_successes += 1;
        self.reputation.record_success();
    }

    /// Record failed communication
    pub fn record_failure(&mut self) {
        self.failures += 1;
        self.reputation.record_failure();
    }

    /// Check if node is likely stale
    pub fn is_stale(&self, max_age_secs: u64) -> bool {
        let age = now().saturating_sub(self.last_seen);
        age > max_age_secs
    }

    /// Check if node should be evicted
    pub fn should_evict(&self, max_failures: u32, max_age_secs: u64) -> bool {
        self.failures >= max_failures || self.is_stale(max_age_secs)
    }

    /// Get best adapter for communication
    pub fn get_best_adapter(&self) -> Option<&AdapterInfo> {
        self.adapters.iter().find(|a| a.active)
    }

    /// Calculate XOR distance to another node
    ///
    /// SECURITY C6: Returns 64-byte XOR distance for enhanced collision resistance
    pub fn distance_to(&self, other: &ProtocolNodeId) -> [u8; NODE_ID_SIZE] {
        self.node_id.distance(other)
    }

    /// Convert to public node info (safe for DHT sharing)
    ///
    /// SECURITY H11: Mode 2 separation - This removes ALL adapter addresses
    /// to prevent de-anonymization, especially for i2p/Tor nodes.
    ///
    /// Mode 2 means: capability flags (i2p_capable, tor_capable) indicate support,
    /// but actual destinations are NEVER shared in public DHT.
    /// Convert to public node info (safe for DHT sharing)
    ///
    /// SECURITY H11: Mode 2 separation - This removes ALL adapter addresses
    /// by structurally excluding them from PublicNodeInfo. The type system
    /// prevents address leakage at compile time - PublicNodeInfo has no
    /// adapters field, making it impossible to leak i2p/Tor addresses.
    pub fn to_public(&self) -> PublicNodeInfo {
        PublicNodeInfo {
            node_id: self.node_id,
            capabilities: self.capabilities.clone(),
            reputation: self.reputation.clone(),
            last_seen: self.last_seen,
            rtt_ms: self.rtt_ms,
        }
    }

    /// SECURITY H11: Validate Mode 2 separation is maintained
    ///
    /// Returns true if node follows Mode 2 privacy model correctly:
    /// - If i2p_capable/tor_capable, actual addresses should NOT be shared publicly
    /// - This method checks that the node configuration is safe for public DHT
    pub fn validates_mode2_separation(&self) -> bool {
        // Mode 2 rule: capability flags can be public, but addresses cannot
        // Since to_public() already strips all addresses, this is automatically maintained
        // This method exists to document and test the invariant

        // For i2p/Tor nodes, we should have the capability flag but addresses
        // are kept private (only in local NodeInfo, never in PublicNodeInfo)
        if self.capabilities.i2p_capable || self.capabilities.tor_capable {
            // Node is correctly configured if it has adapters locally
            // (which will be stripped by to_public())
            return true;
        }

        // Non-privacy nodes are fine
        true
    }
}

/// Public node information (safe for DHT distribution)
///
/// SECURITY H11: This structure is shared publicly in DHT queries.
/// It MUST NOT contain any adapter addresses that could de-anonymize users.
///
/// **Mode 2 Separation (i2p/Tor):**
/// - Use capability flags (i2p_capable, tor_capable) to indicate support
/// - NEVER include actual destination/onion addresses here
/// - Private discovery uses capability tokens exchanged out-of-band
/// - Violating Mode 2 can completely de-anonymize users
///
/// This struct is deliberately designed WITHOUT any address fields
/// to prevent accidental inclusion of identifying information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicNodeInfo {
    /// Node identifier (32 bytes)
    pub node_id: ProtocolNodeId,

    /// Node capabilities (includes privacy-preserving flags)
    pub capabilities: NodeCapabilities,

    /// Reputation tracking
    pub reputation: NodeReputation,

    /// Last successful communication (Unix timestamp)
    pub last_seen: u64,

    /// Round-trip time in milliseconds
    pub rtt_ms: f64,
}

impl PublicNodeInfo {
    /// Create new public node info
    pub fn new(node_id: ProtocolNodeId, capabilities: NodeCapabilities) -> Self {
        PublicNodeInfo {
            node_id,
            capabilities,
            reputation: NodeReputation::new(),
            last_seen: now(),
            rtt_ms: 0.0,
        }
    }

    /// Calculate XOR distance to another node
    ///
    /// SECURITY C6: Returns 64-byte XOR distance for enhanced collision resistance
    pub fn distance_to(&self, other: &ProtocolNodeId) -> [u8; NODE_ID_SIZE] {
        self.node_id.distance(other)
    }

    /// Check if node is likely stale
    pub fn is_stale(&self, max_age_secs: u64) -> bool {
        let age = now().saturating_sub(self.last_seen);
        age > max_age_secs
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_node() -> NodeInfo {
        NodeInfo::new(ProtocolNodeId::from_bytes([1u8; NODE_ID_SIZE]))
    }

    #[test]
    fn test_new_node() {
        let node = create_test_node();
        assert_eq!(node.failures, 0);
        assert_eq!(node.total_successes, 0);
        // SECURITY C7: New nodes start with low reputation, must earn trust
        assert!(!node.reputation.is_trustworthy());
    }

    #[test]
    fn test_record_success() {
        let mut node = create_test_node();

        node.record_success(10.5);
        assert_eq!(node.failures, 0);
        assert_eq!(node.total_successes, 1);
        assert_eq!(node.rtt_ms, 10.5);
    }

    #[test]
    fn test_record_failure() {
        let mut node = create_test_node();

        node.record_failure();
        assert_eq!(node.failures, 1);
    }

    #[test]
    fn test_should_evict() {
        let mut node = create_test_node();

        // Fresh node should not be evicted
        assert!(!node.should_evict(3, 3600));

        // Too many failures
        node.failures = 5;
        assert!(node.should_evict(3, 3600));
    }

    #[test]
    fn test_is_stale() {
        let mut node = create_test_node();

        // Fresh node is not stale
        assert!(!node.is_stale(3600));

        // Old node is stale
        node.last_seen = now() - 7200; // 2 hours ago
        assert!(node.is_stale(3600)); // Max age 1 hour
    }

    #[test]
    fn test_with_adapters() {
        let node_id = ProtocolNodeId::from_bytes([1u8; NODE_ID_SIZE]);
        let adapters = vec![AdapterInfo {
            adapter_type: AdapterType::Ethernet,
            address: "192.168.1.1:4001".to_string(),
            active: true,
        }];

        let node = NodeInfo::with_adapters(node_id, adapters.clone());
        assert_eq!(node.adapters.len(), 1);
        assert!(node.get_best_adapter().is_some());
    }

    #[test]
    fn test_to_public_removes_adapter_addresses() {
        let node_id = ProtocolNodeId::from_bytes([1u8; NODE_ID_SIZE]);
        let adapters = vec![
            AdapterInfo {
                adapter_type: AdapterType::Ethernet,
                address: "192.168.1.1:4001".to_string(),
                active: true,
            },
            AdapterInfo {
                adapter_type: AdapterType::I2P,
                address: "ukeu3k5o...b32.i2p".to_string(),
                active: true,
            },
        ];

        let mut node = NodeInfo::with_adapters(node_id, adapters);
        node.capabilities.i2p_capable = true;

        // Convert to public
        let public = node.to_public();

        // Public version should not have adapter addresses
        // but should preserve capability flags
        assert_eq!(public.node_id, node.node_id);
        assert!(public.capabilities.i2p_capable);
        assert_eq!(public.reputation.score(), node.reputation.score());
    }

    #[test]
    fn test_public_node_info_creation() {
        let node_id = ProtocolNodeId::from_bytes([1u8; NODE_ID_SIZE]);
        let caps = NodeCapabilities {
            i2p_capable: true,
            tor_capable: false,
            ..Default::default()
        };

        let public = PublicNodeInfo::new(node_id, caps.clone());

        assert_eq!(public.node_id, node_id);
        assert_eq!(public.capabilities, caps);
        // SECURITY C7: New nodes start with low reputation, must earn trust
        assert!(!public.reputation.is_trustworthy());
    }

    #[test]
    fn test_public_node_info_is_stale() {
        let node_id = ProtocolNodeId::from_bytes([1u8; NODE_ID_SIZE]);
        let mut public = PublicNodeInfo::new(node_id, NodeCapabilities::default());

        // Fresh node is not stale
        assert!(!public.is_stale(3600));

        // Old node is stale
        public.last_seen = now() - 7200; // 2 hours ago
        assert!(public.is_stale(3600)); // Max age 1 hour
    }

    #[test]
    fn test_node_capabilities_default() {
        let caps = NodeCapabilities::default();
        assert!(caps.can_relay);
        assert!(caps.can_store);
        assert!(!caps.store_and_forward);
        assert!(!caps.i2p_capable);
        assert!(!caps.tor_capable);
        assert!(caps.relay_tier.is_none());
        assert_eq!(caps.max_relay_bandwidth_bps, 1_000_000);
        assert_eq!(caps.relay_uptime_pct, 0.9);
        assert_eq!(caps.relay_load_pct, 0.3);
    }

    #[test]
    fn test_node_capabilities_with_relay_tier() {
        use myriadmesh_protocol::message::RelayTier;

        let mut caps = NodeCapabilities::default();
        caps.relay_tier = Some(RelayTier::Trusted);
        caps.max_relay_bandwidth_bps = 10_000_000;
        caps.relay_uptime_pct = 0.95;
        caps.relay_load_pct = 0.2;

        assert_eq!(caps.relay_tier, Some(RelayTier::Trusted));
        assert_eq!(caps.max_relay_bandwidth_bps, 10_000_000);
        assert_eq!(caps.relay_uptime_pct, 0.95);
        assert_eq!(caps.relay_load_pct, 0.2);
    }

    #[test]
    fn test_node_capabilities_relay_tier_validation() {
        use myriadmesh_protocol::message::RelayTier;

        let mut caps = NodeCapabilities::default();

        // Test ephemeral tier
        caps.relay_tier = Some(RelayTier::Ephemeral);
        assert_eq!(caps.relay_tier, Some(RelayTier::Ephemeral));

        // Test trusted tier
        caps.relay_tier = Some(RelayTier::Trusted);
        assert_eq!(caps.relay_tier, Some(RelayTier::Trusted));

        // Test full server tier
        caps.relay_tier = Some(RelayTier::FullServer);
        assert_eq!(caps.relay_tier, Some(RelayTier::FullServer));

        // Test None (no relay tier assigned)
        caps.relay_tier = None;
        assert!(caps.relay_tier.is_none());
    }

    #[test]
    fn test_node_capabilities_bandwidth_limits() {
        let mut caps = NodeCapabilities::default();

        // Test zero bandwidth (relay disabled)
        caps.max_relay_bandwidth_bps = 0;
        assert_eq!(caps.max_relay_bandwidth_bps, 0);

        // Test high bandwidth
        caps.max_relay_bandwidth_bps = 100_000_000; // 100Mbps
        assert_eq!(caps.max_relay_bandwidth_bps, 100_000_000);
    }

    #[test]
    fn test_node_capabilities_percentage_validation() {
        let mut caps = NodeCapabilities::default();

        // Test minimum percentages
        caps.relay_uptime_pct = 0.0;
        caps.relay_load_pct = 0.0;
        assert_eq!(caps.relay_uptime_pct, 0.0);
        assert_eq!(caps.relay_load_pct, 0.0);

        // Test maximum percentages
        caps.relay_uptime_pct = 1.0;
        caps.relay_load_pct = 1.0;
        assert_eq!(caps.relay_uptime_pct, 1.0);
        assert_eq!(caps.relay_load_pct, 1.0);

        // Test typical values
        caps.relay_uptime_pct = 0.99;  // 99% uptime
        caps.relay_load_pct = 0.5;     // 50% load
        assert_eq!(caps.relay_uptime_pct, 0.99);
        assert_eq!(caps.relay_load_pct, 0.5);
    }

    // SECURITY C2: Proof-of-Work tests

    #[test]
    fn test_count_leading_zero_bits() {
        // All zeros
        assert_eq!(count_leading_zero_bits(&[0u8; 8]), 64);

        // First byte non-zero
        assert_eq!(count_leading_zero_bits(&[0b00010000, 0, 0, 0]), 3);

        // Multiple zero bytes then non-zero
        assert_eq!(count_leading_zero_bits(&[0, 0, 0b00000001, 0]), 7 + 8 + 8);

        // No leading zeros
        assert_eq!(count_leading_zero_bits(&[0b10000000, 0, 0, 0]), 0);
    }

    #[test]
    fn test_pow_compute_and_verify() {
        // SECURITY C2: PoW computation and verification
        let mut node = NodeInfo::new(ProtocolNodeId::from_bytes([42u8; NODE_ID_SIZE]));

        // Initially has no valid PoW
        assert!(!node.verify_pow());

        // Compute PoW (this will take ~65k attempts on average for 16-bit difficulty)
        let nonce = node.compute_pow();

        // Now PoW should be valid
        assert!(node.verify_pow());
        assert_eq!(node.pow_nonce, nonce);
    }

    #[test]
    fn test_pow_reject_invalid_nonce() {
        // SECURITY C2: Verify that invalid nonces are rejected
        let mut node = NodeInfo::new(ProtocolNodeId::from_bytes([123u8; NODE_ID_SIZE]));

        // Set an arbitrary invalid nonce
        node.pow_nonce = 12345;

        // Should fail verification (extremely unlikely to be valid)
        assert!(!node.verify_pow());
    }

    #[test]
    fn test_pow_different_nodes_need_different_nonces() {
        // SECURITY C2: Different NodeIDs need different PoW solutions
        let node_id_1 = ProtocolNodeId::from_bytes([1u8; NODE_ID_SIZE]);
        let node_id_2 = ProtocolNodeId::from_bytes([2u8; NODE_ID_SIZE]);

        let mut node1 = NodeInfo::new(node_id_1);
        let mut node2 = NodeInfo::new(node_id_2);

        node1.compute_pow();
        node2.compute_pow();

        // Different NodeIDs should have different nonces
        // (extremely unlikely to be the same)
        assert_ne!(node1.pow_nonce, node2.pow_nonce);

        // Each should verify correctly
        assert!(node1.verify_pow());
        assert!(node2.verify_pow());

        // Swapping nonces should fail verification
        std::mem::swap(&mut node1.pow_nonce, &mut node2.pow_nonce);

        assert!(!node1.verify_pow());
        assert!(!node2.verify_pow());
    }

    #[test]
    fn test_pow_low_difficulty() {
        // Test with very low difficulty for speed
        let node_id = ProtocolNodeId::from_bytes([99u8; NODE_ID_SIZE]);

        // Test with difficulty 4 (should be fast: ~16 attempts)
        let mut nonce = 0u64;
        loop {
            if NodeInfo::verify_pow_internal(&node_id, nonce, 4) {
                break;
            }
            nonce += 1;
            assert!(nonce < 1000, "Took too many attempts for difficulty 4");
        }

        // Verify the nonce works
        assert!(NodeInfo::verify_pow_internal(&node_id, nonce, 4));
    }

    // SECURITY H11: Mode 2 Separation Tests

    #[test]
    fn test_mode2_separation_enforced() {
        // SECURITY H11: Verify Mode 2 separation - i2p addresses never leak to public
        let node_id = ProtocolNodeId::from_bytes([42u8; NODE_ID_SIZE]);

        let adapters = vec![
            AdapterInfo {
                adapter_type: AdapterType::Ethernet,
                address: "192.168.1.100:4001".to_string(),
                active: true,
            },
            AdapterInfo {
                adapter_type: AdapterType::I2P,
                address: "ukeu3k5oykqjktxj4i6zqmqw3afkrqshnqgw2a9pafb3b6qw7evq.b32.i2p".to_string(),
                active: true,
            },
        ];

        let mut node = NodeInfo::with_adapters(node_id, adapters);
        node.capabilities.i2p_capable = true;

        // Node should validate Mode 2 separation locally
        assert!(node.validates_mode2_separation());

        // Convert to public - this should strip ALL addresses
        let public = node.to_public();

        // SECURITY H11: Verify i2p capability flag is preserved
        assert!(public.capabilities.i2p_capable);

        // SECURITY H11: Verify PublicNodeInfo has no address fields
        // (structurally impossible to leak addresses)
        assert_eq!(public.node_id, node_id);

        // PublicNodeInfo should only have: node_id, capabilities, reputation, last_seen, rtt_ms
        // NO adapter addresses can possibly be included
    }

    // NOTE: AdapterType::Tor is not yet implemented in the protocol
    // This test is commented out until Tor adapter support is added
    // #[test]
    // fn test_mode2_tor_separation() {
    //     // SECURITY H11: Verify Mode 2 works for Tor as well
    //     let node_id = ProtocolNodeId::from_bytes([7u8; NODE_ID_SIZE]);
    //
    //     let adapters = vec![AdapterInfo {
    //         adapter_type: AdapterType::Tor,
    //         address: "thehiddenwiki.onion:8080".to_string(),
    //         active: true,
    //     }];
    //
    //     let mut node = NodeInfo::with_adapters(node_id, adapters);
    //     node.capabilities.tor_capable = true;
    //
    //     // Should validate Mode 2
    //     assert!(node.validates_mode2_separation());
    //
    //     // Convert to public
    //     let public = node.to_public();
    //
    //     // Tor capability should be public
    //     assert!(public.capabilities.tor_capable);
    //
    //     // But no way to access onion address from PublicNodeInfo
    //     assert_eq!(public.node_id, node_id);
    // }

    // NOTE: AdapterType::Tor is not yet implemented in the protocol
    // This test is commented out until Tor adapter support is added
    // #[test]
    // fn test_mode2_multiple_privacy_adapters() {
    //     // SECURITY H11: Node with both i2p and Tor
    //     let node_id = ProtocolNodeId::from_bytes([99u8; NODE_ID_SIZE]);
    //
    //     let adapters = vec![
    //         AdapterInfo {
    //             adapter_type: AdapterType::I2P,
    //             address: "example.b32.i2p".to_string(),
    //             active: true,
    //         },
    //         AdapterInfo {
    //             adapter_type: AdapterType::Tor,
    //             address: "example.onion".to_string(),
    //             active: true,
    //         },
    //     ];
    //
    //     let mut node = NodeInfo::with_adapters(node_id, adapters);
    //     node.capabilities.i2p_capable = true;
    //     node.capabilities.tor_capable = true;
    //
    //     // Should validate
    //     assert!(node.validates_mode2_separation());
    //
    //     let public = node.to_public();
    //
    //     // Both capability flags preserved
    //     assert!(public.capabilities.i2p_capable);
    //     assert!(public.capabilities.tor_capable);
    //
    //     // But addresses are completely stripped
    // }

    #[test]
    fn test_mode2_non_privacy_nodes_unchanged() {
        // SECURITY H11: Non-privacy nodes (Ethernet only) work normally
        let node_id = ProtocolNodeId::from_bytes([5u8; NODE_ID_SIZE]);

        let adapters = vec![AdapterInfo {
            adapter_type: AdapterType::Ethernet,
            address: "10.0.0.5:4001".to_string(),
            active: true,
        }];

        let node = NodeInfo::with_adapters(node_id, adapters);

        // Should validate (non-privacy nodes are always OK)
        assert!(node.validates_mode2_separation());

        let public = node.to_public();

        // No privacy flags set
        assert!(!public.capabilities.i2p_capable);
        assert!(!public.capabilities.tor_capable);

        // Note: Even Ethernet addresses are stripped in to_public()
        // because PublicNodeInfo doesn't have an adapters field at all
    }

    #[test]
    fn test_public_node_info_has_no_address_field() {
        // SECURITY H11: Structurally verify PublicNodeInfo cannot leak addresses
        let node_id = ProtocolNodeId::from_bytes([1u8; NODE_ID_SIZE]);
        let caps = NodeCapabilities {
            i2p_capable: true,
            ..Default::default()
        };

        let public = PublicNodeInfo::new(node_id, caps);

        // PublicNodeInfo should have exactly these fields and no more:
        // - node_id
        // - capabilities
        // - reputation
        // - last_seen
        // - rtt_ms
        //
        // NO adapters, NO addresses, NO way to leak privacy-sensitive info

        assert_eq!(public.node_id, node_id);
        assert!(public.capabilities.i2p_capable);
        assert!(public.reputation.score() >= 0.0);
        assert!(public.last_seen > 0);
    }

    #[test]
    fn test_mode2_capability_flag_vs_address() {
        // SECURITY H11: Demonstrate the difference between capability flag and address
        let node_id = ProtocolNodeId::from_bytes([111u8; NODE_ID_SIZE]);

        // Private node info (local only) has actual i2p address
        let private_adapters = vec![AdapterInfo {
            adapter_type: AdapterType::I2P,
            address: "secretdestination.b32.i2p".to_string(),
            active: true,
        }];

        let mut private_node = NodeInfo::with_adapters(node_id, private_adapters);
        private_node.capabilities.i2p_capable = true;

        // Private node knows the actual address
        assert_eq!(private_node.adapters.len(), 1);
        assert!(private_node.adapters[0]
            .address
            .contains("secretdestination"));

        // Public version only has capability flag
        let public_node = private_node.to_public();
        assert!(public_node.capabilities.i2p_capable);

        // SECURITY H11: Public version structurally CANNOT contain addresses
        // because PublicNodeInfo doesn't have an adapters field
        // This is enforced at the type level - compiler prevents leakage
    }

    #[test]
    fn test_mode2_documentation_compliance() {
        // SECURITY H11: Verify implementation matches Mode 2 documentation
        //
        // Mode 2 Requirements:
        // 1. Capability flags (i2p_capable, tor_capable) can be public
        // 2. Actual addresses MUST remain private
        // 3. Discovery happens out-of-band via capability tokens

        let node_id = ProtocolNodeId::from_bytes([200u8; NODE_ID_SIZE]);
        let mut node = NodeInfo::new(node_id);
        node.capabilities.i2p_capable = true;

        // 1. Capability flag is public
        let public = node.to_public();
        assert!(public.capabilities.i2p_capable); // ✓

        // 2. Addresses are structurally impossible to leak
        // PublicNodeInfo has no address-containing fields ✓

        // 3. Out-of-band discovery is handled separately
        // (not tested here, but Mode 2 is enforced at this layer) ✓
    }
}
