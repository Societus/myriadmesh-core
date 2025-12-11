//! DHT storage for key-value pairs

use crate::error::{DhtError, Result};
use crate::{MAX_DHT_KEYS, MAX_DHT_STORAGE_BYTES, MAX_VALUE_SIZE};
use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

/// Get current timestamp with graceful fallback on system time errors
///
/// SECURITY: If system clock goes backwards or other time errors occur,
/// returns a fallback timestamp instead of panicking. This is better than
/// crashing the DHT during storage operations.
fn now() -> u64 {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(duration) => duration.as_secs(),
        Err(e) => {
            eprintln!(
                "WARNING: System time error in DHT storage: {}. Using fallback timestamp.",
                e
            );
            // Return a reasonable fallback (1.5 billion seconds since epoch, ~2017)
            1500000000
        }
    }
}

/// A stored value with metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageEntry {
    /// The key (32 bytes)
    pub key: [u8; 32],

    /// The value
    pub value: Vec<u8>,

    /// When this entry was stored
    pub stored_at: u64,

    /// When this entry expires (Unix timestamp)
    pub expires_at: u64,

    /// Publisher's Ed25519 public key (32 bytes)
    /// SECURITY H7: REQUIRED for signature verification
    /// NOTE: This is the actual public key, NOT the NodeID
    pub publisher_public_key: [u8; 32],

    /// Publisher's NodeID (64 bytes, derived from public key via BLAKE2b-512)
    /// SECURITY H7: Used for identification and quota tracking
    #[serde(with = "BigArray")]
    pub publisher_node_id: [u8; 64],

    /// Ed25519 signature over (key || value || expires_at)
    /// SECURITY H7: Signature from publisher to prevent DHT poisoning
    #[serde(with = "BigArray")]
    pub signature: [u8; 64],
}

impl StorageEntry {
    /// Check if entry is expired
    pub fn is_expired(&self) -> bool {
        now() >= self.expires_at
    }

    /// Get remaining TTL in seconds
    pub fn ttl_remaining(&self) -> u64 {
        let current = now();
        self.expires_at.saturating_sub(current)
    }

    /// SECURITY H7: Verify signature on stored value
    /// Prevents DHT value poisoning by ensuring publisher authenticity
    pub fn verify_signature(&self) -> Result<()> {
        use blake2::{Blake2b512, Digest};
        use sodiumoxide::crypto::sign::ed25519;

        // Build message to verify: key || value || expires_at
        let mut message = Vec::new();
        message.extend_from_slice(&self.key);
        message.extend_from_slice(&self.value);
        message.extend_from_slice(&self.expires_at.to_le_bytes());

        // Extract signature (ed25519::Signature uses from_bytes which returns a Result)
        let signature = ed25519::Signature::from_bytes(&self.signature)
            .map_err(|_| DhtError::InvalidSignature)?;

        // Extract public key from publisher_public_key field
        let public_key = ed25519::PublicKey::from_slice(&self.publisher_public_key)
            .ok_or(DhtError::InvalidPublicKey)?;

        // SECURITY H7: Verify that the NodeID matches the public key
        // NodeID = BLAKE2b-512(Ed25519_PublicKey)
        let mut hasher = Blake2b512::new();
        hasher.update(self.publisher_public_key);
        let computed_node_id = hasher.finalize();

        if self.publisher_node_id[..] != computed_node_id[..] {
            return Err(DhtError::InvalidPublicKey);
        }

        // Verify signature
        if ed25519::verify_detached(&signature, &message, &public_key) {
            Ok(())
        } else {
            Err(DhtError::InvalidSignature)
        }
    }
}

/// Per-node storage tracking
#[derive(Debug, Clone)]
struct NodeQuota {
    /// Number of keys stored by this node
    key_count: usize,
    /// Total bytes stored by this node
    bytes_used: usize,
}

/// DHT storage layer
#[derive(Debug)]
pub struct DhtStorage {
    /// Stored entries by key
    entries: HashMap<[u8; 32], StorageEntry>,

    /// Current storage size in bytes
    current_size: usize,

    /// Maximum storage size
    max_size: usize,

    /// Maximum number of keys
    max_keys: usize,

    /// SECURITY M2: Per-node storage quotas
    /// Tracks how much storage each publisher is using (keyed by NodeID)
    node_quotas: HashMap<[u8; 64], NodeQuota>,

    /// SECURITY M2: Maximum keys per node
    max_keys_per_node: usize,

    /// SECURITY M2: Maximum bytes per node
    max_bytes_per_node: usize,
}

/// SECURITY M2: Default maximum keys per node (10% of total)
const DEFAULT_MAX_KEYS_PER_NODE: usize = MAX_DHT_KEYS / 10;

/// SECURITY M2: Default maximum bytes per node (10% of total)
const DEFAULT_MAX_BYTES_PER_NODE: usize = MAX_DHT_STORAGE_BYTES / 10;

impl DhtStorage {
    /// Create new DHT storage
    pub fn new() -> Self {
        DhtStorage {
            entries: HashMap::new(),
            current_size: 0,
            max_size: MAX_DHT_STORAGE_BYTES,
            max_keys: MAX_DHT_KEYS,
            node_quotas: HashMap::new(),
            max_keys_per_node: DEFAULT_MAX_KEYS_PER_NODE,
            max_bytes_per_node: DEFAULT_MAX_BYTES_PER_NODE,
        }
    }

    /// Create with custom limits
    pub fn with_limits(max_size: usize, max_keys: usize) -> Self {
        DhtStorage {
            entries: HashMap::new(),
            current_size: 0,
            max_size,
            max_keys,
            node_quotas: HashMap::new(),
            max_keys_per_node: max_keys / 10,  // 10% per node
            max_bytes_per_node: max_size / 10, // 10% per node
        }
    }

    /// Create with custom per-node quotas
    /// SECURITY M2: Allows fine-tuning resource limits per publisher
    pub fn with_quotas(
        max_size: usize,
        max_keys: usize,
        max_keys_per_node: usize,
        max_bytes_per_node: usize,
    ) -> Self {
        DhtStorage {
            entries: HashMap::new(),
            current_size: 0,
            max_size,
            max_keys,
            node_quotas: HashMap::new(),
            max_keys_per_node,
            max_bytes_per_node,
        }
    }

    /// Get current storage size in bytes
    pub fn size(&self) -> usize {
        self.current_size
    }

    /// Get number of stored keys
    pub fn key_count(&self) -> usize {
        self.entries.len()
    }

    /// SECURITY M2: Get node quota usage
    pub fn get_node_usage(&self, publisher_node_id: &[u8; 64]) -> (usize, usize) {
        self.node_quotas
            .get(publisher_node_id)
            .map(|quota| (quota.key_count, quota.bytes_used))
            .unwrap_or((0, 0))
    }

    /// SECURITY M2: Check if node has quota available
    fn node_has_quota(
        &self,
        publisher_node_id: &[u8; 64],
        value_size: usize,
        is_update: bool,
    ) -> bool {
        let quota = self.node_quotas.get(publisher_node_id);

        match quota {
            Some(q) => {
                // If updating existing key, don't count against key quota
                let key_check = if is_update {
                    true
                } else {
                    q.key_count < self.max_keys_per_node
                };

                let byte_check = q.bytes_used + value_size <= self.max_bytes_per_node;

                key_check && byte_check
            }
            None => {
                // New publisher - check if adding first entry would exceed quotas
                value_size <= self.max_bytes_per_node
            }
        }
    }

    /// SECURITY M2: Update node quota
    fn update_node_quota(&mut self, publisher_node_id: [u8; 64], key_delta: i32, bytes_delta: i64) {
        let quota = self
            .node_quotas
            .entry(publisher_node_id)
            .or_insert(NodeQuota {
                key_count: 0,
                bytes_used: 0,
            });

        // Update key count
        if key_delta > 0 {
            quota.key_count += key_delta as usize;
        } else if key_delta < 0 {
            quota.key_count = quota.key_count.saturating_sub((-key_delta) as usize);
        }

        // Update bytes used
        if bytes_delta > 0 {
            quota.bytes_used += bytes_delta as usize;
        } else if bytes_delta < 0 {
            quota.bytes_used = quota.bytes_used.saturating_sub((-bytes_delta) as usize);
        }

        // Remove quota entry if node has nothing stored
        if quota.key_count == 0 && quota.bytes_used == 0 {
            self.node_quotas.remove(&publisher_node_id);
        }
    }

    /// Check if storage has capacity for a value
    fn has_capacity(&self, value_size: usize) -> bool {
        self.key_count() < self.max_keys && (self.current_size + value_size) <= self.max_size
    }

    /// Store a value
    /// SECURITY H7: Requires valid signature from publisher
    /// SECURITY M2: Enforces per-node storage quotas
    pub fn store(
        &mut self,
        key: [u8; 32],
        value: Vec<u8>,
        ttl_secs: u64,
        publisher_public_key: [u8; 32],
        publisher_node_id: [u8; 64],
        signature: [u8; 64],
    ) -> Result<()> {
        // Check value size
        if value.len() > MAX_VALUE_SIZE {
            return Err(DhtError::ValueTooLarge {
                size: value.len(),
                max: MAX_VALUE_SIZE,
            });
        }

        let expires_at = now() + ttl_secs;

        // Create entry for verification
        let entry = StorageEntry {
            key,
            value: value.clone(),
            stored_at: now(),
            expires_at,
            publisher_public_key,
            publisher_node_id,
            signature,
        };

        // SECURITY H7: Verify signature before storing
        entry.verify_signature()?;

        // Check if this is an update to existing key
        let is_update = self.entries.contains_key(&key);
        let old_entry = if is_update {
            self.entries.remove(&key)
        } else {
            None
        };

        // SECURITY M2: Check per-node quota
        if !self.node_has_quota(&publisher_node_id, value.len(), is_update) {
            // Restore old entry if this was an update
            if let Some(old) = old_entry {
                self.entries.insert(key, old);
            }

            let (keys, bytes) = self.get_node_usage(&publisher_node_id);
            return Err(DhtError::NodeQuotaExceeded {
                publisher: publisher_node_id,
                current_keys: keys,
                current_bytes: bytes,
                max_keys: self.max_keys_per_node,
                max_bytes: self.max_bytes_per_node,
            });
        }

        // Update size tracking for old entry
        if let Some(ref old) = old_entry {
            self.current_size -= old.value.len();
            // Update quota for old value removal
            self.update_node_quota(old.publisher_node_id, 0, -(old.value.len() as i64));
        }

        // Check global capacity
        if !self.has_capacity(value.len()) {
            // Try to make space by removing expired entries
            self.cleanup_expired();

            if !self.has_capacity(value.len()) {
                // Restore old entry if this was an update
                if let Some(old) = old_entry {
                    self.current_size += old.value.len();
                    self.update_node_quota(old.publisher_node_id, 0, old.value.len() as i64);
                    self.entries.insert(key, old);
                }
                return Err(DhtError::StorageFull { max: self.max_size });
            }
        }

        // SECURITY M2: Update node quota
        let key_delta = if is_update { 0 } else { 1 };
        self.update_node_quota(publisher_node_id, key_delta, value.len() as i64);

        // Store
        self.entries.insert(key, entry);
        self.current_size += value.len();

        Ok(())
    }

    /// Retrieve a value
    pub fn get(&self, key: &[u8; 32]) -> Option<&StorageEntry> {
        self.entries.get(key).and_then(|entry| {
            if entry.is_expired() {
                None
            } else {
                Some(entry)
            }
        })
    }

    /// Remove a value
    /// SECURITY M2: Updates node quotas
    pub fn remove(&mut self, key: &[u8; 32]) -> Option<StorageEntry> {
        if let Some(entry) = self.entries.remove(key) {
            self.current_size -= entry.value.len();
            // SECURITY M2: Update node quota
            self.update_node_quota(entry.publisher_node_id, -1, -(entry.value.len() as i64));
            Some(entry)
        } else {
            None
        }
    }

    /// Cleanup expired entries
    /// SECURITY M2: Updates node quotas for removed entries
    pub fn cleanup_expired(&mut self) -> usize {
        let current_time = now();

        // Collect expired entries first to avoid borrow checker issues
        let expired_entries: Vec<_> = self
            .entries
            .iter()
            .filter(|(_, entry)| entry.expires_at <= current_time)
            .map(|(key, entry)| (*key, entry.publisher_node_id, entry.value.len()))
            .collect();

        // Remove expired entries and update quotas
        for (key, publisher_node_id, value_len) in expired_entries.iter() {
            self.entries.remove(key);
            self.current_size -= value_len;
            // SECURITY M2: Update node quota
            self.update_node_quota(*publisher_node_id, -1, -(*value_len as i64));
        }

        expired_entries.len()
    }

    /// Get all entries (for republishing)
    pub fn get_all_entries(&self) -> Vec<&StorageEntry> {
        self.entries
            .values()
            .filter(|entry| !entry.is_expired())
            .collect()
    }

    /// Get entries that need republishing
    pub fn get_expiring_entries(&self, within_secs: u64) -> Vec<&StorageEntry> {
        let threshold = now() + within_secs;

        self.entries
            .values()
            .filter(|entry| !entry.is_expired() && entry.expires_at <= threshold)
            .collect()
    }

    /// Clear all storage
    /// SECURITY M2: Clears node quotas
    pub fn clear(&mut self) {
        self.entries.clear();
        self.current_size = 0;
        self.node_quotas.clear();
    }
}

impl Default for DhtStorage {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sodiumoxide::crypto::sign::ed25519;
    use std::sync::Once;

    static INIT: Once = Once::new();

    /// Ensure sodiumoxide is initialized once for all tests
    fn init_sodiumoxide() {
        INIT.call_once(|| {
            sodiumoxide::init().expect("Failed to initialize sodiumoxide");
        });
    }

    /// Helper to sign a DHT value for testing
    /// Returns signature bytes
    fn sign_value(
        key: &[u8; 32],
        value: &[u8],
        expires_at: u64,
        sk: &ed25519::SecretKey,
    ) -> [u8; 64] {
        // Build message to sign: key || value || expires_at
        let mut message = Vec::new();
        message.extend_from_slice(key);
        message.extend_from_slice(value);
        message.extend_from_slice(&expires_at.to_le_bytes());

        // Sign
        let signature = ed25519::sign_detached(&message, sk);
        signature.to_bytes()
    }

    /// Helper to create a keypair and sign a value
    /// Returns (publisher_public_key, publisher_node_id, signature)
    fn create_signed_value(
        key: [u8; 32],
        value: Vec<u8>,
        ttl_secs: u64,
    ) -> ([u8; 32], [u8; 64], [u8; 64]) {
        use blake2::{Blake2b512, Digest};

        init_sodiumoxide();
        let (pk, sk) = ed25519::gen_keypair();
        let expires_at = now() + ttl_secs;
        let signature = sign_value(&key, &value, expires_at, &sk);

        // Extract public key bytes
        let mut pk_bytes = [0u8; 32];
        pk_bytes.copy_from_slice(&pk[..]);

        // Derive NodeID from public key using BLAKE2b-512
        let mut hasher = Blake2b512::new();
        hasher.update(pk_bytes);
        let hash = hasher.finalize();
        let mut node_id = [0u8; 64];
        node_id.copy_from_slice(&hash);

        (pk_bytes, node_id, signature)
    }

    #[test]
    fn test_new_storage() {
        let storage = DhtStorage::new();
        assert_eq!(storage.size(), 0);
        assert_eq!(storage.key_count(), 0);
    }

    #[test]
    fn test_store_and_retrieve() {
        let mut storage = DhtStorage::new();
        let key = [1u8; 32];
        let value = b"test value".to_vec();
        let (publisher_public_key, publisher_node_id, signature) =
            create_signed_value(key, value.clone(), 3600);

        storage
            .store(
                key,
                value.clone(),
                3600,
                publisher_public_key,
                publisher_node_id,
                signature,
            )
            .unwrap();

        assert_eq!(storage.key_count(), 1);
        assert!(storage.size() > 0);

        let retrieved = storage.get(&key).unwrap();
        assert_eq!(retrieved.value, value);
    }

    #[test]
    fn test_store_too_large() {
        let mut storage = DhtStorage::new();
        let key = [1u8; 32];
        let value = vec![0u8; MAX_VALUE_SIZE + 1];
        let (publisher_public_key, publisher_node_id, signature) =
            create_signed_value(key, value.clone(), 3600);

        let result = storage.store(
            key,
            value,
            3600,
            publisher_public_key,
            publisher_node_id,
            signature,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_storage_full() {
        let mut storage = DhtStorage::with_limits(100, 5);
        let key = [1u8; 32];
        let value = vec![0u8; 101]; // Too large for capacity
        let (publisher_public_key, publisher_node_id, signature) =
            create_signed_value(key, value.clone(), 3600);

        let result = storage.store(
            key,
            value,
            3600,
            publisher_public_key,
            publisher_node_id,
            signature,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_update_existing() {
        let mut storage = DhtStorage::new();
        let key = [1u8; 32];
        let value1 = b"first value".to_vec();
        let value2 = b"second value".to_vec();

        let (pk1, node_id1, signature1) = create_signed_value(key, value1.clone(), 3600);
        storage
            .store(key, value1, 3600, pk1, node_id1, signature1)
            .unwrap();
        assert_eq!(storage.key_count(), 1);

        let (pk2, node_id2, signature2) = create_signed_value(key, value2.clone(), 3600);
        storage
            .store(key, value2.clone(), 3600, pk2, node_id2, signature2)
            .unwrap();
        assert_eq!(storage.key_count(), 1); // Still only 1 entry

        let retrieved = storage.get(&key).unwrap();
        assert_eq!(retrieved.value, value2);
    }

    #[test]
    fn test_remove() {
        let mut storage = DhtStorage::new();
        let key = [1u8; 32];
        let value = b"test".to_vec();
        let (publisher_public_key, publisher_node_id, signature) =
            create_signed_value(key, value.clone(), 3600);

        storage
            .store(
                key,
                value,
                3600,
                publisher_public_key,
                publisher_node_id,
                signature,
            )
            .unwrap();
        assert_eq!(storage.key_count(), 1);

        let removed = storage.remove(&key);
        assert!(removed.is_some());
        assert_eq!(storage.key_count(), 0);
        assert_eq!(storage.size(), 0);
    }

    #[test]
    fn test_expired_entry() {
        let mut storage = DhtStorage::new();
        let key = [1u8; 32];
        let value = b"test".to_vec();
        let (publisher_public_key, publisher_node_id, signature) =
            create_signed_value(key, value.clone(), 0);

        // Store with 0 TTL (immediately expired)
        storage
            .store(
                key,
                value,
                0,
                publisher_public_key,
                publisher_node_id,
                signature,
            )
            .unwrap();

        // Should not be retrievable
        assert!(storage.get(&key).is_none());
    }

    #[test]
    fn test_cleanup_expired() {
        let mut storage = DhtStorage::new();

        // Add expired entry
        let key1 = [1u8; 32];
        let value1 = b"expired".to_vec();
        let (pk1, node_id1, signature1) = create_signed_value(key1, value1.clone(), 0);
        storage
            .store(key1, value1, 0, pk1, node_id1, signature1)
            .unwrap();

        // Add valid entry
        let key2 = [2u8; 32];
        let value2 = b"valid".to_vec();
        let (pk2, node_id2, signature2) = create_signed_value(key2, value2.clone(), 3600);
        storage
            .store(key2, value2, 3600, pk2, node_id2, signature2)
            .unwrap();

        assert_eq!(storage.key_count(), 2);

        let removed = storage.cleanup_expired();
        assert_eq!(removed, 1);
        assert_eq!(storage.key_count(), 1);
    }

    #[test]
    fn test_clear() {
        let mut storage = DhtStorage::new();
        let key = [1u8; 32];
        let value = b"test".to_vec();
        let (publisher_public_key, publisher_node_id, signature) =
            create_signed_value(key, value.clone(), 3600);

        storage
            .store(
                key,
                value,
                3600,
                publisher_public_key,
                publisher_node_id,
                signature,
            )
            .unwrap();
        assert_eq!(storage.key_count(), 1);

        storage.clear();
        assert_eq!(storage.key_count(), 0);
        assert_eq!(storage.size(), 0);
    }

    #[test]
    fn test_ttl_remaining() {
        use blake2::{Blake2b512, Digest};

        init_sodiumoxide();
        let (pk, _sk) = ed25519::gen_keypair();
        let mut pk_bytes = [0u8; 32];
        pk_bytes.copy_from_slice(&pk[..]);

        // Derive NodeID from public key
        let mut hasher = Blake2b512::new();
        hasher.update(pk_bytes);
        let hash = hasher.finalize();
        let mut node_id = [0u8; 64];
        node_id.copy_from_slice(&hash);

        let entry = StorageEntry {
            key: [0u8; 32],
            value: vec![],
            stored_at: now(),
            expires_at: now() + 3600,
            publisher_public_key: pk_bytes,
            publisher_node_id: node_id,
            signature: [0u8; 64],
        };

        let ttl = entry.ttl_remaining();
        assert!(ttl > 0 && ttl <= 3600);
    }

    #[test]
    fn test_invalid_signature_rejected() {
        // SECURITY TEST H7: Verify invalid signatures are rejected
        use blake2::{Blake2b512, Digest};

        let mut storage = DhtStorage::new();
        let key = [1u8; 32];
        let value = b"test value".to_vec();

        init_sodiumoxide();
        let (pk, _sk) = ed25519::gen_keypair();
        let mut pk_bytes = [0u8; 32];
        pk_bytes.copy_from_slice(&pk[..]);

        // Derive NodeID
        let mut hasher = Blake2b512::new();
        hasher.update(pk_bytes);
        let hash = hasher.finalize();
        let mut node_id = [0u8; 64];
        node_id.copy_from_slice(&hash);

        let invalid_signature = [0u8; 64]; // Invalid signature

        let result = storage.store(key, value, 3600, pk_bytes, node_id, invalid_signature);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), DhtError::InvalidSignature));
    }

    #[test]
    fn test_tampered_value_rejected() {
        // SECURITY TEST H7: Verify tampered values are rejected
        let mut storage = DhtStorage::new();
        let key = [1u8; 32];
        let original_value = b"original value".to_vec();
        let tampered_value = b"tampered value".to_vec();

        // Sign the original value
        let (publisher_public_key, publisher_node_id, signature) =
            create_signed_value(key, original_value.clone(), 3600);

        // Try to store tampered value with original signature
        let result = storage.store(
            key,
            tampered_value,
            3600,
            publisher_public_key,
            publisher_node_id,
            signature,
        );
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), DhtError::InvalidSignature));
    }

    #[test]
    fn test_valid_signature_accepted() {
        // SECURITY TEST H7: Verify valid signatures are accepted
        let mut storage = DhtStorage::new();
        let key = [1u8; 32];
        let value = b"test value".to_vec();
        let (publisher_public_key, publisher_node_id, signature) =
            create_signed_value(key, value.clone(), 3600);

        let result = storage.store(
            key,
            value,
            3600,
            publisher_public_key,
            publisher_node_id,
            signature,
        );
        assert!(result.is_ok());
        assert_eq!(storage.key_count(), 1);
    }

    #[test]
    fn test_wrong_key_signature_rejected() {
        // SECURITY TEST H7: Verify signature for different key is rejected
        let mut storage = DhtStorage::new();
        let key1 = [1u8; 32];
        let key2 = [2u8; 32];
        let value = b"test value".to_vec();

        // Sign with key1
        let (publisher_public_key, publisher_node_id, signature) =
            create_signed_value(key1, value.clone(), 3600);

        // Try to store with key2 but signature for key1
        let result = storage.store(
            key2,
            value,
            3600,
            publisher_public_key,
            publisher_node_id,
            signature,
        );
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), DhtError::InvalidSignature));
    }

    #[test]
    fn test_per_node_key_quota() {
        // SECURITY TEST M2: Verify per-node key quota enforcement
        use blake2::{Blake2b512, Digest};

        let mut storage = DhtStorage::with_quotas(10_000, 100, 5, 5000); // Max 5 keys per node

        let value = b"test".to_vec();

        init_sodiumoxide();
        let (pk, sk) = ed25519::gen_keypair();
        let mut pk_bytes = [0u8; 32];
        pk_bytes.copy_from_slice(&pk[..]);

        // Derive NodeID
        let mut hasher = Blake2b512::new();
        hasher.update(pk_bytes);
        let hash = hasher.finalize();
        let mut node_id = [0u8; 64];
        node_id.copy_from_slice(&hash);

        // Store 5 keys (should succeed)
        for i in 0..5 {
            let mut key = [0u8; 32];
            key[0] = i as u8;
            let signature = sign_value(&key, &value, now() + 3600, &sk);
            assert!(storage
                .store(key, value.clone(), 3600, pk_bytes, node_id, signature)
                .is_ok());
        }

        // Verify quota tracking
        let (keys, bytes) = storage.get_node_usage(&node_id);
        assert_eq!(keys, 5);
        assert_eq!(bytes, 5 * value.len());

        // Try to store 6th key (should fail)
        let mut key6 = [0u8; 32];
        key6[0] = 6;
        let signature6 = sign_value(&key6, &value, now() + 3600, &sk);
        let result = storage.store(key6, value.clone(), 3600, pk_bytes, node_id, signature6);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            DhtError::NodeQuotaExceeded { .. }
        ));
    }

    #[test]
    fn test_per_node_byte_quota() {
        // SECURITY TEST M2: Verify per-node byte quota enforcement
        use blake2::{Blake2b512, Digest};

        let mut storage = DhtStorage::with_quotas(10_000, 100, 100, 1000); // Max 1000 bytes per node

        init_sodiumoxide();
        let (pk, sk) = ed25519::gen_keypair();
        let mut pk_bytes = [0u8; 32];
        pk_bytes.copy_from_slice(&pk[..]);

        // Derive NodeID
        let mut hasher = Blake2b512::new();
        hasher.update(pk_bytes);
        let hash = hasher.finalize();
        let mut node_id = [0u8; 64];
        node_id.copy_from_slice(&hash);

        // Store values totaling 1000 bytes (should succeed)
        let value1 = vec![0u8; 500];
        let key1 = [1u8; 32];
        let sig1 = sign_value(&key1, &value1, now() + 3600, &sk);
        assert!(storage
            .store(key1, value1, 3600, pk_bytes, node_id, sig1)
            .is_ok());

        let value2 = vec![0u8; 500];
        let key2 = [2u8; 32];
        let sig2 = sign_value(&key2, &value2, now() + 3600, &sk);
        assert!(storage
            .store(key2, value2, 3600, pk_bytes, node_id, sig2)
            .is_ok());

        // Verify quota tracking
        let (keys, bytes) = storage.get_node_usage(&node_id);
        assert_eq!(keys, 2);
        assert_eq!(bytes, 1000);

        // Try to store more bytes (should fail)
        let value3 = vec![0u8; 100];
        let key3 = [3u8; 32];
        let sig3 = sign_value(&key3, &value3, now() + 3600, &sk);
        let result = storage.store(key3, value3, 3600, pk_bytes, node_id, sig3);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            DhtError::NodeQuotaExceeded { .. }
        ));
    }

    #[test]
    fn test_quota_update_on_removal() {
        // SECURITY TEST M2: Verify quotas are updated when entries are removed
        let mut storage = DhtStorage::with_quotas(10_000, 100, 10, 5000);

        let value = b"test value".to_vec();
        let key = [1u8; 32];
        let (publisher_public_key, publisher_node_id, signature) =
            create_signed_value(key, value.clone(), 3600);

        // Store a value
        storage
            .store(
                key,
                value.clone(),
                3600,
                publisher_public_key,
                publisher_node_id,
                signature,
            )
            .unwrap();

        // Check quota
        let (keys, bytes) = storage.get_node_usage(&publisher_node_id);
        assert_eq!(keys, 1);
        assert_eq!(bytes, value.len());

        // Remove the value
        storage.remove(&key);

        // Verify quota is cleared
        let (keys, bytes) = storage.get_node_usage(&publisher_node_id);
        assert_eq!(keys, 0);
        assert_eq!(bytes, 0);
    }

    #[test]
    fn test_quota_update_on_expiration() {
        // SECURITY TEST M2: Verify quotas are updated when entries expire
        let mut storage = DhtStorage::with_quotas(10_000, 100, 10, 5000);

        let value = b"test value".to_vec();
        let key = [1u8; 32];
        let (publisher_public_key, publisher_node_id, signature) =
            create_signed_value(key, value.clone(), 0); // Immediate expiration

        // Store with 0 TTL
        storage
            .store(
                key,
                value.clone(),
                0,
                publisher_public_key,
                publisher_node_id,
                signature,
            )
            .unwrap();

        // Check quota before cleanup
        let (keys, _bytes) = storage.get_node_usage(&publisher_node_id);
        assert_eq!(keys, 1);

        // Cleanup expired entries
        storage.cleanup_expired();

        // Verify quota is cleared
        let (keys, bytes) = storage.get_node_usage(&publisher_node_id);
        assert_eq!(keys, 0);
        assert_eq!(bytes, 0);
    }

    #[test]
    fn test_multiple_publishers_independent_quotas() {
        // SECURITY TEST M2: Verify each publisher has independent quotas
        use blake2::{Blake2b512, Digest};

        let mut storage = DhtStorage::with_quotas(10_000, 100, 5, 5000);

        init_sodiumoxide();

        // Publisher 1
        let (pk1, sk1) = ed25519::gen_keypair();
        let mut publisher1 = [0u8; 32];
        publisher1.copy_from_slice(&pk1[..]);
        let mut hasher1 = Blake2b512::new();
        hasher1.update(publisher1);
        let hash1 = hasher1.finalize();
        let mut node_id1 = [0u8; 64];
        node_id1.copy_from_slice(&hash1);

        // Publisher 2
        let (pk2, sk2) = ed25519::gen_keypair();
        let mut publisher2 = [0u8; 32];
        publisher2.copy_from_slice(&pk2[..]);
        let mut hasher2 = Blake2b512::new();
        hasher2.update(publisher2);
        let hash2 = hasher2.finalize();
        let mut node_id2 = [0u8; 64];
        node_id2.copy_from_slice(&hash2);

        let value = b"test".to_vec();

        // Store 5 keys for publisher 1
        for i in 0..5 {
            let mut key = [1u8; 32];
            key[0] = i as u8;
            let signature = sign_value(&key, &value, now() + 3600, &sk1);
            assert!(storage
                .store(key, value.clone(), 3600, publisher1, node_id1, signature)
                .is_ok());
        }

        // Store 5 keys for publisher 2 (should also succeed)
        for i in 0..5 {
            let mut key = [2u8; 32];
            key[0] = i as u8;
            let signature = sign_value(&key, &value, now() + 3600, &sk2);
            assert!(storage
                .store(key, value.clone(), 3600, publisher2, node_id2, signature)
                .is_ok());
        }

        // Verify independent quotas
        let (keys1, _bytes1) = storage.get_node_usage(&node_id1);
        assert_eq!(keys1, 5);

        let (keys2, _bytes2) = storage.get_node_usage(&node_id2);
        assert_eq!(keys2, 5);

        // Publisher 1 cannot store more
        let mut key6 = [1u8; 32];
        key6[0] = 6;
        let signature = sign_value(&key6, &value, now() + 3600, &sk1);
        let result = storage.store(key6, value.clone(), 3600, publisher1, node_id1, signature);
        assert!(result.is_err());
    }

    #[test]
    fn test_quota_allows_value_update() {
        // SECURITY TEST M2: Verify updating existing value doesn't exceed key quota
        use blake2::{Blake2b512, Digest};

        let mut storage = DhtStorage::with_quotas(10_000, 100, 1, 5000); // Only 1 key per node

        init_sodiumoxide();
        let (pk, sk) = ed25519::gen_keypair();
        let mut publisher = [0u8; 32];
        publisher.copy_from_slice(&pk[..]);

        // Derive NodeID
        let mut hasher = Blake2b512::new();
        hasher.update(publisher);
        let hash = hasher.finalize();
        let mut publisher_node_id = [0u8; 64];
        publisher_node_id.copy_from_slice(&hash);

        let key = [1u8; 32];

        // Store initial value
        let value1 = b"first value".to_vec();
        let sig1 = sign_value(&key, &value1, now() + 3600, &sk);
        assert!(storage
            .store(key, value1, 3600, publisher, publisher_node_id, sig1)
            .is_ok());

        // Update with different value (should succeed even though quota is 1 key)
        let value2 = b"second value".to_vec();
        let sig2 = sign_value(&key, &value2, now() + 3600, &sk);
        assert!(storage
            .store(
                key,
                value2.clone(),
                3600,
                publisher,
                publisher_node_id,
                sig2
            )
            .is_ok());

        // Verify still only 1 key in quota
        let (keys, bytes) = storage.get_node_usage(&publisher_node_id);
        assert_eq!(keys, 1);
        assert_eq!(bytes, value2.len());
    }
}
