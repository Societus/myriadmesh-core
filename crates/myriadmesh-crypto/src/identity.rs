//! Node identity generation and management
//!
//! This module provides functionality for generating and managing node identities
//! using Ed25519 key pairs and BLAKE2b for node ID derivation.

use blake2::{Blake2b512, Digest};
use serde::{Deserialize, Serialize};
use sodiumoxide::crypto::sign::ed25519;
use std::fmt;

use crate::error::{CryptoError, Result};

/// Size of a node ID in bytes (64 bytes / 512 bits)
///
/// SECURITY C6: Increased from 32 to 64 bytes to prevent birthday collision attacks.
/// Birthday attack complexity: 2^(n/2) for n-bit hash
/// - 256-bit: 2^128 ≈ 10^38 operations (potentially feasible for nation-states)
/// - 512-bit: 2^256 ≈ 10^77 operations (exceeds atoms in universe, quantum-resistant)
pub const NODE_ID_SIZE: usize = 64;

/// A unique identifier for a node in the MyriadMesh network
///
/// SECURITY C6: Uses custom serde implementation for 64-byte array support
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct NodeId([u8; NODE_ID_SIZE]);

impl NodeId {
    /// Create a NodeId from a byte array
    pub fn from_bytes(bytes: [u8; NODE_ID_SIZE]) -> Self {
        NodeId(bytes)
    }

    /// Get the bytes of this NodeId
    pub fn as_bytes(&self) -> &[u8; NODE_ID_SIZE] {
        &self.0
    }

    /// Convert to hex string
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// Parse from hex string
    pub fn from_hex(s: &str) -> Result<Self> {
        let bytes = hex::decode(s).map_err(|e| CryptoError::SerializationError(e.to_string()))?;

        if bytes.len() != NODE_ID_SIZE {
            return Err(CryptoError::InvalidKeyLength {
                expected: NODE_ID_SIZE,
                actual: bytes.len(),
            });
        }

        let mut arr = [0u8; NODE_ID_SIZE];
        arr.copy_from_slice(&bytes);
        Ok(NodeId(arr))
    }
}

impl fmt::Debug for NodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "NodeId({})", self.to_hex())
    }
}

impl fmt::Display for NodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", &self.to_hex()[..16])
    }
}

// SECURITY C6: Custom serde implementation for 64-byte arrays
impl Serialize for NodeId {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_bytes(&self.0)
    }
}

impl<'de> Deserialize<'de> for NodeId {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct NodeIdVisitor;

        impl<'de> serde::de::Visitor<'de> for NodeIdVisitor {
            type Value = NodeId;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str(&format!("a byte array of length {}", NODE_ID_SIZE))
            }

            fn visit_bytes<E>(self, v: &[u8]) -> std::result::Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                if v.len() != NODE_ID_SIZE {
                    return Err(E::custom(format!(
                        "Invalid NodeId length: expected {}, got {}",
                        NODE_ID_SIZE,
                        v.len()
                    )));
                }
                let mut bytes = [0u8; NODE_ID_SIZE];
                bytes.copy_from_slice(v);
                Ok(NodeId(bytes))
            }

            fn visit_seq<A>(self, mut seq: A) -> std::result::Result<Self::Value, A::Error>
            where
                A: serde::de::SeqAccess<'de>,
            {
                let mut bytes = [0u8; NODE_ID_SIZE];
                #[allow(clippy::needless_range_loop)]
                for i in 0..NODE_ID_SIZE {
                    bytes[i] = seq
                        .next_element()?
                        .ok_or_else(|| serde::de::Error::invalid_length(i, &self))?;
                }
                Ok(NodeId(bytes))
            }
        }

        deserializer.deserialize_bytes(NodeIdVisitor)
    }
}

/// A node's identity including its key pair
#[derive(Clone)]
pub struct NodeIdentity {
    /// Ed25519 public key
    pub public_key: ed25519::PublicKey,
    /// Ed25519 secret key
    pub secret_key: ed25519::SecretKey,
    /// Derived node ID (BLAKE2b hash of public key)
    pub node_id: NodeId,
}

impl NodeIdentity {
    /// Generate a new random node identity
    pub fn generate() -> Result<Self> {
        let (public_key, secret_key) = ed25519::gen_keypair();
        let node_id = Self::derive_node_id(&public_key);

        Ok(NodeIdentity {
            public_key,
            secret_key,
            node_id,
        })
    }

    /// Derive a node ID from a public key using BLAKE2b-512 (full 512 bits)
    ///
    /// SECURITY C6: Uses full 64-byte BLAKE2b-512 output for maximum collision resistance.
    /// This prevents birthday attacks that could enable identity theft or DHT takeover.
    pub fn derive_node_id(public_key: &ed25519::PublicKey) -> NodeId {
        let mut hasher = Blake2b512::new();
        hasher.update(public_key.as_ref());
        let hash = hasher.finalize();

        // SECURITY C6: Use all 64 bytes (512 bits) of the hash for collision resistance
        let mut node_id = [0u8; NODE_ID_SIZE];
        node_id.copy_from_slice(&hash[..NODE_ID_SIZE]);

        NodeId(node_id)
    }

    /// Create identity from existing keys
    pub fn from_keypair(public_key: ed25519::PublicKey, secret_key: ed25519::SecretKey) -> Self {
        let node_id = Self::derive_node_id(&public_key);
        NodeIdentity {
            public_key,
            secret_key,
            node_id,
        }
    }

    /// Export the secret key as bytes (for secure storage)
    pub fn export_secret_key(&self) -> &[u8] {
        self.secret_key.as_ref()
    }

    /// Export the public key as bytes
    pub fn export_public_key(&self) -> &[u8] {
        self.public_key.as_ref()
    }

    /// Import identity from raw key bytes
    pub fn from_bytes(public_bytes: &[u8], secret_bytes: &[u8]) -> Result<Self> {
        let public_key =
            ed25519::PublicKey::from_slice(public_bytes).ok_or(CryptoError::InvalidKeyFormat)?;
        let secret_key =
            ed25519::SecretKey::from_slice(secret_bytes).ok_or(CryptoError::InvalidKeyFormat)?;

        Ok(Self::from_keypair(public_key, secret_key))
    }
}

impl fmt::Debug for NodeIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NodeIdentity")
            .field("node_id", &self.node_id)
            .field("public_key", &hex::encode(self.public_key.as_ref()))
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_identity() {
        crate::init().unwrap();
        let identity = NodeIdentity::generate().unwrap();

        // Node ID should be 32 bytes
        assert_eq!(identity.node_id.as_bytes().len(), NODE_ID_SIZE);

        // Node ID should be deterministic from public key
        let derived = NodeIdentity::derive_node_id(&identity.public_key);
        assert_eq!(identity.node_id, derived);
    }

    #[test]
    fn test_node_id_hex() {
        crate::init().unwrap();
        let identity = NodeIdentity::generate().unwrap();

        let hex = identity.node_id.to_hex();
        assert_eq!(hex.len(), NODE_ID_SIZE * 2); // 2 hex chars per byte

        let parsed = NodeId::from_hex(&hex).unwrap();
        assert_eq!(identity.node_id, parsed);
    }

    #[test]
    fn test_identity_export_import() {
        crate::init().unwrap();
        let identity = NodeIdentity::generate().unwrap();

        let pub_bytes = identity.export_public_key();
        let sec_bytes = identity.export_secret_key();

        let restored = NodeIdentity::from_bytes(pub_bytes, sec_bytes).unwrap();
        assert_eq!(identity.node_id, restored.node_id);
    }

    #[test]
    fn test_node_id_display() {
        crate::init().unwrap();
        let identity = NodeIdentity::generate().unwrap();

        let display = format!("{}", identity.node_id);
        assert_eq!(display.len(), 16); // First 16 hex chars
    }
}
