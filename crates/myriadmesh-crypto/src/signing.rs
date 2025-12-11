//! Message signing and verification using Ed25519
//!
//! This module provides functionality for signing messages and verifying signatures.

use serde::{Deserialize, Serialize};
use sodiumoxide::crypto::sign::ed25519;

use crate::error::{CryptoError, Result};
use crate::identity::NodeIdentity;

/// Size of Ed25519 signature in bytes
pub const SIGNATURE_SIZE: usize = 64;

/// A cryptographic signature
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Signature([u8; SIGNATURE_SIZE]);

impl Serialize for Signature {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_bytes(&self.0)
    }
}

impl<'de> Deserialize<'de> for Signature {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct SignatureVisitor;

        impl<'de> serde::de::Visitor<'de> for SignatureVisitor {
            type Value = Signature;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("a 64-byte signature")
            }

            fn visit_bytes<E>(self, v: &[u8]) -> std::result::Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                if v.len() != SIGNATURE_SIZE {
                    return Err(E::custom(format!(
                        "invalid signature length: expected {}, got {}",
                        SIGNATURE_SIZE,
                        v.len()
                    )));
                }
                let mut bytes = [0u8; SIGNATURE_SIZE];
                bytes.copy_from_slice(v);
                Ok(Signature(bytes))
            }
        }

        deserializer.deserialize_bytes(SignatureVisitor)
    }
}

impl Signature {
    /// Create a signature from bytes
    pub fn from_bytes(bytes: [u8; SIGNATURE_SIZE]) -> Self {
        Signature(bytes)
    }

    /// Get the signature bytes
    pub fn as_bytes(&self) -> &[u8; SIGNATURE_SIZE] {
        &self.0
    }

    /// Convert to hex string
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// Parse from hex string
    pub fn from_hex(s: &str) -> Result<Self> {
        let bytes = hex::decode(s).map_err(|e| CryptoError::SerializationError(e.to_string()))?;

        if bytes.len() != SIGNATURE_SIZE {
            return Err(CryptoError::InvalidKeyLength {
                expected: SIGNATURE_SIZE,
                actual: bytes.len(),
            });
        }

        let mut arr = [0u8; SIGNATURE_SIZE];
        arr.copy_from_slice(&bytes);
        Ok(Signature(arr))
    }
}

impl std::fmt::Debug for Signature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Signature({}...)", &self.to_hex()[..16])
    }
}

impl std::fmt::Display for Signature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", &self.to_hex()[..16])
    }
}

/// Sign a message using the node's identity
pub fn sign_message(identity: &NodeIdentity, message: &[u8]) -> Result<Signature> {
    let signature = ed25519::sign_detached(message, &identity.secret_key);
    let mut sig_bytes = [0u8; SIGNATURE_SIZE];
    sig_bytes.copy_from_slice(signature.as_ref());
    Ok(Signature::from_bytes(sig_bytes))
}

/// Verify a signature on a message
pub fn verify_signature(
    public_key: &ed25519::PublicKey,
    message: &[u8],
    signature: &Signature,
) -> Result<()> {
    let sig = ed25519::Signature::from_bytes(signature.as_bytes())
        .map_err(|_| CryptoError::InvalidSignature)?;

    if ed25519::verify_detached(&sig, message, public_key) {
        Ok(())
    } else {
        Err(CryptoError::VerificationFailed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sign_and_verify() {
        crate::init().unwrap();
        let identity = NodeIdentity::generate().unwrap();
        let message = b"Hello, MyriadMesh!";

        let signature = sign_message(&identity, message).unwrap();
        assert!(verify_signature(&identity.public_key, message, &signature).is_ok());
    }

    #[test]
    fn test_verify_invalid_signature() {
        crate::init().unwrap();
        let identity = NodeIdentity::generate().unwrap();
        let message = b"Hello, MyriadMesh!";

        let signature = sign_message(&identity, message).unwrap();

        // Try to verify with different message
        let wrong_message = b"Different message";
        assert!(verify_signature(&identity.public_key, wrong_message, &signature).is_err());
    }

    #[test]
    fn test_verify_wrong_key() {
        crate::init().unwrap();
        let identity1 = NodeIdentity::generate().unwrap();
        let identity2 = NodeIdentity::generate().unwrap();
        let message = b"Hello, MyriadMesh!";

        let signature = sign_message(&identity1, message).unwrap();

        // Try to verify with different public key
        assert!(verify_signature(&identity2.public_key, message, &signature).is_err());
    }

    #[test]
    fn test_signature_hex() {
        crate::init().unwrap();
        let identity = NodeIdentity::generate().unwrap();
        let message = b"Test message";

        let signature = sign_message(&identity, message).unwrap();
        let hex = signature.to_hex();
        assert_eq!(hex.len(), SIGNATURE_SIZE * 2);

        let parsed = Signature::from_hex(&hex).unwrap();
        assert_eq!(signature, parsed);
    }
}
