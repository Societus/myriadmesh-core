//! Key exchange using X25519 ECDH and HKDF for key derivation
//!
//! This module provides functionality for establishing shared secrets between nodes.

use serde::{Deserialize, Serialize};
use sodiumoxide::crypto::kx;

use crate::encryption::SymmetricKey;
use crate::error::{CryptoError, Result};

/// Size of X25519 public key in bytes
pub const X25519_PUBLIC_KEY_SIZE: usize = 32;

/// Size of X25519 secret key in bytes
pub const X25519_SECRET_KEY_SIZE: usize = 32;

/// X25519 key pair for key exchange
#[derive(Clone)]
pub struct KeyExchangeKeypair {
    pub public_key: kx::PublicKey,
    pub secret_key: kx::SecretKey,
}

impl KeyExchangeKeypair {
    /// Generate a new random key exchange keypair
    pub fn generate() -> Self {
        let (public_key, secret_key) = kx::gen_keypair();
        KeyExchangeKeypair {
            public_key,
            secret_key,
        }
    }

    /// Create keypair from raw bytes
    pub fn from_bytes(public_bytes: &[u8], secret_bytes: &[u8]) -> Result<Self> {
        let public_key =
            kx::PublicKey::from_slice(public_bytes).ok_or(CryptoError::InvalidKeyFormat)?;
        let secret_key =
            kx::SecretKey::from_slice(secret_bytes).ok_or(CryptoError::InvalidKeyFormat)?;

        Ok(KeyExchangeKeypair {
            public_key,
            secret_key,
        })
    }

    /// Export public key as bytes
    pub fn public_bytes(&self) -> &[u8] {
        self.public_key.as_ref()
    }

    /// Export secret key as bytes
    pub fn secret_bytes(&self) -> &[u8] {
        self.secret_key.as_ref()
    }
}

impl std::fmt::Debug for KeyExchangeKeypair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyExchangeKeypair")
            .field("public_key", &hex::encode(self.public_key.as_ref()))
            .finish()
    }
}

/// X25519 public key for serialization
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct X25519PublicKey([u8; X25519_PUBLIC_KEY_SIZE]);

impl X25519PublicKey {
    /// Create from bytes
    pub fn from_bytes(bytes: [u8; X25519_PUBLIC_KEY_SIZE]) -> Self {
        X25519PublicKey(bytes)
    }

    /// Get bytes
    pub fn as_bytes(&self) -> &[u8; X25519_PUBLIC_KEY_SIZE] {
        &self.0
    }

    /// Convert to sodiumoxide public key
    pub fn to_sodiumoxide(&self) -> Result<kx::PublicKey> {
        kx::PublicKey::from_slice(&self.0).ok_or(CryptoError::InvalidKeyFormat)
    }

    /// Convert to hex string
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// Parse from hex string
    pub fn from_hex(s: &str) -> Result<Self> {
        let bytes = hex::decode(s).map_err(|e| CryptoError::SerializationError(e.to_string()))?;

        if bytes.len() != X25519_PUBLIC_KEY_SIZE {
            return Err(CryptoError::InvalidKeyLength {
                expected: X25519_PUBLIC_KEY_SIZE,
                actual: bytes.len(),
            });
        }

        let mut arr = [0u8; X25519_PUBLIC_KEY_SIZE];
        arr.copy_from_slice(&bytes);
        Ok(X25519PublicKey(arr))
    }
}

impl From<&kx::PublicKey> for X25519PublicKey {
    fn from(key: &kx::PublicKey) -> Self {
        let mut bytes = [0u8; X25519_PUBLIC_KEY_SIZE];
        bytes.copy_from_slice(key.as_ref());
        X25519PublicKey(bytes)
    }
}

impl std::fmt::Debug for X25519PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "X25519PublicKey({}...)", &self.to_hex()[..16])
    }
}

/// Session keys derived from key exchange
#[derive(Debug)]
pub struct SessionKeys {
    /// Key for encrypting messages sent by the client
    pub tx_key: SymmetricKey,
    /// Key for decrypting messages received by the client
    pub rx_key: SymmetricKey,
}

/// Perform key exchange as the client (initiator)
pub fn client_session_keys(
    client_keypair: &KeyExchangeKeypair,
    server_public_key: &X25519PublicKey,
) -> Result<SessionKeys> {
    let server_pk = server_public_key.to_sodiumoxide()?;

    let (rx, tx) = kx::client_session_keys(
        &client_keypair.public_key,
        &client_keypair.secret_key,
        &server_pk,
    )
    .map_err(|_| CryptoError::KeyExchangeFailed)?;

    Ok(SessionKeys {
        tx_key: SymmetricKey::from_bytes(tx.as_ref())?,
        rx_key: SymmetricKey::from_bytes(rx.as_ref())?,
    })
}

/// Perform key exchange as the server (responder)
pub fn server_session_keys(
    server_keypair: &KeyExchangeKeypair,
    client_public_key: &X25519PublicKey,
) -> Result<SessionKeys> {
    let client_pk = client_public_key.to_sodiumoxide()?;

    let (rx, tx) = kx::server_session_keys(
        &server_keypair.public_key,
        &server_keypair.secret_key,
        &client_pk,
    )
    .map_err(|_| CryptoError::KeyExchangeFailed)?;

    Ok(SessionKeys {
        tx_key: SymmetricKey::from_bytes(tx.as_ref())?,
        rx_key: SymmetricKey::from_bytes(rx.as_ref())?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encryption::{decrypt, encrypt};

    #[test]
    fn test_key_exchange() {
        crate::init().unwrap();

        let client_kp = KeyExchangeKeypair::generate();
        let server_kp = KeyExchangeKeypair::generate();

        let client_pub = X25519PublicKey::from(&client_kp.public_key);
        let server_pub = X25519PublicKey::from(&server_kp.public_key);

        let client_keys = client_session_keys(&client_kp, &server_pub).unwrap();
        let server_keys = server_session_keys(&server_kp, &client_pub).unwrap();

        // Client's TX key should match server's RX key
        // and client's RX key should match server's TX key
        let plaintext = b"Hello from client";

        let encrypted = encrypt(&client_keys.tx_key, plaintext).unwrap();
        let decrypted = decrypt(&server_keys.rx_key, &encrypted).unwrap();
        assert_eq!(plaintext.as_slice(), decrypted.as_slice());

        let plaintext2 = b"Hello from server";
        let encrypted2 = encrypt(&server_keys.tx_key, plaintext2).unwrap();
        let decrypted2 = decrypt(&client_keys.rx_key, &encrypted2).unwrap();
        assert_eq!(plaintext2.as_slice(), decrypted2.as_slice());
    }

    #[test]
    fn test_keypair_serialization() {
        crate::init().unwrap();

        let kp = KeyExchangeKeypair::generate();
        let pub_bytes = kp.public_bytes();
        let sec_bytes = kp.secret_bytes();

        let restored = KeyExchangeKeypair::from_bytes(pub_bytes, sec_bytes).unwrap();

        // Use the restored keypair in a key exchange
        let server_kp = KeyExchangeKeypair::generate();
        let server_pub = X25519PublicKey::from(&server_kp.public_key);

        let keys = client_session_keys(&restored, &server_pub).unwrap();
        // If this doesn't panic, the keys work
        let _ = encrypt(&keys.tx_key, b"test").unwrap();
    }

    #[test]
    fn test_x25519_public_key_hex() {
        crate::init().unwrap();

        let kp = KeyExchangeKeypair::generate();
        let pub_key = X25519PublicKey::from(&kp.public_key);

        let hex = pub_key.to_hex();
        assert_eq!(hex.len(), X25519_PUBLIC_KEY_SIZE * 2);

        let parsed = X25519PublicKey::from_hex(&hex).unwrap();
        assert_eq!(pub_key, parsed);
    }
}
