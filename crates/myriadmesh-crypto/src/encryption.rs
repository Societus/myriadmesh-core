//! Message encryption using XSalsa20-Poly1305 AEAD
//!
//! This module provides authenticated encryption for messages.

use serde::{Deserialize, Serialize};
use sodiumoxide::crypto::secretbox;
use sodiumoxide::crypto::secretbox::xsalsa20poly1305;

use crate::error::{CryptoError, Result};

/// Size of encryption nonce in bytes
pub const NONCE_SIZE: usize = 24;

/// Size of symmetric encryption key in bytes
pub const KEY_SIZE: usize = 32;

/// A nonce for encryption (must be unique for each message with the same key)
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Nonce([u8; NONCE_SIZE]);

impl Nonce {
    /// Generate a random nonce
    pub fn generate() -> Self {
        Nonce(secretbox::gen_nonce().0)
    }

    /// Create a nonce from bytes
    pub fn from_bytes(bytes: [u8; NONCE_SIZE]) -> Self {
        Nonce(bytes)
    }

    /// Get the nonce bytes
    pub fn as_bytes(&self) -> &[u8; NONCE_SIZE] {
        &self.0
    }

    /// Convert to sodiumoxide nonce
    fn to_sodiumoxide(self) -> xsalsa20poly1305::Nonce {
        xsalsa20poly1305::Nonce(self.0)
    }
}

impl std::fmt::Debug for Nonce {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Nonce({}...)", &hex::encode(&self.0[..8]))
    }
}

/// A symmetric encryption key
#[derive(Clone, Serialize, Deserialize)]
pub struct SymmetricKey(xsalsa20poly1305::Key);

impl SymmetricKey {
    /// Generate a random symmetric key
    pub fn generate() -> Self {
        SymmetricKey(secretbox::gen_key())
    }

    /// Create a key from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != KEY_SIZE {
            return Err(CryptoError::InvalidKeyLength {
                expected: KEY_SIZE,
                actual: bytes.len(),
            });
        }

        let key = xsalsa20poly1305::Key::from_slice(bytes).ok_or(CryptoError::InvalidKeyFormat)?;
        Ok(SymmetricKey(key))
    }

    /// Get the key bytes
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl std::fmt::Debug for SymmetricKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SymmetricKey([REDACTED])")
    }
}

/// Encrypted data with its nonce
#[derive(Clone, Serialize, Deserialize)]
pub struct EncryptedMessage {
    /// The nonce used for encryption
    pub nonce: Nonce,
    /// The encrypted ciphertext (includes authentication tag)
    pub ciphertext: Vec<u8>,
}

impl EncryptedMessage {
    /// Get the total size of the encrypted message
    pub fn size(&self) -> usize {
        NONCE_SIZE + self.ciphertext.len()
    }
}

impl std::fmt::Debug for EncryptedMessage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EncryptedMessage")
            .field("nonce", &self.nonce)
            .field("ciphertext_len", &self.ciphertext.len())
            .finish()
    }
}

/// Encrypt a message with a symmetric key
pub fn encrypt(key: &SymmetricKey, plaintext: &[u8]) -> Result<EncryptedMessage> {
    let nonce = Nonce::generate();
    let ciphertext = secretbox::seal(plaintext, &nonce.to_sodiumoxide(), &key.0);

    Ok(EncryptedMessage { nonce, ciphertext })
}

/// Decrypt a message with a symmetric key
pub fn decrypt(key: &SymmetricKey, encrypted: &EncryptedMessage) -> Result<Vec<u8>> {
    secretbox::open(
        &encrypted.ciphertext,
        &encrypted.nonce.to_sodiumoxide(),
        &key.0,
    )
    .map_err(|_| CryptoError::DecryptionFailed)
}

/// Encrypt with a specific nonce (use with caution - nonce reuse is dangerous)
pub fn encrypt_with_nonce(
    key: &SymmetricKey,
    plaintext: &[u8],
    nonce: &Nonce,
) -> Result<EncryptedMessage> {
    let ciphertext = secretbox::seal(plaintext, &nonce.to_sodiumoxide(), &key.0);

    Ok(EncryptedMessage {
        nonce: *nonce,
        ciphertext,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt() {
        crate::init().unwrap();
        let key = SymmetricKey::generate();
        let plaintext = b"Hello, MyriadMesh!";

        let encrypted = encrypt(&key, plaintext).unwrap();
        let decrypted = decrypt(&key, &encrypted).unwrap();

        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_decrypt_with_wrong_key() {
        crate::init().unwrap();
        let key1 = SymmetricKey::generate();
        let key2 = SymmetricKey::generate();
        let plaintext = b"Secret message";

        let encrypted = encrypt(&key1, plaintext).unwrap();
        assert!(decrypt(&key2, &encrypted).is_err());
    }

    #[test]
    fn test_decrypt_tampered_ciphertext() {
        crate::init().unwrap();
        let key = SymmetricKey::generate();
        let plaintext = b"Important data";

        let mut encrypted = encrypt(&key, plaintext).unwrap();

        // Tamper with ciphertext
        if !encrypted.ciphertext.is_empty() {
            encrypted.ciphertext[0] ^= 0xFF;
        }

        assert!(decrypt(&key, &encrypted).is_err());
    }

    #[test]
    fn test_nonce_uniqueness() {
        crate::init().unwrap();
        let nonce1 = Nonce::generate();
        let nonce2 = Nonce::generate();

        // Statistically, these should never be equal
        assert_ne!(nonce1, nonce2);
    }

    #[test]
    fn test_key_from_bytes() {
        crate::init().unwrap();
        let key1 = SymmetricKey::generate();
        let bytes = key1.as_bytes();

        let key2 = SymmetricKey::from_bytes(bytes).unwrap();
        let plaintext = b"Test message";

        let encrypted = encrypt(&key1, plaintext).unwrap();
        let decrypted = decrypt(&key2, &encrypted).unwrap();

        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_encrypt_with_nonce() {
        crate::init().unwrap();
        let key = SymmetricKey::generate();
        let nonce = Nonce::generate();
        let plaintext = b"Test with nonce";

        let encrypted = encrypt_with_nonce(&key, plaintext, &nonce).unwrap();
        assert_eq!(encrypted.nonce, nonce);

        let decrypted = decrypt(&key, &encrypted).unwrap();
        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }
}
