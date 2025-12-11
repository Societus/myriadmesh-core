//! MyriadMesh Cryptography Module
//!
//! This module provides the core cryptographic primitives for the MyriadMesh protocol:
//! - Node identity generation (Ed25519 key pairs)
//! - Key exchange (X25519 ECDH)
//! - Message encryption (XSalsa20-Poly1305 AEAD)
//! - Message signing (Ed25519 signatures)
//! - Key derivation (HKDF)
//! - Encrypted channels for end-to-end encryption

pub mod channel;
pub mod encryption;
pub mod error;
pub mod identity;
pub mod keyexchange;
pub mod signing;

pub use error::{CryptoError, Result};

/// Initialize the cryptography library
///
/// This must be called before using any cryptographic functions.
/// It initializes the underlying sodiumoxide library.
pub fn init() -> Result<()> {
    sodiumoxide::init().map_err(|_| CryptoError::InitializationFailed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_init() {
        assert!(init().is_ok());
    }
}
