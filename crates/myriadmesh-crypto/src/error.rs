//! Error types for cryptographic operations

use thiserror::Error;

pub type Result<T> = std::result::Result<T, CryptoError>;

#[derive(Error, Debug, Clone, PartialEq)]
pub enum CryptoError {
    #[error("Failed to initialize cryptography library")]
    InitializationFailed,

    #[error("Key generation failed")]
    KeyGenerationFailed,

    #[error("Invalid key format")]
    InvalidKeyFormat,

    #[error("Invalid key length: expected {expected}, got {actual}")]
    InvalidKeyLength { expected: usize, actual: usize },

    #[error("Encryption failed")]
    EncryptionFailed,

    #[error("Decryption failed")]
    DecryptionFailed,

    #[error("Signature generation failed")]
    SignatureFailed,

    #[error("Signature verification failed")]
    VerificationFailed,

    #[error("Key exchange failed")]
    KeyExchangeFailed,

    #[error("Key derivation failed")]
    KeyDerivationFailed,

    #[error("Invalid nonce")]
    InvalidNonce,

    #[error("Invalid signature")]
    InvalidSignature,

    #[error("Serialization error: {0}")]
    SerializationError(String),

    #[error("Deserialization error: {0}")]
    DeserializationError(String),

    #[error("Invalid state: {0}")]
    InvalidState(String),

    #[error("System time error: {0}")]
    SystemTimeError(String),
}
