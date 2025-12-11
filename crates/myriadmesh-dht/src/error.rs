//! DHT error types

use thiserror::Error;

/// DHT-specific errors
#[derive(Error, Debug)]
pub enum DhtError {
    #[error("Node not found: {0}")]
    NodeNotFound(String),

    #[error("Key not found")]
    KeyNotFound,

    #[error("Storage full (max {max} bytes)")]
    StorageFull { max: usize },

    #[error("Value too large: {size} bytes (max {max})")]
    ValueTooLarge { size: usize, max: usize },

    #[error("Too many keys (max {0})")]
    TooManyKeys(usize),

    // SECURITY M2: Per-node quota exceeded
    #[error(
        "Node quota exceeded: {current_keys}/{max_keys} keys, {current_bytes}/{max_bytes} bytes"
    )]
    NodeQuotaExceeded {
        publisher: [u8; 64],
        current_keys: usize,
        current_bytes: usize,
        max_keys: usize,
        max_bytes: usize,
    },

    #[error("Invalid signature")]
    InvalidSignature,

    #[error("Invalid public key")]
    InvalidPublicKey,

    #[error("Not responsible for key")]
    NotResponsible,

    #[error("Operation timeout")]
    Timeout,

    #[error("Query timeout")]
    QueryTimeout,

    #[error("No known nodes in routing table")]
    NoKnownNodes,

    #[error("Insufficient nodes for operation")]
    InsufficientNodes,

    #[error("Bucket full")]
    BucketFull,

    #[error("Invalid Proof-of-Work: {0}")]
    InvalidProofOfWork(String),

    #[error("Protocol error: {0}")]
    Protocol(#[from] myriadmesh_protocol::ProtocolError),

    #[error("Crypto error: {0}")]
    Crypto(#[from] myriadmesh_crypto::CryptoError),

    #[error("Serialization error: {0}")]
    Serialization(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Other error: {0}")]
    Other(String),
}

/// Result type for DHT operations
pub type Result<T> = std::result::Result<T, DhtError>;
