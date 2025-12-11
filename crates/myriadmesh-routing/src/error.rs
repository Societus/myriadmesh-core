//! Routing error types

use myriadmesh_protocol::message::MessageId;
use thiserror::Error;

/// Routing-specific errors
#[derive(Error, Debug)]
pub enum RoutingError {
    #[error("TTL exceeded")]
    TtlExceeded,

    #[error("Destination not found: {0}")]
    DestinationNotFound(String),

    #[error("No route to destination")]
    NoRoute,

    #[error("Message replay detected")]
    ReplayDetected,

    #[error("Invalid signature")]
    InvalidSignature,

    #[error("Invalid timestamp (drift: {drift_ms}ms)")]
    InvalidTimestamp { drift_ms: i64 },

    #[error("Rate limit exceeded")]
    RateLimitExceeded,

    #[error("Global rate limit exceeded")]
    GlobalRateLimitExceeded,

    #[error("Cache full")]
    CacheFull,

    #[error("Message filtered by policy")]
    MessageFiltered,

    #[error("Insufficient relays for onion routing")]
    InsufficientRelays,

    // SECURITY M1: DOS protection error types
    #[error("Invalid message: {0}")]
    InvalidMessage(String),

    #[error("Duplicate message: {0:?}")]
    DuplicateMessage(MessageId),

    #[error("Rate limited: {0}")]
    RateLimited(String),

    #[error("Queue full: {0}")]
    QueueFull(String),

    #[error("Policy violation: {0}")]
    PolicyViolation(String),

    #[error("Protocol error: {0}")]
    Protocol(#[from] myriadmesh_protocol::ProtocolError),

    #[error("Crypto error: {0}")]
    Crypto(#[from] myriadmesh_crypto::CryptoError),

    #[error("DHT error: {0}")]
    Dht(#[from] myriadmesh_dht::DhtError),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Other error: {0}")]
    Other(String),
}

/// Result type for routing operations
pub type Result<T> = std::result::Result<T, RoutingError>;
