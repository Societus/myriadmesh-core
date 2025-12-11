//! MyriadMesh Message Routing
//!
//! This module implements the message router for Phase 2 & Phase 4:
//!
//! ## Phase 2 (Basic Routing)
//! - Priority queue system (5 levels)
//! - Direct and multi-hop routing
//! - Store-and-forward for offline nodes
//! - Message deduplication
//! - Content tag filtering (optional)
//!
//! ## Phase 4 (Advanced Routing)
//! - Geographic routing with location-based path selection
//! - Multi-path routing with parallel transmission
//! - Adaptive routing with dynamic path updates
//! - Quality of Service (QoS) with bandwidth reservation

pub mod adaptive;
pub mod adapter_selector;
pub mod bandwidth_monitor;
pub mod circuit_breaker;
pub mod consensus;
pub mod consensus_validator;
pub mod deduplication;
pub mod dht_resolver;
pub mod emergency_manager;
pub mod error;
pub mod failure_detection;
pub mod fragmentation;
pub mod geographic;
pub mod ml_predictor;
pub mod multipath;
pub mod offline_cache;
pub mod path_selector;
pub mod priority_queue;
pub mod queue_processor;
pub mod qos;
pub mod rate_limiter;
pub mod relay_scoring;
pub mod reputation;
pub mod router;
pub mod routing_strategies;
pub mod store_and_forward;
pub mod transmission;

pub use adaptive::{
    AdaptiveRoutingStats, AdaptiveRoutingTable, CostWeights, LinkMetrics, RoutingPolicy,
};
pub use adapter_selector::{AdapterSelector, AdapterId, AdapterTier, NetworkConditions};
pub use bandwidth_monitor::{BandwidthMonitor, BandwidthMonitorConfig, Direction, UtilizationResult};
pub use circuit_breaker::{CircuitBreaker, CircuitBreakerStats, CircuitState};
pub use consensus::{ConsensusConfig as RelayConsensusConfig, ConsensusManager, ConsensusProposal, ConsensusResult as RelayConsensusResult, ConsensusStats as RelayConsensusStats, ConsensusType, ConsensusVote};
pub use consensus_validator::{ConsensusConfig, ConsensusResult, ConsensusStats, ConsensusValidator};
pub use deduplication::DeduplicationCache;
pub use dht_resolver::{DhtResolver, DhtResolverConfig, DhtResolverStats};
pub use emergency_manager::{EmergencyManager, EmergencyManagerConfig, EmergencyStats, EmergencyValidation};
pub use error::{Result, RoutingError};
pub use failure_detection::{FailureDetectionConfig, FailureDetectionManager, FailureDetectionStats, NodeStatus};
pub use fragmentation::{
    fragment_frame, FragmentHeader, FragmentReassembler, FragmentationDecision, FragmentationReason,
};
pub use geographic::{GeoCoordinates, GeoRoutingTable, NodeLocation};
pub use ml_predictor::{PathFeatures, PathPredictor, Prediction, TrainingSample};
pub use multipath::{MultiPathRouter, MultiPathStats, MultiPathStrategy, NetworkPath};
pub use offline_cache::{CacheStats, OfflineMessageCache};
pub use path_selector::{PathMetrics, PathSelection, PathSelector, RoutingPath};
pub use priority_queue::{PriorityLevel, PriorityQueue};
pub use queue_processor::{QueueProcessor, QueueProcessorConfig, QueueProcessorStats, TransmissionCallback};
pub use qos::{FlowId, FlowStats, QosClass, QosError, QosManager, QosStats};
pub use rate_limiter::RateLimiter;
pub use relay_scoring::{CapacityMetrics, PerformanceMetrics, RelayScore, RelayScoringConfig, RelayScoringManager, ReliabilityMetrics};
pub use reputation::{LedgerTransaction, ReputationScore};
pub use router::{Router, RouterStats};
pub use routing_strategies::EnhancedPathSelector;
pub use store_and_forward::{StoreAndForwardManager, StoreForwardStats, StoreForwardStatus};
pub use transmission::{RetryContext, RetryStrategy, TransmissionConfig, TransmissionResult, TransmissionState};

/// Maximum cached messages per destination
pub const MAX_CACHED_MESSAGES_PER_DEST: usize = 100;

/// Maximum cached message age (seconds)
pub const MAX_CACHED_MESSAGE_AGE_SECS: u64 = 24 * 3600; // 24 hours

/// Maximum total cached messages
pub const MAX_TOTAL_CACHED_MESSAGES: usize = 10_000;

/// Maximum cached message size
pub const MAX_CACHED_MESSAGE_SIZE: usize = 1024 * 1024; // 1MB

/// Size of message deduplication cache
pub const MESSAGE_DEDUP_CACHE_SIZE: usize = 10_000;

/// Message deduplication TTL (seconds)
pub const MESSAGE_DEDUP_TTL_SECS: u64 = 3600; // 1 hour

#[cfg(test)]
mod tests {
    #[test]
    fn test_placeholder() {
        assert_eq!(2 + 2, 4);
    }
}
