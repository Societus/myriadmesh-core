//! MyriadMesh DHT (Distributed Hash Table)
//!
//! This module implements a Kademlia-based DHT for:
//! - Node discovery and routing
//! - Decentralized key-value storage
//! - Message store-and-forward for offline nodes
//! - Route record storage for performance optimization

pub mod blacklist;
pub mod dht;
pub mod error;
pub mod iterative_lookup;
pub mod kbucket;
pub mod node_info;
pub mod operations;
pub mod reputation;
pub mod request_handler;
pub mod routing_table;
pub mod rpc_transport;
pub mod storage;

pub use blacklist::{BlacklistEntry, BlacklistReason, BlacklistStats, NodeBlacklist};
pub use dht::{DhtService, DhtTransport};
pub use error::{DhtError, Result};
pub use iterative_lookup::{iterative_find_node, IterativeLookup, LookupResult, LookupStats, LookupTransport};
pub use kbucket::KBucket;
pub use node_info::{AdapterInfo, NodeCapabilities, NodeInfo, PublicNodeInfo};
pub use operations::{FindNodeRequest, FindNodeResponse, FindValueRequest, FindValueResponse, StoreRequest, StoreAck};
pub use reputation::{NodeReputation, ReputationManager};
pub use request_handler::DhtRequestHandler;
pub use routing_table::RoutingTable;
pub use rpc_transport::NetworkRpcTransport;
pub use storage::{DhtStorage, StorageEntry};

/// Kademlia k parameter (nodes per k-bucket)
pub const K: usize = 20;

/// Alpha parameter (parallel queries)
pub const ALPHA: usize = 3;

/// Maximum DHT storage per node (bytes)
pub const MAX_DHT_STORAGE_BYTES: usize = 100 * 1024 * 1024; // 100MB

/// Maximum number of DHT keys
pub const MAX_DHT_KEYS: usize = 10_000;

/// Maximum value size (bytes)
pub const MAX_VALUE_SIZE: usize = 1024 * 1024; // 1MB

#[cfg(test)]
mod tests {
    #[test]
    fn test_placeholder() {
        assert_eq!(2 + 2, 4);
    }
}
