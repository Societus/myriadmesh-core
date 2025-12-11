//! DHT operations (FIND_NODE, STORE, FIND_VALUE)

use crate::node_info::PublicNodeInfo;
use myriadmesh_protocol::NodeId;
use serde::{Deserialize, Serialize};

/// Query ID for tracking requests/responses
pub type QueryId = [u8; 16];

/// Generate a random query ID
pub fn generate_query_id() -> QueryId {
    use rand::Rng;
    let mut id = [0u8; 16];
    rand::thread_rng().fill(&mut id);
    id
}

/// FIND_NODE request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindNodeRequest {
    /// Query ID for matching request/response
    pub query_id: QueryId,

    /// Target node ID to find
    pub target: NodeId,

    /// Requestor node ID
    pub requestor: NodeId,
}

impl FindNodeRequest {
    pub fn new(target: NodeId, requestor: NodeId) -> Self {
        FindNodeRequest {
            query_id: generate_query_id(),
            target,
            requestor,
        }
    }
}

/// FIND_NODE response
///
/// SECURITY: Returns PublicNodeInfo which excludes adapter addresses
/// to prevent de-anonymization of i2p/Tor nodes
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindNodeResponse {
    /// Query ID matching the request
    pub query_id: QueryId,

    /// Closest nodes to the target (up to k nodes)
    /// Uses PublicNodeInfo to preserve privacy
    pub nodes: Vec<PublicNodeInfo>,
}

/// STORE request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoreRequest {
    /// Query ID
    pub query_id: QueryId,

    /// Key to store
    pub key: [u8; 32],

    /// Value to store
    pub value: Vec<u8>,

    /// Time-to-live in seconds
    pub ttl: u32,

    /// Publisher node ID
    pub publisher: NodeId,

    /// Signature over (key || value)
    pub signature: Vec<u8>,
}

/// STORE acknowledgment
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoreAck {
    /// Query ID matching the request
    pub query_id: QueryId,

    /// Whether store was successful
    pub success: bool,

    /// Optional error message
    pub error: Option<String>,
}

/// FIND_VALUE request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindValueRequest {
    /// Query ID
    pub query_id: QueryId,

    /// Key to find
    pub key: [u8; 32],

    /// Requestor node ID
    pub requestor: NodeId,
}

impl FindValueRequest {
    pub fn new(key: [u8; 32], requestor: NodeId) -> Self {
        FindValueRequest {
            query_id: generate_query_id(),
            key,
            requestor,
        }
    }
}

/// FIND_VALUE response
///
/// SECURITY: Returns PublicNodeInfo which excludes adapter addresses
/// to prevent de-anonymization of i2p/Tor nodes
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FindValueResponse {
    /// Value was found
    Found {
        query_id: QueryId,
        key: [u8; 32],
        value: Vec<u8>,
        signature: Vec<u8>,
    },

    /// Value not found, here are closer nodes
    /// Uses PublicNodeInfo to preserve privacy
    NotFound {
        query_id: QueryId,
        nodes: Vec<PublicNodeInfo>,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use myriadmesh_protocol::types::NODE_ID_SIZE;

    #[test]
    fn test_generate_query_id() {
        let id1 = generate_query_id();
        let id2 = generate_query_id();

        // Should be different (with very high probability)
        assert_ne!(id1, id2);
    }

    #[test]
    fn test_find_node_request() {
        let target = NodeId::from_bytes([1u8; NODE_ID_SIZE]);
        let requestor = NodeId::from_bytes([2u8; NODE_ID_SIZE]);

        let req = FindNodeRequest::new(target, requestor);

        assert_eq!(req.target, target);
        assert_eq!(req.requestor, requestor);
    }

    #[test]
    fn test_find_value_request() {
        let key = [1u8; 32];
        let requestor = NodeId::from_bytes([2u8; NODE_ID_SIZE]);

        let req = FindValueRequest::new(key, requestor);

        assert_eq!(req.key, key);
        assert_eq!(req.requestor, requestor);
    }

    #[test]
    fn test_find_value_response_found() {
        let query_id = generate_query_id();
        let key = [1u8; 32];
        let value = b"test value".to_vec();
        let signature = vec![0u8; 64];

        let response = FindValueResponse::Found {
            query_id,
            key,
            value: value.clone(),
            signature,
        };

        match response {
            FindValueResponse::Found { value: v, .. } => assert_eq!(v, value),
            _ => panic!("Expected Found variant"),
        }
    }

    #[test]
    fn test_store_ack() {
        let ack = StoreAck {
            query_id: generate_query_id(),
            success: true,
            error: None,
        };

        assert!(ack.success);
        assert!(ack.error.is_none());
    }
}
