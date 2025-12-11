//! DHT request handler for processing incoming queries
//!
//! This module handles incoming DHT requests from other nodes and generates responses.

use crate::error::Result;
use crate::operations::{
    FindNodeRequest, FindNodeResponse, FindValueRequest, FindValueResponse, StoreAck, StoreRequest,
};
use crate::routing_table::RoutingTable;
use crate::storage::DhtStorage;
use crate::K;
use myriadmesh_protocol::{Frame, MessageId, MessageType, NodeId};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

/// DHT request handler
///
/// Processes incoming DHT queries and generates appropriate responses.
pub struct DhtRequestHandler {
    /// Local node ID
    node_id: NodeId,

    /// Routing table
    routing_table: Arc<RwLock<RoutingTable>>,

    /// Local DHT storage
    storage: Arc<RwLock<DhtStorage>>,
}

impl DhtRequestHandler {
    /// Create a new DHT request handler
    pub fn new(
        node_id: NodeId,
        routing_table: Arc<RwLock<RoutingTable>>,
        storage: Arc<RwLock<DhtStorage>>,
    ) -> Self {
        Self {
            node_id,
            routing_table,
            storage,
        }
    }

    /// Handle an incoming DHT request frame
    ///
    /// Returns a response frame if successful, or an error.
    pub async fn handle_request(&self, request_frame: Frame) -> Result<Frame> {
        let message_type = request_frame.header.message_type;
        let source = request_frame.header.source;

        match message_type {
            MessageType::DhtQuery => {
                // Could be FIND_NODE or FIND_VALUE
                // Try to deserialize as FindNodeRequest first
                if let Ok(request) = bincode::deserialize::<FindNodeRequest>(&request_frame.payload)
                {
                    debug!(
                        "Received FIND_NODE from {:?} for target {:?}",
                        &source.as_bytes()[0..8],
                        &request.target.as_bytes()[0..8]
                    );
                    return self.handle_find_node(source, request).await;
                }

                // Try as FindValueRequest
                if let Ok(request) =
                    bincode::deserialize::<FindValueRequest>(&request_frame.payload)
                {
                    debug!(
                        "Received FIND_VALUE from {:?} for key {:?}",
                        &source.as_bytes()[0..8],
                        &request.key[0..8]
                    );
                    return self.handle_find_value(source, request).await;
                }

                warn!("Received DhtQuery with unrecognized payload");
                Err(crate::error::DhtError::Serialization(
                    "Unknown DHT query type".to_string(),
                ))
            }

            MessageType::DhtStore => {
                if let Ok(request) = bincode::deserialize::<StoreRequest>(&request_frame.payload) {
                    debug!(
                        "Received STORE from {:?} for key {:?}",
                        &source.as_bytes()[0..8],
                        &request.key[0..8]
                    );
                    return self.handle_store(source, request).await;
                }

                warn!("Received DhtStore with invalid payload");
                Err(crate::error::DhtError::Serialization(
                    "Invalid STORE request".to_string(),
                ))
            }

            _ => {
                warn!("Received non-DHT frame in DHT handler: {:?}", message_type);
                Err(crate::error::DhtError::Other(
                    "Not a DHT request".to_string(),
                ))
            }
        }
    }

    /// Handle FIND_NODE request
    async fn handle_find_node(&self, requestor: NodeId, request: FindNodeRequest) -> Result<Frame> {
        // Get k closest nodes to the target from our routing table
        let closest_nodes = {
            let rt = self.routing_table.read().await;
            rt.get_k_closest(&request.target, K)
        };

        // Convert to PublicNodeInfo (privacy-preserving)
        let public_nodes: Vec<_> = closest_nodes.iter().map(|n| n.to_public()).collect();

        info!(
            "Responding to FIND_NODE from {:?} with {} nodes",
            &requestor.as_bytes()[0..8],
            public_nodes.len()
        );

        // Create response
        let response = FindNodeResponse {
            query_id: request.query_id,
            nodes: public_nodes,
        };

        // Serialize response
        let payload = bincode::serialize(&response).map_err(|e| {
            crate::error::DhtError::Serialization(format!(
                "Failed to serialize FindNodeResponse: {}",
                e
            ))
        })?;

        // Create response frame
        self.create_response_frame(requestor, MessageType::DhtResponse, payload)
    }

    /// Handle FIND_VALUE request
    async fn handle_find_value(
        &self,
        requestor: NodeId,
        request: FindValueRequest,
    ) -> Result<Frame> {
        // Check if we have the value in our storage
        let storage_result = {
            let storage = self.storage.read().await;
            storage.get(&request.key).cloned()
        };

        let response = if let Some(entry) = storage_result {
            // Verify signature before returning
            if entry.verify_signature().is_ok() {
                info!(
                    "Returning stored value to {:?} for key {:?}",
                    &requestor.as_bytes()[0..8],
                    &request.key[0..8]
                );

                FindValueResponse::Found {
                    query_id: request.query_id,
                    key: request.key,
                    value: entry.value,
                    signature: entry.signature.to_vec(),
                }
            } else {
                warn!(
                    "Found value for key {:?} but signature is invalid, returning nodes instead",
                    &request.key[0..8]
                );
                // Fall through to return closest nodes
                self.find_value_nodes_fallback(&request).await
            }
        } else {
            // Value not found, return closest nodes
            debug!(
                "Value not found for key {:?}, returning closest nodes",
                &request.key[0..8]
            );
            self.find_value_nodes_fallback(&request).await
        };

        // Serialize response
        let payload = bincode::serialize(&response).map_err(|e| {
            crate::error::DhtError::Serialization(format!(
                "Failed to serialize FindValueResponse: {}",
                e
            ))
        })?;

        // Create response frame
        self.create_response_frame(requestor, MessageType::DhtResponse, payload)
    }

    /// Helper to create NotFound response with closest nodes
    async fn find_value_nodes_fallback(&self, request: &FindValueRequest) -> FindValueResponse {
        // Convert key to NodeId for distance calculations
        let target = NodeId::from_bytes(Self::key_to_node_id_bytes(request.key));

        // Get k closest nodes
        let closest_nodes = {
            let rt = self.routing_table.read().await;
            rt.get_k_closest(&target, K)
        };

        let public_nodes: Vec<_> = closest_nodes.iter().map(|n| n.to_public()).collect();

        FindValueResponse::NotFound {
            query_id: request.query_id,
            nodes: public_nodes,
        }
    }

    /// Handle STORE request
    async fn handle_store(&self, requestor: NodeId, request: StoreRequest) -> Result<Frame> {
        // Verify signature before storing
        // TODO: Implement proper signature verification (SECURITY H7)
        // For now, we trust the signature field exists

        // Extract publisher public key (first 32 bytes of NodeId)
        // Note: This is a simplification - in production, we'd need the actual Ed25519 public key
        let mut publisher_public_key = [0u8; 32];
        publisher_public_key.copy_from_slice(&request.publisher.as_bytes()[0..32]);

        // Convert signature Vec<u8> to [u8; 64]
        let signature_array: [u8; 64] = if request.signature.len() == 64 {
            let mut arr = [0u8; 64];
            arr.copy_from_slice(&request.signature);
            arr
        } else {
            warn!(
                "Invalid signature length in STORE request: {}",
                request.signature.len()
            );
            [0u8; 64]
        };

        // Store the value
        let mut storage = self.storage.write().await;
        let store_result = storage.store(
            request.key,
            request.value,
            request.ttl as u64, // Convert u32 to u64
            publisher_public_key,
            *request.publisher.as_bytes(),
            signature_array,
        );

        let response = match store_result {
            Ok(()) => {
                info!(
                    "Stored value from {:?} for key {:?}",
                    &requestor.as_bytes()[0..8],
                    &request.key[0..8]
                );
                StoreAck {
                    query_id: request.query_id,
                    success: true,
                    error: None,
                }
            }
            Err(e) => {
                warn!(
                    "Failed to store value from {:?}: {}",
                    &requestor.as_bytes()[0..8],
                    e
                );
                StoreAck {
                    query_id: request.query_id,
                    success: false,
                    error: Some(e.to_string()),
                }
            }
        };

        // Serialize response
        let payload = bincode::serialize(&response).map_err(|e| {
            crate::error::DhtError::Serialization(format!("Failed to serialize StoreAck: {}", e))
        })?;

        // Create response frame
        self.create_response_frame(requestor, MessageType::DhtResponse, payload)
    }

    /// Helper to create a response frame
    fn create_response_frame(
        &self,
        destination: NodeId,
        message_type: MessageType,
        payload: Vec<u8>,
    ) -> Result<Frame> {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;

        let message_id = MessageId::generate(&self.node_id, &destination, &payload, timestamp, 0);

        Frame::new(
            message_type,
            self.node_id,
            destination,
            payload,
            message_id,
            timestamp,
        )
        .map_err(|e| crate::error::DhtError::Other(format!("Failed to create frame: {}", e)))
    }

    /// Convert a 32-byte key to a 64-byte NodeId
    fn key_to_node_id_bytes(key: [u8; 32]) -> [u8; 64] {
        let mut node_id_bytes = [0u8; 64];
        node_id_bytes[..32].copy_from_slice(&key);
        node_id_bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use myriadmesh_protocol::types::NODE_ID_SIZE;

    fn create_test_node_id(value: u8) -> NodeId {
        let mut bytes = [0u8; NODE_ID_SIZE];
        bytes[0] = value;
        NodeId::from_bytes(bytes)
    }

    #[tokio::test]
    async fn test_request_handler_creation() {
        let node_id = create_test_node_id(1);
        let routing_table = Arc::new(RwLock::new(RoutingTable::new(node_id)));
        let storage = Arc::new(RwLock::new(DhtStorage::new()));

        let handler = DhtRequestHandler::new(node_id, routing_table, storage);

        assert_eq!(handler.node_id, node_id);
    }

    #[tokio::test]
    async fn test_handle_find_node() {
        let node_id = create_test_node_id(1);
        let requestor = create_test_node_id(2);
        let target = create_test_node_id(100);

        let routing_table = Arc::new(RwLock::new(RoutingTable::new(node_id)));
        let storage = Arc::new(RwLock::new(DhtStorage::new()));

        let handler = DhtRequestHandler::new(node_id, routing_table, storage);

        let request = FindNodeRequest::new(target, requestor);
        let response_frame = handler.handle_find_node(requestor, request).await.unwrap();

        // Verify response frame is valid
        assert_eq!(response_frame.header.message_type, MessageType::DhtResponse);
        assert_eq!(response_frame.header.source, node_id);
        assert_eq!(response_frame.header.destination, requestor);

        // Deserialize response
        let response: FindNodeResponse = bincode::deserialize(&response_frame.payload).unwrap();
        // Routing table is empty, so we should get 0 nodes
        assert_eq!(response.nodes.len(), 0);
    }

    #[tokio::test]
    async fn test_handle_find_value_not_found() {
        let node_id = create_test_node_id(1);
        let requestor = create_test_node_id(2);
        let key = [42u8; 32];

        let routing_table = Arc::new(RwLock::new(RoutingTable::new(node_id)));
        let storage = Arc::new(RwLock::new(DhtStorage::new()));

        let handler = DhtRequestHandler::new(node_id, routing_table, storage);

        let request = FindValueRequest::new(key, requestor);
        let response_frame = handler.handle_find_value(requestor, request).await.unwrap();

        // Verify response
        let response: FindValueResponse = bincode::deserialize(&response_frame.payload).unwrap();

        match response {
            FindValueResponse::NotFound { nodes, .. } => {
                // Should return empty list since routing table is empty
                assert_eq!(nodes.len(), 0);
            }
            _ => panic!("Expected NotFound response"),
        }
    }
}
