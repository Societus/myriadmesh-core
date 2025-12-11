//! DHT RPC transport implementation
//!
//! This module provides the concrete implementation of DhtTransport
//! that uses the network adapter layer for sending/receiving DHT queries.

use crate::dht::DhtTransport;
use crate::error::{DhtError, Result};
use crate::operations::{
    FindNodeRequest, FindNodeResponse, FindValueRequest, FindValueResponse, QueryId,
    StoreRequest, StoreAck,
};
use myriadmesh_protocol::{Frame, MessageId, MessageType, NodeId};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::{mpsc, RwLock};
use tokio::time::timeout;
use tracing::{debug, warn};

/// Timeout for DHT RPC queries
const RPC_TIMEOUT: Duration = Duration::from_secs(5);

/// Maximum pending queries before dropping new ones
const MAX_PENDING_QUERIES: usize = 1000;

/// Response channel for a specific query
type ResponseSender<T> = mpsc::Sender<T>;

/// Pending query tracker
struct PendingQuery<T> {
    /// Query ID for matching responses
    /// TODO: Use this for detailed logging and timeout tracking
    #[allow(dead_code)]
    query_id: QueryId,
    /// Channel to send response back
    response_tx: ResponseSender<T>,
}

/// Network RPC transport for DHT operations
///
/// This implements the DhtTransport trait using the network adapter layer.
/// It handles serialization, frame transmission, response matching, and timeouts.
pub struct NetworkRpcTransport {
    /// Local node ID
    node_id: NodeId,

    /// Pending FIND_NODE queries
    pending_find_node: Arc<RwLock<HashMap<QueryId, PendingQuery<FindNodeResponse>>>>,

    /// Pending FIND_VALUE queries
    pending_find_value: Arc<RwLock<HashMap<QueryId, PendingQuery<FindValueResponse>>>>,

    /// Pending STORE queries
    pending_store: Arc<RwLock<HashMap<QueryId, PendingQuery<StoreAck>>>>,

    /// Pending PING queries
    pending_ping: Arc<RwLock<HashMap<QueryId, PendingQuery<bool>>>>,

    /// Frame transmission function (injected dependency)
    /// This allows us to avoid direct coupling to AdapterManager
    send_frame:
        Arc<dyn Fn(NodeId, Frame) -> futures::future::BoxFuture<'static, Result<()>> + Send + Sync>,
}

impl NetworkRpcTransport {
    /// Create a new network RPC transport
    ///
    /// # Parameters
    /// - `node_id`: Local node identifier
    /// - `send_frame`: Function to send frames via network adapters
    pub fn new<F>(node_id: NodeId, send_frame: F) -> Self
    where
        F: Fn(NodeId, Frame) -> futures::future::BoxFuture<'static, Result<()>>
            + Send
            + Sync
            + 'static,
    {
        Self {
            node_id,
            pending_find_node: Arc::new(RwLock::new(HashMap::new())),
            pending_find_value: Arc::new(RwLock::new(HashMap::new())),
            pending_store: Arc::new(RwLock::new(HashMap::new())),
            pending_ping: Arc::new(RwLock::new(HashMap::new())),
            send_frame: Arc::new(send_frame),
        }
    }

    /// Handle an incoming DHT response frame
    ///
    /// This should be called by the network layer when a DhtResponse frame is received.
    /// It will match the response to a pending query and send it through the response channel.
    pub async fn handle_response(&self, frame: Frame) -> Result<()> {
        // Deserialize the frame payload
        let payload = &frame.payload;

        // Try to match as FindNodeResponse first
        if let Ok(response) = bincode::deserialize::<FindNodeResponse>(payload) {
            debug!(
                "Received FindNodeResponse for query {:?}",
                &response.query_id[0..4]
            );

            let mut pending = self.pending_find_node.write().await;
            if let Some(query) = pending.remove(&response.query_id) {
                // Send response to waiting query
                if query.response_tx.send(response).await.is_err() {
                    warn!("Failed to send FindNodeResponse: receiver dropped");
                }
                return Ok(());
            }
        }

        // Try to match as FindValueResponse
        if let Ok(response) = bincode::deserialize::<FindValueResponse>(payload) {
            let query_id = match &response {
                FindValueResponse::Found { query_id, .. } => *query_id,
                FindValueResponse::NotFound { query_id, .. } => *query_id,
            };

            debug!("Received FindValueResponse for query {:?}", &query_id[0..4]);

            let mut pending = self.pending_find_value.write().await;
            if let Some(query) = pending.remove(&query_id) {
                // Send response to waiting query
                if query.response_tx.send(response).await.is_err() {
                    warn!("Failed to send FindValueResponse: receiver dropped");
                }
                return Ok(());
            }
        }

        // Try to match as StoreAck
        if let Ok(ack) = bincode::deserialize::<StoreAck>(payload) {
            debug!("Received StoreAck for query {:?}", &ack.query_id[0..4]);

            let mut pending = self.pending_store.write().await;
            if let Some(query) = pending.remove(&ack.query_id) {
                // Send response to waiting query
                if query.response_tx.send(ack).await.is_err() {
                    warn!("Failed to send StoreAck: receiver dropped");
                }
                return Ok(());
            }
        }

        // Try to match as PING response (simple boolean)
        // PING responses are empty frames - just the existence of a response indicates success
        if frame.header.message_type == MessageType::DhtResponse {
            // Try to extract query_id from frame metadata or use message_id as proxy
            // For now, we'll use a simple approach where PING uses the message_id as query_id
            let query_id = frame.header.message_id.as_bytes()[0..16].try_into().unwrap_or([0u8; 16]);

            let mut pending = self.pending_ping.write().await;
            if let Some(query) = pending.remove(&query_id) {
                // Send true to indicate successful ping
                if query.response_tx.send(true).await.is_err() {
                    warn!("Failed to send PING response: receiver dropped");
                }
                return Ok(());
            }
        }

        // Response didn't match any pending query
        debug!("Received DHT response that didn't match any pending query");
        Ok(())
    }

    /// Clean up expired queries
    ///
    /// This should be called periodically to prevent memory leaks from timed-out queries.
    pub async fn cleanup_expired_queries(&self) {
        // This is a simple cleanup - in production, we'd track timestamps
        // and only clean up queries older than RPC_TIMEOUT

        let find_node_count = self.pending_find_node.read().await.len();
        let find_value_count = self.pending_find_value.read().await.len();
        let store_count = self.pending_store.read().await.len();
        let ping_count = self.pending_ping.read().await.len();

        if find_node_count > MAX_PENDING_QUERIES {
            warn!(
                "Too many pending FIND_NODE queries ({}), clearing all",
                find_node_count
            );
            self.pending_find_node.write().await.clear();
        }

        if find_value_count > MAX_PENDING_QUERIES {
            warn!(
                "Too many pending FIND_VALUE queries ({}), clearing all",
                find_value_count
            );
            self.pending_find_value.write().await.clear();
        }

        if store_count > MAX_PENDING_QUERIES {
            warn!(
                "Too many pending STORE queries ({}), clearing all",
                store_count
            );
            self.pending_store.write().await.clear();
        }

        if ping_count > MAX_PENDING_QUERIES {
            warn!(
                "Too many pending PING queries ({}), clearing all",
                ping_count
            );
            self.pending_ping.write().await.clear();
        }
    }

    /// Send a frame and wait for typed response
    async fn send_and_await<Req, Resp>(
        &self,
        target_node: &NodeId,
        request: Req,
        message_type: MessageType,
        pending_map: Arc<RwLock<HashMap<QueryId, PendingQuery<Resp>>>>,
        query_id: QueryId,
    ) -> Result<Resp>
    where
        Req: serde::Serialize,
        Resp: Send + 'static,
    {
        // Serialize request
        let payload = bincode::serialize(&request)
            .map_err(|e| DhtError::Serialization(format!("Failed to serialize request: {}", e)))?;

        // Generate message ID and timestamp
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;

        let message_id = MessageId::generate(
            &self.node_id,
            target_node,
            &payload,
            timestamp,
            0, // sequence number
        );

        // Create frame
        let frame = Frame::new(
            message_type,
            self.node_id,
            *target_node,
            payload,
            message_id,
            timestamp,
        )?;

        // Create response channel
        let (response_tx, mut response_rx) = mpsc::channel(1);

        // Register pending query
        {
            let mut pending = pending_map.write().await;
            pending.insert(
                query_id,
                PendingQuery {
                    query_id,
                    response_tx,
                },
            );
        }

        // Send frame
        let send_result = (self.send_frame)(*target_node, frame).await;
        if let Err(e) = send_result {
            // Remove pending query on send failure
            pending_map.write().await.remove(&query_id);
            return Err(e);
        }

        // Wait for response with timeout
        match timeout(RPC_TIMEOUT, response_rx.recv()).await {
            Ok(Some(response)) => Ok(response),
            Ok(None) => {
                // Channel closed without response
                pending_map.write().await.remove(&query_id);
                Err(DhtError::QueryTimeout)
            }
            Err(_) => {
                // Timeout
                pending_map.write().await.remove(&query_id);
                Err(DhtError::QueryTimeout)
            }
        }
    }
}

#[async_trait::async_trait]
impl DhtTransport for NetworkRpcTransport {
    async fn find_node(
        &self,
        target_node: &NodeId,
        request: FindNodeRequest,
    ) -> Result<FindNodeResponse> {
        debug!(
            "Sending FIND_NODE to {:?} for target {:?}",
            &target_node.as_bytes()[0..8],
            &request.target.as_bytes()[0..8]
        );

        self.send_and_await(
            target_node,
            request.clone(),
            MessageType::DhtQuery,
            Arc::clone(&self.pending_find_node),
            request.query_id,
        )
        .await
    }

    async fn find_value(
        &self,
        target_node: &NodeId,
        request: FindValueRequest,
    ) -> Result<FindValueResponse> {
        debug!(
            "Sending FIND_VALUE to {:?} for key {:?}",
            &target_node.as_bytes()[0..8],
            &request.key[0..8]
        );

        self.send_and_await(
            target_node,
            request.clone(),
            MessageType::DhtQuery,
            Arc::clone(&self.pending_find_value),
            request.query_id,
        )
        .await
    }

    async fn store(
        &self,
        target_node: &NodeId,
        request: StoreRequest,
    ) -> Result<StoreAck> {
        debug!(
            "Sending STORE to {:?} for key {:?}",
            &target_node.as_bytes()[0..8],
            &request.key[0..8]
        );

        self.send_and_await(
            target_node,
            request.clone(),
            MessageType::DhtQuery,
            Arc::clone(&self.pending_store),
            request.query_id,
        )
        .await
    }

    async fn ping(&self, target_node: &NodeId) -> Result<bool> {
        use crate::operations::generate_query_id;

        debug!(
            "Sending PING to {:?}",
            &target_node.as_bytes()[0..8]
        );

        // For PING, we send an empty payload
        let query_id = generate_query_id();
        let payload = vec![];

        // Generate message ID and timestamp
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;

        let message_id = MessageId::generate(
            &self.node_id,
            target_node,
            &payload,
            timestamp,
            0,
        );

        // Create frame
        let frame = Frame::new(
            MessageType::DhtQuery,
            self.node_id,
            *target_node,
            payload,
            message_id,
            timestamp,
        )?;

        // Create response channel
        let (response_tx, mut response_rx) = mpsc::channel(1);

        // Register pending query
        {
            let mut pending = self.pending_ping.write().await;
            pending.insert(
                query_id,
                PendingQuery {
                    query_id,
                    response_tx,
                },
            );
        }

        // Send frame
        let send_result = (self.send_frame)(*target_node, frame).await;
        if let Err(e) = send_result {
            // Remove pending query on send failure
            self.pending_ping.write().await.remove(&query_id);
            return Err(e);
        }

        // Wait for response with timeout
        match timeout(RPC_TIMEOUT, response_rx.recv()).await {
            Ok(Some(response)) => Ok(response),
            Ok(None) => {
                // Channel closed without response
                self.pending_ping.write().await.remove(&query_id);
                Ok(false)
            }
            Err(_) => {
                // Timeout
                self.pending_ping.write().await.remove(&query_id);
                Ok(false)
            }
        }
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
    async fn test_network_rpc_transport_creation() {
        let node_id = create_test_node_id(1);

        let transport =
            NetworkRpcTransport::new(node_id, |_node, _frame| Box::pin(async { Ok(()) }));

        assert_eq!(transport.node_id, node_id);
    }

    #[tokio::test]
    async fn test_cleanup_expired_queries() {
        let node_id = create_test_node_id(1);

        let transport =
            NetworkRpcTransport::new(node_id, |_node, _frame| Box::pin(async { Ok(()) }));

        // Add some dummy pending queries
        {
            let mut pending = transport.pending_find_node.write().await;
            for i in 0..(MAX_PENDING_QUERIES + 100) {
                let mut query_id = [0u8; 16];
                query_id[0] = (i % 256) as u8;
                query_id[1] = ((i / 256) % 256) as u8;
                let (tx, _rx) = mpsc::channel(1);
                pending.insert(
                    query_id,
                    PendingQuery {
                        query_id,
                        response_tx: tx,
                    },
                );
            }
        }

        // Cleanup should clear all queries
        transport.cleanup_expired_queries().await;

        let count = transport.pending_find_node.read().await.len();
        assert_eq!(count, 0);
    }

    #[tokio::test]
    async fn test_find_node_timeout() {
        let node_id = create_test_node_id(1);
        let target_node = create_test_node_id(2);

        // Transport that never sends frames (simulates network failure)
        let transport = NetworkRpcTransport::new(node_id, |_node, _frame| {
            Box::pin(async {
                // Never actually send
                tokio::time::sleep(Duration::from_secs(10)).await;
                Ok(())
            })
        });

        let request = FindNodeRequest::new(target_node, node_id);

        let result = transport.find_node(&target_node, request).await;

        // Should timeout
        assert!(matches!(result, Err(DhtError::QueryTimeout)));
    }
}
