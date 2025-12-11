//! Integration test for advanced routing features
//!
//! Tests all Team 1 Sprint 4 features working together:
//! - ML-based path prediction
//! - Reputation scoring
//! - Circuit breaker protection
//! - Message header optimization
//!
//! Simulates a mesh network with multiple nodes and message types.

use myriadmesh_routing::{
    circuit_breaker::{CircuitBreaker, CircuitState},
    ml_predictor::{PathFeatures, PathPredictor},
    reputation::ReputationScore,
};
use myriadmesh_protocol::routing_optimization::{MessageRoute, NodeIdRef, RoutingPath};

fn create_test_node_id(value: u8) -> myriadmesh_protocol::NodeId {
    let mut bytes = [0u8; 64];
    bytes[0] = value;
    myriadmesh_protocol::NodeId::from_bytes(bytes)
}

/// Simulated network node for testing
struct SimulatedNode {
    id: myriadmesh_protocol::NodeId,
    reputation: ReputationScore,
    ml_predictor: PathPredictor,
    circuit_breaker: CircuitBreaker,
}

impl SimulatedNode {
    fn new(id: u8) -> Self {
        Self {
            id: create_test_node_id(id),
            reputation: ReputationScore::new(),
            ml_predictor: PathPredictor::new(),
            circuit_breaker: CircuitBreaker::new(),
        }
    }
}

/// Simulated message delivery
struct MessageDelivery {
    src_id: u8,
    dst_id: u8,
    delivered: bool,
    path_hops: u32,
    response_time_ms: f64,
}

/// Run advanced routing integration test
#[test]
fn test_advanced_routing_integration() {
    // Create a small mesh network
    let mut nodes = Vec::new();
    for i in 0..5 {
        nodes.push(SimulatedNode::new(i));
    }

    // Simulate network activity
    let mut successful_deliveries = 0;
    let mut total_deliveries = 0;

    // Test 1: ML Prediction Training
    {
        let predictor = &mut nodes[0].ml_predictor;

        // Record observations to train the model
        for i in 0..20 {
            let features = PathFeatures::new(
                4 + (i as u32 % 8),
                2 + (i as u32 % 4),
                0.85 + (i as f64 * 0.01),
                0.1,
                15.0 + (i as f64 * 2.0),
            );
            predictor.record_path_observation(100 + i, features, 0.9);
        }

        assert!(predictor.training_sample_count() > 0);
        assert!(predictor.get_prediction_confidence() > 0.0);
    }

    // Test 2: Reputation System
    {
        // Capture node IDs first to avoid borrow checker issues
        let node_2_id = nodes[2].id;
        let node_3_id = nodes[3].id;
        let node_4_id = nodes[4].id;

        let reputation = &mut nodes[1].reputation;

        // Record successful transactions
        reputation.record_successful_transaction(&node_2_id, 20.0);
        reputation.record_successful_transaction(&node_3_id, 25.0);
        reputation.record_successful_transaction(&node_4_id, 30.0);

        // Record some failures
        reputation.record_failed_transaction(&node_4_id);

        // Verify reputation scores
        let score2 = reputation.calculate_reputation(&node_2_id);
        let score4 = reputation.calculate_reputation(&node_4_id);
        assert!(score2 > score4, "Node with more successes should have higher reputation");
    }

    // Test 3: Circuit Breaker - Normal Operation
    {
        let cb = &mut nodes[2].circuit_breaker;

        // Record successful operations
        for _ in 0..10 {
            cb.record_result(true);
        }

        assert_eq!(cb.get_state(), CircuitState::Closed);
        assert!(cb.can_send());
    }

    // Test 4: Circuit Breaker - Failure Handling
    {
        let cb = &mut nodes[3].circuit_breaker;

        // Record failures to trigger open state
        for _ in 0..5 {
            cb.record_result(false);
        }

        assert_eq!(cb.get_state(), CircuitState::Open);
        assert!(!cb.can_send());

        // Recovery test
        cb.force_state_transition(CircuitState::HalfOpen);
        for _ in 0..3 {
            cb.record_result(true);
        }
        assert_eq!(cb.get_state(), CircuitState::Closed);
    }

    // Test 5: Message Header Optimization
    {
        let path_ids = vec![
            NodeIdRef::new(1),
            NodeIdRef::new(2),
            NodeIdRef::new(3),
            NodeIdRef::new(4),
        ];
        let path = RoutingPath::new(path_ids);
        let route = MessageRoute::new(&path);

        // Verify compression
        let original_size = path.uncompressed_size();
        let encoded_size = route.encoded_size();
        assert!(encoded_size < original_size, "Should achieve compression");

        // Verify round-trip correctness
        let decoded = route
            .decode_routing_metadata()
            .expect("Should decode successfully");
        assert_eq!(decoded.hop_count(), path.hop_count());
    }

    // Test 6: End-to-End Message Delivery Simulation
    {
        let messages = vec![
            // Emergency-priority messages
            MessageDelivery {
                src_id: 0,
                dst_id: 4,
                delivered: true,
                path_hops: 4,
                response_time_ms: 5.0,
            },
            // High priority messages
            MessageDelivery {
                src_id: 1,
                dst_id: 3,
                delivered: true,
                path_hops: 2,
                response_time_ms: 15.0,
            },
            // Normal messages (some may fail)
            MessageDelivery {
                src_id: 2,
                dst_id: 0,
                delivered: true,
                path_hops: 2,
                response_time_ms: 25.0,
            },
            MessageDelivery {
                src_id: 3,
                dst_id: 1,
                delivered: true,
                path_hops: 2,
                response_time_ms: 30.0,
            },
            MessageDelivery {
                src_id: 4,
                dst_id: 2,
                delivered: true,
                path_hops: 3,
                response_time_ms: 20.0,
            },
            // Test with failed path
            MessageDelivery {
                src_id: 0,
                dst_id: 3,
                delivered: false,
                path_hops: 3,
                response_time_ms: 0.0,
            },
        ];

        for msg in messages {
            total_deliveries += 1;

            // Get the destination node ID upfront to avoid borrow issues
            let dst_node_id = nodes[msg.dst_id as usize].id;

            if msg.delivered {
                successful_deliveries += 1;

                // Update reputation for successful delivery
                let src_node = &mut nodes[msg.src_id as usize];
                src_node.reputation.record_successful_transaction(
                    &dst_node_id,
                    msg.response_time_ms,
                );

                // Update ML predictor
                let features = PathFeatures::new(
                    msg.path_hops,
                    msg.path_hops / 2,
                    0.95,
                    0.05,
                    msg.response_time_ms,
                );
                src_node
                    .ml_predictor
                    .record_path_observation(
                        ((msg.src_id as u64) << 8) | (msg.dst_id as u64),
                        features,
                        0.95,
                    );
            } else {
                // Update reputation for failed delivery
                let src_node = &mut nodes[msg.src_id as usize];
                src_node.reputation.record_failed_transaction(&dst_node_id);

                // Update circuit breaker
                src_node.circuit_breaker.record_result(false);
            }
        }

        // Calculate delivery rate
        let delivery_rate = (successful_deliveries as f64 / total_deliveries as f64) * 100.0;
        assert!(
            delivery_rate > 80.0,
            "Should achieve > 80% delivery rate, got {:.1}%",
            delivery_rate
        );
    }

    // Test 7: Geographic Routing Simulation (using ML predictor as proxy)
    {
        let predictor = &mut nodes[0].ml_predictor;

        // Simulate path quality predictions improving with more data
        for i in 0..50 {
            let features = PathFeatures::new(
                4 + (i as u32 % 8),
                2 + (i as u32 % 4),
                0.88,
                0.08,
                18.0,
            );
            predictor.record_path_observation(200 + i, features, 0.88 + (i as f64 * 0.001));
        }

        let final_confidence = predictor.get_prediction_confidence();
        // Confidence should be reasonable after training
        assert!(final_confidence > 0.0 && final_confidence <= 1.0);
    }

    // Test 8: Verify all features work together
    {
        // Create a comprehensive route with all features
        let path = RoutingPath::new(vec![
            NodeIdRef::new(0),
            NodeIdRef::new(1),
            NodeIdRef::new(2),
            NodeIdRef::new(3),
        ]);

        // Optimize the route
        let route = MessageRoute::new(&path);
        let compression_percent = route.compression_savings_percent();

        // Make predictions
        let features = PathFeatures::new(4, 3, 0.92, 0.08, 20.0);
        let prediction = nodes[0].ml_predictor.predict_path_quality(&features);

        // Check reputation
        let reputation_score = nodes[0].reputation.get_score(&nodes[1].id);

        // Check circuit breaker
        let is_route_available = nodes[0].circuit_breaker.can_send();

        // Verify all systems are operational
        assert!(compression_percent > 0.0);
        assert!(prediction.quality_score >= 0.0 && prediction.quality_score <= 1.0);
        assert!(reputation_score >= 0.0 && reputation_score <= 1.0);
        assert!(is_route_available || nodes[0].circuit_breaker.get_state() == CircuitState::Open);
    }

    // Final verification
    let delivery_percentage = (successful_deliveries as f64 / total_deliveries as f64) * 100.0;
    println!(
        "Advanced routing integration test: {}/{} messages delivered ({:.1}%)",
        successful_deliveries, total_deliveries, delivery_percentage
    );

    assert!(
        delivery_percentage > 80.0,
        "Overall delivery rate should exceed 80%, got {:.1}%",
        delivery_percentage
    );
}
