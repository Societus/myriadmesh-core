//! Integration tests for complete routing workflows
//!
//! These tests verify end-to-end routing scenarios combining multiple modules:
//! - Path selection with multiple candidates
//! - Adapter selection under different network conditions
//! - Store-and-forward for offline nodes
//! - Retry logic with exponential backoff
//! - Strategy composition

use myriadmesh_routing::{
    AdapterSelector, AdapterTier, AdapterId, NetworkConditions,
    PathSelector, MultiPathStrategy, EnhancedPathSelector,
    StoreAndForwardManager, StoreForwardStatus,
    TransmissionConfig, RetryContext, TransmissionState,
};
use myriadmesh_protocol::{NodeId, message::Message, MessageType};
use myriadmesh_dht::{PublicNodeInfo, NodeCapabilities, NodeReputation};
use myriadmesh_protocol::types::{NODE_ID_SIZE, Priority};
use std::time::SystemTime;

/// Helper to create test NodeIds
fn create_node_id(id: u8) -> NodeId {
    let mut bytes = [0u8; NODE_ID_SIZE];
    bytes[0] = id;
    NodeId::from_bytes(bytes)
}

/// Helper to create test PublicNodeInfo
fn create_test_node(id: u8, rtt_ms: f64, can_relay: bool) -> PublicNodeInfo {
    PublicNodeInfo {
        node_id: create_node_id(id),
        capabilities: NodeCapabilities {
            can_relay,
            ..Default::default()
        },
        reputation: NodeReputation::new(),
        last_seen: SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
        rtt_ms,
    }
}

/// Helper to create test messages
fn create_test_message(src: u8, dst: u8) -> Message {
    Message::new(
        create_node_id(src),
        create_node_id(dst),
        MessageType::Data,
        b"test payload".to_vec(),
    )
    .unwrap()
    .with_priority(Priority::normal())
}

// ============================================================================
// PATH SELECTION INTEGRATION TESTS
// ============================================================================

#[test]
fn test_path_selection_single_hop() {
    // Test selecting optimal path for single-hop routing
    let selector = PathSelector::new();
    let target = create_node_id(99);

    // Create candidate nodes with various qualities
    let candidates = vec![
        create_test_node(1, 50.0, true),   // Good RTT, can relay
        create_test_node(2, 150.0, true),  // High RTT, can relay
        create_test_node(3, 30.0, false),  // Best RTT but can't relay
    ];

    let selection = selector.select_paths(target, candidates);

    // Should select a primary path
    assert!(selection.primary.is_some());

    // Should have alternatives
    assert!(!selection.alternatives.is_empty());

    // Primary should have lower cost than some alternatives
    let primary_cost = selection.primary.as_ref().unwrap().estimated_cost;
    assert!(selection.alternatives.iter().any(|p| p.estimated_cost > primary_cost));
}

#[test]
fn test_path_selection_many_candidates() {
    // Test path selection with many candidate nodes (>100)
    let selector = PathSelector::new();
    let target = create_node_id(200);

    // Create 100 candidate nodes with varying qualities
    let mut candidates = Vec::new();
    for i in 0..100 {
        let rtt = 10.0 + (i as f64) * 0.5; // Varying RTT from 10 to 59.5ms
        let can_relay = i % 3 != 0; // 2/3 can relay
        candidates.push(create_test_node((i % 255) as u8, rtt, can_relay));
    }

    let selection = selector.select_paths(target, candidates);

    // Should handle large candidate set
    assert!(selection.primary.is_some());
    assert!(!selection.alternatives.is_empty());

    // Primary should be one with good RTT
    let primary = selection.primary.as_ref().unwrap();
    assert!(primary.hop_count >= 1);
}

#[test]
fn test_path_selection_cost_ordering() {
    // Test that selected paths are properly ordered by cost
    let selector = PathSelector::new();
    let target = create_node_id(99);

    let candidates = vec![
        create_test_node(1, 100.0, false),  // Worst option: high RTT, no relay
        create_test_node(2, 20.0, true),    // Best option: low RTT, can relay
        create_test_node(3, 50.0, true),    // Middle option
    ];

    let selection = selector.select_paths(target, candidates);

    let primary = selection.primary.as_ref().unwrap();
    let mut all_costs = vec![primary.estimated_cost];
    all_costs.extend(selection.alternatives.iter().map(|p| p.estimated_cost));

    // Costs should be in ascending order
    for i in 0..all_costs.len() - 1 {
        assert!(all_costs[i] <= all_costs[i + 1],
            "Costs not in order: {} > {}", all_costs[i], all_costs[i + 1]);
    }
}

// ============================================================================
// ADAPTER SELECTION INTEGRATION TESTS
// ============================================================================

#[test]
fn test_adapter_selection_optimal_conditions() {
    // Test adapter selection under optimal network conditions
    let tiers = vec![
        AdapterTier::new(vec![AdapterId::new(1), AdapterId::new(2)], 10, 50),
        AdapterTier::new(vec![AdapterId::new(3)], 5, 50),
    ];
    let selector = AdapterSelector::new(tiers);

    let conditions = NetworkConditions {
        latency_ms: 20.0,
        bandwidth_mbps: 100,
        packet_loss_percent: 0.0,
        on_battery: false,
        power_usage_percent: 10.0,
    };

    let result = selector.select_adapter(&conditions);
    assert!(result.is_ok(), "Should select adapter under optimal conditions");

    let adapter = result.unwrap();
    assert_eq!(adapter.0, 1); // Should prefer first tier, first adapter
}

#[test]
fn test_adapter_selection_degraded_network() {
    // Test adapter selection under degraded network conditions
    let tiers = vec![
        AdapterTier::new(vec![AdapterId::new(1)], 100, 50),  // Requires high bandwidth
        AdapterTier::new(vec![AdapterId::new(2)], 20, 50),   // Moderate requirement
        AdapterTier::new(vec![AdapterId::new(3)], 5, 50),    // Low requirement
    ];
    let selector = AdapterSelector::new(tiers);

    // Degraded conditions: low bandwidth
    let conditions = NetworkConditions {
        latency_ms: 150.0,
        bandwidth_mbps: 15,
        packet_loss_percent: 5.0,
        on_battery: true,
        power_usage_percent: 70.0,
    };

    let result = selector.select_adapter(&conditions);
    assert!(result.is_ok());

    let adapter = result.unwrap();
    // Should fall back to Tier 3 (ID 3) since tier 1 requires 100 Mbps
    assert_eq!(adapter.0, 3);
}

#[test]
fn test_adapter_failure_blacklist_timeout() {
    // Test that failed adapters are temporarily blacklisted with exponential backoff
    let tiers = vec![
        AdapterTier::new(vec![AdapterId::new(1), AdapterId::new(2)], 10, 50),
    ];
    let mut selector = AdapterSelector::new(tiers);

    let adapter1 = AdapterId::new(1);
    let adapter2 = AdapterId::new(2);
    let conditions = NetworkConditions::default();

    // Initial selection should work
    assert!(selector.select_adapter(&conditions).is_ok());

    // Mark adapter 1 as failed
    selector.mark_adapter_failed(adapter1);
    assert!(selector.is_blacklisted(adapter1));

    // Should fall back to adapter 2
    let result = selector.select_adapter(&conditions);
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), adapter2);

    // Adapter 1 failure count should increase with multiple failures
    selector.mark_adapter_failed(adapter1);
    assert_eq!(selector.get_failure_count(adapter1), 2);
}

#[test]
fn test_adapter_recovery_resets_failures() {
    // Test that successful transmission resets failure count
    let tiers = vec![
        AdapterTier::new(vec![AdapterId::new(1)], 10, 50),
    ];
    let mut selector = AdapterSelector::new(tiers);

    let adapter = AdapterId::new(1);

    // Fail multiple times
    selector.mark_adapter_failed(adapter);
    selector.mark_adapter_failed(adapter);
    assert_eq!(selector.get_failure_count(adapter), 2);

    // Recover
    selector.mark_adapter_recovered(adapter);
    assert_eq!(selector.get_failure_count(adapter), 0);
    assert!(!selector.is_blacklisted(adapter));
}

#[test]
fn test_adapter_battery_aware_selection() {
    // Test that adapter selection considers battery status
    let tiers = vec![
        AdapterTier::new(vec![AdapterId::new(1)], 10, 10), // Low power priority
        AdapterTier::new(vec![AdapterId::new(2)], 10, 50), // Medium power priority
    ];
    let selector = AdapterSelector::new(tiers);

    // On battery with high power usage
    let on_battery = NetworkConditions {
        latency_ms: 50.0,
        bandwidth_mbps: 20,
        packet_loss_percent: 0.0,
        on_battery: true,
        power_usage_percent: 70.0,
    };

    // On AC power
    let on_ac = NetworkConditions {
        latency_ms: 50.0,
        bandwidth_mbps: 20,
        packet_loss_percent: 0.0,
        on_battery: false,
        power_usage_percent: 0.0,
    };

    // Both should select adapters, but scoring differs
    assert!(selector.select_adapter(&on_battery).is_ok());
    assert!(selector.select_adapter(&on_ac).is_ok());
}

// ============================================================================
// TRANSMISSION & RETRY INTEGRATION TESTS
// ============================================================================

#[test]
fn test_retry_context_path_ordering() {
    // Test that RetryContext selects paths in correct order: primary then alternatives
    let primary = myriadmesh_routing::RoutingPath {
        next_hop: create_node_id(1),
        hop_count: 1,
        estimated_cost: 25.0,
    };

    let alts = vec![
        myriadmesh_routing::RoutingPath {
            next_hop: create_node_id(2),
            hop_count: 2,
            estimated_cost: 35.0,
        },
        myriadmesh_routing::RoutingPath {
            next_hop: create_node_id(3),
            hop_count: 3,
            estimated_cost: 45.0,
        },
    ];

    let mut context = RetryContext::new("msg-1".to_string(), primary.clone(), alts.clone());

    // First path should be primary
    let path1 = context.get_next_path().unwrap();
    assert_eq!(path1.estimated_cost, 25.0);

    // Second path should be first alternative
    let path2 = context.get_next_path().unwrap();
    assert_eq!(path2.estimated_cost, 35.0);

    // Third path should be second alternative
    let path3 = context.get_next_path().unwrap();
    assert_eq!(path3.estimated_cost, 45.0);

    // Fourth should be exhausted
    assert!(context.get_next_path().is_none());
}

#[test]
fn test_backoff_delay_progression() {
    // Test exponential backoff delay calculation
    let config = TransmissionConfig {
        max_retries: 5,
        base_delay_ms: 100,
        max_delay_ms: 10000,
    };

    // Attempt 1: 100ms
    let delay1 = TransmissionState::calculate_backoff_delay(1, config.base_delay_ms, config.max_delay_ms);
    assert_eq!(delay1.as_millis(), 100);

    // Attempt 2: 200ms (100 * 2^1)
    let delay2 = TransmissionState::calculate_backoff_delay(2, config.base_delay_ms, config.max_delay_ms);
    assert_eq!(delay2.as_millis(), 200);

    // Attempt 3: 400ms (100 * 2^2)
    let delay3 = TransmissionState::calculate_backoff_delay(3, config.base_delay_ms, config.max_delay_ms);
    assert_eq!(delay3.as_millis(), 400);

    // Attempt 5: 1600ms (100 * 2^4)
    let delay5 = TransmissionState::calculate_backoff_delay(5, config.base_delay_ms, config.max_delay_ms);
    assert_eq!(delay5.as_millis(), 1600);

    // Attempt 10 would exceed max, should be capped
    let delay10 = TransmissionState::calculate_backoff_delay(10, config.base_delay_ms, config.max_delay_ms);
    assert_eq!(delay10.as_millis(), 10000);
}

#[test]
fn test_retry_tracking_accumulation() {
    // Test that retry context properly tracks attempt counts
    let primary = myriadmesh_routing::RoutingPath {
        next_hop: create_node_id(1),
        hop_count: 1,
        estimated_cost: 25.0,
    };

    let mut context = RetryContext::new("msg-1".to_string(), primary, vec![]);

    // Record attempts
    for i in 1..=5 {
        context.record_attempt();
        let (total, _) = context.get_stats();
        assert_eq!(total, i as u32);
    }
}

// ============================================================================
// STORE-AND-FORWARD INTEGRATION TESTS
// ============================================================================

#[test]
fn test_store_forward_offline_node_workflow() {
    // Test complete store-and-forward workflow: cache → offline → online → retrieve
    let mut manager = StoreAndForwardManager::new();
    let offline_node = create_node_id(42);

    // Step 1: Node is offline, cache messages
    let msg1 = create_test_message(1, 42);
    let msg2 = create_test_message(2, 42);

    let status1 = manager.cache_for_offline(&offline_node, msg1);
    assert_eq!(status1, StoreForwardStatus::Cached);

    let status2 = manager.cache_for_offline(&offline_node, msg2);
    assert_eq!(status2, StoreForwardStatus::Cached);

    assert!(manager.has_cached_messages(&offline_node));
    assert_eq!(manager.cached_message_count(&offline_node), 2);

    // Step 2: Node comes online, retrieve all cached messages
    let retrieved = manager.retrieve_for_online_node(&offline_node);
    assert_eq!(retrieved.len(), 2);

    // Step 3: Messages should be cleared after retrieval
    assert!(!manager.has_cached_messages(&offline_node));
    assert_eq!(manager.cached_message_count(&offline_node), 0);

    // Step 4: Verify statistics
    let stats = manager.stats();
    assert_eq!(stats.messages_cached, 2);
    assert_eq!(stats.messages_delivered_from_cache, 2);
}

#[test]
fn test_store_forward_multiple_offline_nodes() {
    // Test managing cache for multiple offline nodes simultaneously
    let mut manager = StoreAndForwardManager::new();

    // Cache messages for 5 different nodes
    for node_id in 1..=5u8 {
        let node = create_node_id(node_id);
        for _msg_id in 0..3 {
            let msg = create_test_message(100, node_id);
            manager.cache_for_offline(&node, msg);
        }
    }

    // Verify all cached
    let stats = manager.stats();
    assert_eq!(stats.messages_cached, 15);
    assert_eq!(stats.current_cached_count, 15);

    // Bring nodes online in sequence
    let mut total_retrieved = 0;
    for node_id in 1..=5u8 {
        let node = create_node_id(node_id);
        let retrieved = manager.retrieve_for_online_node(&node);
        assert_eq!(retrieved.len(), 3);
        total_retrieved += retrieved.len();
    }

    assert_eq!(total_retrieved, 15);

    let final_stats = manager.stats();
    assert_eq!(final_stats.messages_delivered_from_cache, 15);
    assert_eq!(final_stats.current_cached_count, 0);
}

#[test]
fn test_store_forward_cache_limits() {
    // Test that cache respects size limits and uses eviction
    let mut manager = StoreAndForwardManager::with_limits(10, 50);

    let node1 = create_node_id(1);
    let node2 = create_node_id(2);

    // Cache messages for node1
    for i in 0..15 {  // Try to cache more than per-node limit
        let msg = create_test_message(i, 1);
        let _status = manager.cache_for_offline(&node1, msg);
    }

    // Should have cached up to the per-node limit (10)
    let actual_count = manager.cached_message_count(&node1);
    assert!(actual_count <= 10, "Per-node count {} should be <= 10", actual_count);

    // Can still cache for different node (within total limit)
    let msg = create_test_message(100, 2);
    let status = manager.cache_for_offline(&node2, msg);
    assert_eq!(status, StoreForwardStatus::Cached);
}

#[test]
fn test_store_forward_cleanup_expired() {
    // Test cleanup of expired messages
    let mut manager = StoreAndForwardManager::new();
    let node = create_node_id(1);

    // Cache a message
    let msg = create_test_message(2, 1);
    manager.cache_for_offline(&node, msg);

    assert_eq!(manager.stats().current_cached_count, 1);

    // Cleanup (message should not be expired immediately)
    let expired_count = manager.cleanup_expired_messages();
    assert_eq!(expired_count, 0); // Fresh message shouldn't expire

    // Message should still be there
    assert_eq!(manager.stats().current_cached_count, 1);
}

// ============================================================================
// STRATEGY COMPOSITION INTEGRATION TESTS
// ============================================================================

#[test]
fn test_strategy_composition_multipath() {
    // Test that multipath strategy limits number of paths
    let base_selector = PathSelector::new();
    let enhanced = EnhancedPathSelector::new(base_selector)
        .with_multipath(MultiPathStrategy::BestN(2));

    let target = create_node_id(99);
    let candidates = vec![
        create_test_node(1, 20.0, true),
        create_test_node(2, 30.0, true),
        create_test_node(3, 40.0, true),
        create_test_node(4, 50.0, true),
    ];

    let selection = enhanced.select_optimized_paths(target, candidates);

    // Should have primary + at most 2 alternatives
    assert!(selection.primary.is_some());
    assert!(selection.alternatives.len() <= 2,
        "Expected <= 2 alternatives, got {}", selection.alternatives.len());
}

#[test]
fn test_strategy_composition_adaptive() {
    // Test that adaptive routing adjusts costs based on metrics
    let base_selector = PathSelector::new();
    let mut enhanced = EnhancedPathSelector::new(base_selector)
        .with_adaptive_routing();

    // Add metrics for a node with poor quality
    let degraded_node = create_node_id(1);
    let mut metrics = myriadmesh_routing::LinkMetrics::new();
    metrics.update(100.0, true, 100000, 0.9); // High latency, packet loss, high utilization

    enhanced.update_node_metrics(degraded_node, metrics);

    let target = create_node_id(99);
    let candidates = vec![create_test_node(1, 50.0, true)];

    let selection = enhanced.select_optimized_paths(target, candidates);

    // Cost should be adjusted upward due to poor metrics
    assert!(selection.primary.is_some());
    let cost = selection.primary.as_ref().unwrap().estimated_cost;
    // Base cost for 50ms = 25.0, should be higher with adaptive penalty
    assert!(cost > 25.0, "Cost {} should reflect adaptive penalty", cost);
}

#[test]
fn test_strategy_composition_all_together() {
    // Test that all strategies can be composed together
    let base_selector = PathSelector::new();
    let enhanced = EnhancedPathSelector::new(base_selector)
        .with_multipath(MultiPathStrategy::BestN(3))
        .with_adaptive_routing();

    let target = create_node_id(99);
    let candidates = vec![
        create_test_node(1, 10.0, true),
        create_test_node(2, 20.0, true),
        create_test_node(3, 30.0, true),
        create_test_node(4, 40.0, true),
        create_test_node(5, 50.0, true),
    ];

    let selection = enhanced.select_optimized_paths(target, candidates);

    // Should have primary and limited alternatives due to multipath
    assert!(selection.primary.is_some());
    assert!(selection.alternatives.len() <= 3);
}

// ============================================================================
// COMPLEX SCENARIO TESTS
// ============================================================================

#[test]
fn test_scenario_node_comes_online_after_offline_period() {
    // Simulate a realistic scenario: node goes offline, messages cached, node comes back
    let mut store_forward = StoreAndForwardManager::new();
    let selector = PathSelector::new();

    let offline_node = create_node_id(50);

    // Simulate routing to offline node - cache messages
    for i in 1..=3 {
        let msg = create_test_message(i, 50);
        let status = store_forward.cache_for_offline(&offline_node, msg);
        assert_eq!(status, StoreForwardStatus::Cached);
    }

    // Node comes online - retrieve from cache
    let cached_msgs = store_forward.retrieve_for_online_node(&offline_node);
    assert_eq!(cached_msgs.len(), 3);

    // Now select path to this node (it's online)
    let candidates = vec![create_test_node(50, 25.0, true)];
    let selection = selector.select_paths(offline_node, candidates);

    assert!(selection.primary.is_some());
    assert_eq!(selection.primary.unwrap().hop_count, 1);
}

#[test]
fn test_scenario_fallback_through_adapters_and_paths() {
    // Test complete fallback scenario: primary adapter fails, fallback to secondary,
    // primary path unavailable, fallback to alternative
    let mut adapter_selector = AdapterSelector::new(vec![
        AdapterTier::new(vec![AdapterId::new(1), AdapterId::new(2)], 10, 50),
        AdapterTier::new(vec![AdapterId::new(3)], 5, 50),
    ]);

    let path_selector = PathSelector::new();

    let conditions = NetworkConditions::default();

    // Step 1: Select adapter - should get first one
    let adapter1 = adapter_selector.select_adapter(&conditions).unwrap();
    assert_eq!(adapter1.0, 1);

    // Step 2: Mark it failed
    adapter_selector.mark_adapter_failed(adapter1);

    // Step 3: Select again - should get second adapter
    let adapter2 = adapter_selector.select_adapter(&conditions).unwrap();
    assert_eq!(adapter2.0, 2);

    // Step 4: Select paths for fallback routing
    let candidates = vec![
        create_test_node(10, 30.0, true),
        create_test_node(20, 50.0, true),
    ];
    let target = create_node_id(100);
    let selection = path_selector.select_paths(target, candidates);

    // Should have primary and alternative
    assert!(selection.primary.is_some());
    assert!(!selection.alternatives.is_empty());
}

#[test]
fn test_scenario_high_volume_caching() {
    // Test store-and-forward with high message volume
    let mut manager = StoreAndForwardManager::with_limits(200, 1000);

    // Simulate 10 offline nodes each receiving 10 messages
    let mut total_cached = 0;
    for node_id in 1..=10u8 {
        let node = create_node_id(node_id);
        for msg_id in 0..10 {
            let msg = create_test_message(msg_id, node_id);
            let status = manager.cache_for_offline(&node, msg);
            if let StoreForwardStatus::Cached = status {
                total_cached += 1;
            }
        }
    }

    assert_eq!(total_cached, 100);

    let stats = manager.stats();
    assert_eq!(stats.messages_cached, 100);
    assert_eq!(stats.current_cached_count, 100);

    // Bring all nodes online and retrieve
    let mut total_retrieved = 0;
    for node_id in 1..=10u8 {
        let node = create_node_id(node_id);
        let retrieved = manager.retrieve_for_online_node(&node);
        total_retrieved += retrieved.len();
    }

    assert_eq!(total_retrieved, 100);
}
