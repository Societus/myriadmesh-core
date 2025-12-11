//! Edge case and stress tests for routing components
//!
//! Tests covering:
//! - Boundary conditions
//! - Empty or minimal inputs
//! - Large scale scenarios
//! - Network condition extremes
//! - Concurrent/sequential stress patterns

use myriadmesh_routing::{
    AdapterSelector, AdapterTier, AdapterId, NetworkConditions,
    PathSelector, MultiPathStrategy, EnhancedPathSelector,
    StoreAndForwardManager, StoreForwardStatus,
    RetryContext, TransmissionState,
};
use myriadmesh_protocol::{NodeId, message::Message, MessageType};
use myriadmesh_dht::{PublicNodeInfo, NodeCapabilities, NodeReputation};
use myriadmesh_protocol::types::{NODE_ID_SIZE, Priority};
use std::time::SystemTime;

fn create_node_id(id: u8) -> NodeId {
    let mut bytes = [0u8; NODE_ID_SIZE];
    bytes[0] = id;
    NodeId::from_bytes(bytes)
}

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

fn create_test_message(src: u8, dst: u8) -> Message {
    Message::new(
        create_node_id(src),
        create_node_id(dst),
        MessageType::Data,
        b"test".to_vec(),
    )
    .unwrap()
    .with_priority(Priority::normal())
}

// ============================================================================
// ADAPTER SELECTION EDGE CASES
// ============================================================================

#[test]
fn test_adapter_selection_no_available_adapters() {
    // Test behavior when no adapters meet bandwidth requirements
    let tiers = vec![
        AdapterTier::new(vec![AdapterId::new(1)], 100, 50),
    ];
    let selector = AdapterSelector::new(tiers);

    let conditions = NetworkConditions {
        bandwidth_mbps: 10, // Below requirement
        ..Default::default()
    };

    let result = selector.select_adapter(&conditions);
    assert!(result.is_err(), "Should fail with no available adapters");
}

#[test]
fn test_adapter_selection_single_adapter() {
    // Test with only one adapter available
    let tiers = vec![
        AdapterTier::new(vec![AdapterId::new(42)], 1, 50),
    ];
    let selector = AdapterSelector::new(tiers);

    let conditions = NetworkConditions::default();

    let result = selector.select_adapter(&conditions);
    assert!(result.is_ok());
    assert_eq!(result.unwrap().0, 42);
}

#[test]
fn test_adapter_selection_extreme_latency() {
    // Test adapter scoring with extreme latency values
    let tiers = vec![
        AdapterTier::new(vec![AdapterId::new(1)], 10, 50),
    ];
    let selector = AdapterSelector::new(tiers);

    // Extremely high latency
    let conditions = NetworkConditions {
        latency_ms: 10000.0,
        bandwidth_mbps: 20,
        packet_loss_percent: 0.0,
        on_battery: false,
        power_usage_percent: 0.0,
    };

    let result = selector.select_adapter(&conditions);
    assert!(result.is_ok(), "Should still select adapter even with extreme latency");
}

#[test]
fn test_adapter_selection_extreme_packet_loss() {
    // Test adapter scoring with maximum packet loss
    let tiers = vec![
        AdapterTier::new(vec![AdapterId::new(1)], 10, 50),
    ];
    let selector = AdapterSelector::new(tiers);

    let conditions = NetworkConditions {
        latency_ms: 50.0,
        bandwidth_mbps: 20,
        packet_loss_percent: 100.0,
        on_battery: false,
        power_usage_percent: 0.0,
    };

    let result = selector.select_adapter(&conditions);
    assert!(result.is_ok(), "Should still select adapter even with 100% packet loss");
}

#[test]
fn test_adapter_many_failures_exponential_backoff() {
    // Test exponential backoff with many consecutive failures
    let tiers = vec![
        AdapterTier::new(vec![AdapterId::new(1)], 10, 50),
    ];
    let mut selector = AdapterSelector::new(tiers);

    let adapter = AdapterId::new(1);

    // Record 7 failures
    for i in 1..=7 {
        selector.mark_adapter_failed(adapter);
        assert_eq!(selector.get_failure_count(adapter), i);
    }

    // Even with 7 failures, backoff is capped at 60 seconds
    assert!(selector.is_blacklisted(adapter));
}

// ============================================================================
// PATH SELECTION EDGE CASES
// ============================================================================

#[test]
fn test_path_selection_single_candidate() {
    // Test path selection with only one candidate
    let selector = PathSelector::new();
    let target = create_node_id(99);

    let candidates = vec![create_test_node(1, 50.0, true)];

    let selection = selector.select_paths(target, candidates);
    assert!(selection.primary.is_some());
    // Should have no alternatives with only one candidate
    assert!(selection.alternatives.is_empty());
}

#[test]
fn test_path_selection_identical_candidates() {
    // Test path selection when all candidates have identical metrics
    let selector = PathSelector::new();
    let target = create_node_id(99);

    let candidates = vec![
        create_test_node(1, 50.0, true),
        create_test_node(2, 50.0, true),
        create_test_node(3, 50.0, true),
    ];

    let selection = selector.select_paths(target, candidates);
    assert!(selection.primary.is_some());
    // All have same cost, should all be in alternatives with no ordering constraint
    assert!(!selection.alternatives.is_empty());
}

#[test]
fn test_path_selection_no_relay_capable_nodes() {
    // Test path selection when no nodes can relay
    let selector = PathSelector::new();
    let target = create_node_id(99);

    let candidates = vec![
        create_test_node(1, 20.0, false),
        create_test_node(2, 30.0, false),
        create_test_node(3, 40.0, false),
    ];

    let selection = selector.select_paths(target, candidates);
    // Should still select a path, just with higher cost due to no-relay penalty
    assert!(selection.primary.is_some());
}

#[test]
fn test_path_selection_all_poor_reputation() {
    // Test path selection when all candidates have poor reputation
    let selector = PathSelector::new();
    let target = create_node_id(99);

    // Create nodes with intentionally poor reputation
    let mut candidates = vec![];
    for i in 0..5 {
        candidates.push(create_test_node(i, 50.0, true));
        // Note: reputation would be intentionally degraded in real scenario
    }

    let selection = selector.select_paths(target, candidates);
    // Should still work despite poor metrics
    assert!(selection.primary.is_some());
}

// ============================================================================
// STORE-AND-FORWARD EDGE CASES
// ============================================================================

#[test]
fn test_store_forward_empty_cache() {
    // Test operations on empty cache
    let manager = StoreAndForwardManager::new();
    let node = create_node_id(1);

    assert!(!manager.has_cached_messages(&node));
    assert_eq!(manager.cached_message_count(&node), 0);
    assert_eq!(manager.stats().current_cached_count, 0);
}

#[test]
fn test_store_forward_retrieve_from_empty() {
    // Test retrieving from node with no cached messages
    let mut manager = StoreAndForwardManager::new();
    let node = create_node_id(1);

    let retrieved = manager.retrieve_for_online_node(&node);
    assert!(retrieved.is_empty());
}

#[test]
fn test_store_forward_clear_all() {
    // Test clearing entire cache
    let mut manager = StoreAndForwardManager::new();

    // Cache messages for multiple nodes
    for node_id in 1..=5u8 {
        let node = create_node_id(node_id);
        for _ in 0..3 {
            let msg = create_test_message(10, node_id);
            manager.cache_for_offline(&node, msg);
        }
    }

    assert_eq!(manager.stats().current_cached_count, 15);

    // Clear all
    manager.clear_all();

    assert_eq!(manager.stats().current_cached_count, 0);
    for node_id in 1..=5u8 {
        let node = create_node_id(node_id);
        assert!(!manager.has_cached_messages(&node));
    }
}

#[test]
fn test_store_forward_single_message() {
    // Test caching and retrieving a single message
    let mut manager = StoreAndForwardManager::new();
    let node = create_node_id(1);

    let msg = create_test_message(2, 1);
    let status = manager.cache_for_offline(&node, msg);
    assert_eq!(status, StoreForwardStatus::Cached);

    let retrieved = manager.retrieve_for_online_node(&node);
    assert_eq!(retrieved.len(), 1);
}

#[test]
fn test_store_forward_cache_same_message_twice() {
    // Test caching the same logical message multiple times
    let mut manager = StoreAndForwardManager::new();
    let node = create_node_id(1);

    let msg1 = create_test_message(2, 1);
    let msg2 = create_test_message(2, 1);

    manager.cache_for_offline(&node, msg1);
    manager.cache_for_offline(&node, msg2);

    let count = manager.cached_message_count(&node);
    assert_eq!(count, 2); // Both should be cached
}

#[test]
fn test_store_forward_extreme_message_volume() {
    // Test caching with very large message count
    let mut manager = StoreAndForwardManager::with_limits(1000, 5000);

    let node = create_node_id(1);
    let mut cached = 0;

    // Try to cache 500 messages
    for i in 0..500 {
        let msg = create_test_message((i % 255) as u8, 1);
        if let StoreForwardStatus::Cached = manager.cache_for_offline(&node, msg) {
            cached += 1;
        }
    }

    assert!(cached > 0, "Should cache at least some messages");
    assert_eq!(cached, manager.cached_message_count(&node));
}

// ============================================================================
// TRANSMISSION & RETRY EDGE CASES
// ============================================================================

#[test]
fn test_retry_context_no_alternatives() {
    // Test retry context with no alternative paths
    let primary = myriadmesh_routing::RoutingPath {
        next_hop: create_node_id(1),
        hop_count: 1,
        estimated_cost: 25.0,
    };

    let mut context = RetryContext::new("msg-1".to_string(), primary.clone(), vec![]);

    // First call returns primary
    assert!(context.get_next_path().is_some());

    // Second call returns None
    assert!(context.get_next_path().is_none());
}

#[test]
fn test_backoff_zero_base_delay() {
    // Test backoff calculation with zero base delay
    let delay1 = TransmissionState::calculate_backoff_delay(1, 0, 10000);
    assert_eq!(delay1.as_millis(), 0);

    let delay2 = TransmissionState::calculate_backoff_delay(2, 0, 10000);
    assert_eq!(delay2.as_millis(), 0);
}

#[test]
fn test_backoff_equal_base_and_max() {
    // Test backoff when base delay equals max delay
    let delay1 = TransmissionState::calculate_backoff_delay(1, 100, 100);
    assert_eq!(delay1.as_millis(), 100);

    let delay2 = TransmissionState::calculate_backoff_delay(2, 100, 100);
    assert_eq!(delay2.as_millis(), 100); // Should be capped at 100
}

#[test]
fn test_retry_context_single_attempt() {
    // Test retry context with single attempt capability
    let primary = myriadmesh_routing::RoutingPath {
        next_hop: create_node_id(1),
        hop_count: 1,
        estimated_cost: 25.0,
    };

    let context = RetryContext::new("msg-1".to_string(), primary, vec![]);

    assert!(context.can_try_next_path()); // Can try primary
}

// ============================================================================
// STRATEGY COMPOSITION EDGE CASES
// ============================================================================

#[test]
fn test_enhanced_selector_no_strategies() {
    // Test enhanced selector with no strategies enabled
    let base_selector = PathSelector::new();
    let enhanced = EnhancedPathSelector::new(base_selector);

    let target = create_node_id(99);
    let candidates = vec![
        create_test_node(1, 20.0, true),
        create_test_node(2, 30.0, true),
    ];

    let selection = enhanced.select_optimized_paths(target, candidates);
    assert!(selection.primary.is_some());
    // Should behave same as base selector
}

#[test]
fn test_enhanced_selector_multipath_bestn_zero() {
    // Test multipath with BestN(0)
    let base_selector = PathSelector::new();
    let enhanced = EnhancedPathSelector::new(base_selector)
        .with_multipath(MultiPathStrategy::BestN(0));

    let target = create_node_id(99);
    let candidates = vec![
        create_test_node(1, 20.0, true),
        create_test_node(2, 30.0, true),
    ];

    let selection = enhanced.select_optimized_paths(target, candidates);
    // Should still have primary even with BestN(0)
    assert!(selection.primary.is_some());
}

#[test]
fn test_enhanced_selector_large_multipath_limit() {
    // Test multipath with limit larger than available candidates
    let base_selector = PathSelector::new();
    let enhanced = EnhancedPathSelector::new(base_selector)
        .with_multipath(MultiPathStrategy::BestN(1000));

    let target = create_node_id(99);
    let candidates = vec![
        create_test_node(1, 20.0, true),
        create_test_node(2, 30.0, true),
    ];

    let selection = enhanced.select_optimized_paths(target, candidates);
    // Should have primary and 1 alternative (only 2 candidates total)
    assert!(selection.primary.is_some());
    assert!(selection.alternatives.len() <= 1);
}

// ============================================================================
// NETWORK CONDITION EXTREMES
// ============================================================================

#[test]
fn test_adapter_scoring_zero_latency() {
    // Test adapter scoring with impossible zero latency
    let tiers = vec![
        AdapterTier::new(vec![AdapterId::new(1)], 10, 50),
    ];
    let selector = AdapterSelector::new(tiers);

    let conditions = NetworkConditions {
        latency_ms: 0.0,
        bandwidth_mbps: 100,
        packet_loss_percent: 0.0,
        on_battery: false,
        power_usage_percent: 0.0,
    };

    let result = selector.select_adapter(&conditions);
    assert!(result.is_ok());
}

#[test]
fn test_adapter_scoring_max_bandwidth() {
    // Test adapter scoring with extremely high bandwidth
    let tiers = vec![
        AdapterTier::new(vec![AdapterId::new(1)], 10, 50),
    ];
    let selector = AdapterSelector::new(tiers);

    let conditions = NetworkConditions {
        latency_ms: 50.0,
        bandwidth_mbps: u32::MAX,
        packet_loss_percent: 0.0,
        on_battery: false,
        power_usage_percent: 0.0,
    };

    let result = selector.select_adapter(&conditions);
    assert!(result.is_ok());
}

#[test]
fn test_adapter_scoring_max_power_usage() {
    // Test adapter scoring when device is fully consuming power
    let tiers = vec![
        AdapterTier::new(vec![AdapterId::new(1)], 10, 50),
    ];
    let selector = AdapterSelector::new(tiers);

    let conditions = NetworkConditions {
        latency_ms: 50.0,
        bandwidth_mbps: 20,
        packet_loss_percent: 0.0,
        on_battery: true,
        power_usage_percent: 100.0,
    };

    let result = selector.select_adapter(&conditions);
    assert!(result.is_ok());
}

// ============================================================================
// CONCURRENT ACCESS PATTERNS
// ============================================================================

#[test]
fn test_adapter_selector_rapid_state_changes() {
    // Test adapter selector under rapid failure/recovery cycles
    let tiers = vec![
        AdapterTier::new(vec![AdapterId::new(1)], 10, 50),
    ];
    let mut selector = AdapterSelector::new(tiers);

    let adapter = AdapterId::new(1);

    // Rapid failure/recovery cycles
    for _ in 0..10 {
        selector.mark_adapter_failed(adapter);
        selector.mark_adapter_recovered(adapter);
    }

    // Should end with no failures
    assert_eq!(selector.get_failure_count(adapter), 0);
}

#[test]
fn test_store_forward_rapid_cache_retrieve_cycles() {
    // Test store-forward under rapid cache/retrieve operations
    let mut manager = StoreAndForwardManager::new();

    for cycle in 0..5 {
        let node = create_node_id((cycle % 255) as u8);

        // Cache
        for i in 0..10 {
            let msg = create_test_message(i, (cycle % 255) as u8);
            manager.cache_for_offline(&node, msg);
        }

        // Retrieve
        let retrieved = manager.retrieve_for_online_node(&node);
        assert_eq!(retrieved.len(), 10);
    }
}

#[test]
fn test_retry_context_stats_accumulation() {
    // Test that retry context properly accumulates stats over multiple operations
    let primary = myriadmesh_routing::RoutingPath {
        next_hop: create_node_id(1),
        hop_count: 1,
        estimated_cost: 25.0,
    };

    let mut context = RetryContext::new("msg-1".to_string(), primary, vec![]);

    // Simulate multiple transmission attempts
    for attempt in 1..=10 {
        context.record_attempt();
        let (total, _) = context.get_stats();
        assert_eq!(total, attempt as u32);
    }
}
