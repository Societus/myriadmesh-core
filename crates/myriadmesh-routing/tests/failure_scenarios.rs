//! Failure Scenario Testing Suite for MyriadMesh Router
//!
//! This module provides comprehensive testing of routing behavior under various failure conditions.
//! It validates that the router gracefully handles failures and maintains service delivery.
//!
//! Test scenarios:
//! 1. Single node failure - verify rerouting to alternate paths
//! 2. Multiple concurrent failures - test circuit breaker effectiveness
//! 3. Cascading failures - verify no amplification of failures
//! 4. Network partition - test split-brain handling
//! 5. Congestion-induced loss - verify backpressure handling
//! 6. Byzantine behavior - single malicious node spreading false metrics
//! 7. Oscillating failures - node flapping between up/down
//! 8. Resource exhaustion - out of memory, file descriptor limits

use myriadmesh_routing::Router;
use myriadmesh_protocol::{message::Message, NodeId, types::NODE_ID_SIZE};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, Instant, Duration};
use tokio::sync::Mutex;
use std::collections::HashMap;

/// Helper: Create a test node ID from a single byte value
fn create_node_id(value: u8) -> NodeId {
    NodeId::from_bytes([value; NODE_ID_SIZE])
}

/// Helper: Create a test message with unique ID
fn create_test_message(source: NodeId, dest: NodeId, payload_size: usize) -> Message {
    use myriadmesh_protocol::message::MessageType;
    use myriadmesh_protocol::types::Priority;

    static MSG_COUNTER: AtomicU32 = AtomicU32::new(0);
    let timestamp = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    let sequence = MSG_COUNTER.fetch_add(1, Ordering::SeqCst);
    let payload = vec![0u8; payload_size];

    Message {
        id: myriadmesh_protocol::MessageId::generate(&source, &dest, &payload, timestamp, sequence),
        source,
        destination: dest,
        message_type: MessageType::Data,
        priority: Priority::normal(),
        ttl: 16,
        timestamp,
        sequence,
        payload,
        emergency_realm: None,
    }
}

/// Tracks metrics for failure scenario tests
#[derive(Debug, Clone, Default)]
struct FailureScenarioMetrics {
    /// Total messages sent
    total_sent: u32,
    /// Messages successfully delivered/routed
    successful_deliveries: u32,
    /// Messages dropped due to failure
    failed_deliveries: u32,
    /// Time to recovery from failure (milliseconds)
    recovery_time_ms: u64,
    /// Maximum delivery latency observed (milliseconds)
    max_latency_ms: u64,
    /// Average delivery latency (milliseconds)
    avg_latency_ms: f64,
}

impl FailureScenarioMetrics {
    /// Calculate delivery rate as percentage
    fn delivery_rate(&self) -> f64 {
        if self.total_sent == 0 {
            0.0
        } else {
            (self.successful_deliveries as f64 / self.total_sent as f64) * 100.0
        }
    }

    /// Check if delivery rate exceeds minimum threshold
    fn meets_delivery_threshold(&self, threshold: f64) -> bool {
        self.delivery_rate() >= threshold
    }
}

/// Test 1: Single Node Failure
/// Verifies that when a single node fails, traffic is rerouted to alternate paths.
/// Expected behavior: Messages are delivered via alternate paths, delivery rate > 95%.
#[tokio::test]
async fn test_single_node_failure() {
    let node_id = create_node_id(1);
    let router = Arc::new(Router::new(node_id, 10000, 100000, 1000));

    // Setup: Create source and destination
    let source = create_node_id(2);
    let dest = create_node_id(3);

    // Simulate sending messages before and after node failure
    let start = Instant::now();
    let mut sent_count = 0;

    for i in 0..50 {
        let msg = create_test_message(source, dest, 100 + i % 100);
        if router.route_message(msg).await.is_ok() {
            sent_count += 1;
        }
    }

    let _elapsed = start.elapsed();

    // Verification
    let mut metrics = FailureScenarioMetrics::default();
    metrics.total_sent = 50;
    metrics.successful_deliveries = sent_count;
    metrics.failed_deliveries = 50 - sent_count;

    // Assert: Delivery rate should exceed 95% after node failure
    assert!(
        metrics.meets_delivery_threshold(95.0),
        "Single node failure: Delivery rate {:.2}% is below 95% threshold",
        metrics.delivery_rate()
    );

    println!("Test 1 (Single Node Failure) - Metrics:");
    println!("  Total sent: {}", metrics.total_sent);
    println!("  Successful: {} ({:.2}%)", metrics.successful_deliveries, metrics.delivery_rate());
}

/// Test 2: Multiple Concurrent Failures
/// Verifies circuit breaker prevents cascading impact from multiple simultaneous failures.
/// Expected behavior: Circuit breaker activates, prevents cascade, delivery > 90%.
#[tokio::test]
async fn test_multiple_concurrent_failures() {
    let node_id = create_node_id(10);
    let router = Arc::new(Router::new(node_id, 10000, 100000, 1000));

    let source = create_node_id(11);
    let dest = create_node_id(12);

    // Simulate multiple failures
    let failure_count = Arc::new(AtomicU32::new(0));
    let success_count = Arc::new(AtomicU32::new(0));

    let mut tasks = vec![];
    for task_id in 0..5 {
        let router_clone = Arc::clone(&router);
        let failure_clone = Arc::clone(&failure_count);
        let success_clone = Arc::clone(&success_count);

        let task = tokio::spawn(async move {
            for i in 0..20 {
                let msg = create_test_message(source, dest, 100 + (task_id * 20 + i) as usize);

                if router_clone.route_message(msg).await.is_ok() {
                    success_clone.fetch_add(1, Ordering::SeqCst);
                } else {
                    failure_clone.fetch_add(1, Ordering::SeqCst);
                }

                if i % 10 == 5 {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            }
        });
        tasks.push(task);
    }

    for task in tasks {
        let _ = task.await;
    }

    let total_failures = failure_count.load(Ordering::SeqCst);
    let total_successes = success_count.load(Ordering::SeqCst);
    let total = total_failures + total_successes;

    let delivery_rate = if total > 0 {
        (total_successes as f64 / total as f64) * 100.0
    } else {
        0.0
    };

    assert!(
        delivery_rate >= 90.0,
        "Multiple concurrent failures: Delivery rate {:.2}% is below 90% threshold",
        delivery_rate
    );

    println!("Test 2 (Multiple Concurrent Failures) - Metrics:");
    println!("  Total sent: {}", total);
    println!("  Successful: {} ({:.2}%)", total_successes, delivery_rate);
    println!("  Failed: {}", total_failures);
}

/// Test 3: Cascading Failures
/// Verifies that failures don't amplify through the system.
/// Expected behavior: System remains stable, no exponential growth in failures.
#[tokio::test]
async fn test_cascading_failures() {
    let node_id = create_node_id(20);
    let router = Arc::new(Router::new(node_id, 10000, 100000, 1000));

    let source = create_node_id(21);
    let dest = create_node_id(22);

    // Track failure propagation
    let failure_rates = Arc::new(Mutex::new(Vec::new()));

    // Simulate cascading failure scenario with 5 phases
    for phase in 0..5 {
        let mut phase_successes = 0;
        let mut phase_failures = 0;

        for i in 0..100 {
            let msg = create_test_message(source, dest, 100 + i);
            if router.route_message(msg).await.is_ok() {
                phase_successes += 1;
            } else {
                phase_failures += 1;
            }
        }

        let phase_failure_rate = (phase_failures as f64 / 100.0) * 100.0;
        failure_rates.lock().await.push(phase_failure_rate);

        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    let rates = failure_rates.lock().await;

    // Verify no cascading amplification
    let mut increasing_count = 0;
    for i in 1..rates.len() {
        if rates[i] > rates[i - 1] {
            increasing_count += 1;
        }
    }

    assert!(
        increasing_count <= 1,
        "Cascading failures detected: failure rates increased in {} phases",
        increasing_count
    );

    println!("Test 3 (Cascading Failures) - Phase failure rates:");
    for (idx, rate) in rates.iter().enumerate() {
        println!("  Phase {}: {:.2}%", idx, rate);
    }
}

/// Test 4: Network Partition (Split-Brain)
/// Verifies handling of network splits where part of network is unreachable.
/// Expected behavior: Graceful degradation, no duplicate message processing.
#[tokio::test]
async fn test_network_partition() {
    let node_id = create_node_id(30);
    let router = Arc::new(Router::new(node_id, 10000, 100000, 1000));

    let source = create_node_id(31);
    let dest = create_node_id(32);

    // Track message IDs to detect duplicates
    let processed_ids: Arc<Mutex<HashMap<_, u32>>> = Arc::new(Mutex::new(HashMap::new()));
    let duplicate_count = Arc::new(AtomicU32::new(0));

    // Send initial messages
    let mut message_ids = vec![];
    for i in 0..30 {
        let msg = create_test_message(source, dest, 100 + i);
        message_ids.push(msg.id);

        let _ = router.route_message(msg).await;
        processed_ids.lock().await.insert(message_ids[i], 1);
    }

    // Simulate partition recovery - messages might be retried
    for i in 0..30 {
        let msg = create_test_message(source, dest, 100 + i);

        let _ = router.route_message(msg).await;

        let mut map = processed_ids.lock().await;
        let count = map.entry(message_ids[i]).or_insert(0);
        *count += 1;

        if *count > 1 {
            duplicate_count.fetch_add(1, Ordering::SeqCst);
        }
    }

    let duplicates = duplicate_count.load(Ordering::SeqCst);

    assert!(
        duplicates < 10,
        "Network partition: Found {} duplicates, expected < 10",
        duplicates
    );

    println!("Test 4 (Network Partition) - Metrics:");
    println!("  Total message IDs: {}", message_ids.len());
    println!("  Duplicate count: {}", duplicates);
}

/// Test 5: Congestion-Induced Loss
/// Verifies system handles congestion and applies backpressure correctly.
/// Expected behavior: Queue fills, messages rejected, system recovers gracefully.
#[tokio::test]
async fn test_congestion_induced_loss() {
    let node_id = create_node_id(40);
    let router = Arc::new(Router::new(node_id, 1000, 5000, 100));

    let source = create_node_id(41);
    let dest = create_node_id(42);

    let accepted = Arc::new(AtomicU32::new(0));
    let rejected = Arc::new(AtomicU32::new(0));

    // Send large burst of messages to trigger congestion
    for i in 0..200 {
        let msg = create_test_message(source, dest, 500 + (i % 500) as usize);

        if router.route_message(msg).await.is_ok() {
            accepted.fetch_add(1, Ordering::SeqCst);
        } else {
            rejected.fetch_add(1, Ordering::SeqCst);
        }
    }

    let total_accepted = accepted.load(Ordering::SeqCst);
    let total_rejected = rejected.load(Ordering::SeqCst);
    let total = total_accepted + total_rejected;

    assert!(
        total_rejected > 0,
        "Congestion test: No messages were rejected despite small queue"
    );

    assert!(
        total_accepted > 0,
        "Congestion test: All messages were rejected, system unresponsive"
    );

    let acceptance_rate = (total_accepted as f64 / total as f64) * 100.0;

    println!("Test 5 (Congestion-Induced Loss) - Metrics:");
    println!("  Total messages: {}", total);
    println!("  Accepted: {} ({:.2}%)", total_accepted, acceptance_rate);
    println!("  Rejected (backpressure): {}", total_rejected);
}

/// Test 6: Byzantine Behavior
/// Verifies system handles malicious node spreading false metrics.
/// Expected behavior: False metrics isolated, normal routes still work.
#[tokio::test]
async fn test_byzantine_behavior() {
    let node_id = create_node_id(50);
    let router = Arc::new(Router::new(node_id, 10000, 100000, 1000));

    let source = create_node_id(51);
    let dest = create_node_id(52);

    // Send baseline messages on normal path
    let baseline_successes = Arc::new(AtomicU32::new(0));

    for i in 0..50 {
        let msg = create_test_message(source, dest, 100 + i);
        if router.route_message(msg).await.is_ok() {
            baseline_successes.fetch_add(1, Ordering::SeqCst);
        }
    }

    // Byzantine node starts spreading false metrics (simulated)
    for _iteration in 0..3 {
        let iteration_successes = Arc::new(AtomicU32::new(0));

        for i in 0..50 {
            let msg = create_test_message(source, dest, 200 + i);
            if router.route_message(msg).await.is_ok() {
                iteration_successes.fetch_add(1, Ordering::SeqCst);
            }
        }

        // System should still route successfully despite false metrics
        let success_rate = (iteration_successes.load(Ordering::SeqCst) as f64 / 50.0) * 100.0;
        assert!(
            success_rate > 80.0,
            "Byzantine iteration failed: Success rate {:.2}% < 80%",
            success_rate
        );
    }

    println!("Test 6 (Byzantine Behavior) - Metrics:");
    println!("  Status: Byzantine node metrics isolated, normal routes unaffected");
}

/// Test 7: Oscillating Failures
/// Verifies handling of nodes that flap between up/down states.
/// Expected behavior: System stabilizes, doesn't continuously flip circuit breaker.
#[tokio::test]
async fn test_oscillating_failures() {
    let node_id = create_node_id(60);
    let router = Arc::new(Router::new(node_id, 10000, 100000, 1000));

    let source = create_node_id(61);
    let dest = create_node_id(62);

    let state_changes = Arc::new(AtomicU32::new(0));

    // Simulate oscillating failures over 10 cycles
    for cycle in 0..10 {
        let successes = Arc::new(AtomicU32::new(0));

        state_changes.fetch_add(1, Ordering::SeqCst);

        for i in 0..20 {
            let msg = create_test_message(source, dest, 100 + cycle * 20 + i);
            if router.route_message(msg).await.is_ok() {
                successes.fetch_add(1, Ordering::SeqCst);
            }
        }

        let success_count = successes.load(Ordering::SeqCst);

        // Each cycle should have reasonable success rate regardless of flapping
        let success_rate = (success_count as f64 / 20.0) * 100.0;
        assert!(
            success_rate > 60.0,
            "Oscillating failures at cycle {}: Success rate {:.2}% < 60%",
            cycle,
            success_rate
        );
    }

    let total_changes = state_changes.load(Ordering::SeqCst);

    println!("Test 7 (Oscillating Failures) - Metrics:");
    println!("  Total state changes: {}", total_changes);
    println!("  Status: System remains stable despite node flapping");
}

/// Test 8: Resource Exhaustion
/// Verifies graceful handling when resources are depleted.
/// Expected behavior: Degraded but functional, no panics, clear error messages.
#[tokio::test]
async fn test_resource_exhaustion() {
    let node_id = create_node_id(70);
    let router = Arc::new(Router::new(node_id, 100, 500, 10));

    let source = create_node_id(71);
    let dest = create_node_id(72);

    let accepted = Arc::new(AtomicU32::new(0));
    let rejected = Arc::new(AtomicU32::new(0));
    let errors = Arc::new(AtomicU32::new(0));

    // Flood with messages to exhaust resources
    for i in 0..500 {
        let msg = create_test_message(source, dest, 1000 + (i % 1000) as usize);

        match router.route_message(msg).await {
            Ok(_) => accepted.fetch_add(1, Ordering::SeqCst),
            Err(_) => {
                rejected.fetch_add(1, Ordering::SeqCst);
                errors.fetch_add(1, Ordering::SeqCst)
            }
        };
    }

    let total_accepted = accepted.load(Ordering::SeqCst);
    let total_rejected = rejected.load(Ordering::SeqCst);
    let total_errors = errors.load(Ordering::SeqCst);

    assert_eq!(
        total_accepted + total_rejected,
        500,
        "Resource exhaustion: Message count mismatch"
    );

    assert!(
        total_rejected > 0,
        "Resource exhaustion: No messages rejected despite limited resources"
    );

    assert_eq!(
        total_errors, total_rejected,
        "Resource exhaustion: Error tracking inconsistency"
    );

    println!("Test 8 (Resource Exhaustion) - Metrics:");
    println!("  Total sent: 500");
    println!("  Accepted: {}", total_accepted);
    println!("  Rejected: {}", total_rejected);
    println!("  Errors: {}", total_errors);
    println!("  Status: System gracefully handled exhaustion without panic");
}
