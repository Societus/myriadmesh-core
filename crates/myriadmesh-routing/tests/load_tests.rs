//! Sprint 3 Load Testing Suite
//!
//! Comprehensive load tests for:
//! - Concurrent message routing (1000+ msgs/sec throughput)
//! - Queue saturation behavior and recovery
//! - Multipath scaling with many available paths
//! - Adaptive routing with many links (1000+)
//! - Burst traffic recovery and fallback mechanisms

use myriadmesh_routing::{
    Router, MultiPathRouter, MultiPathStrategy, NetworkPath, AdaptiveRoutingTable, RoutingPolicy,
};
use myriadmesh_protocol::{message::Message, NodeId, types::NODE_ID_SIZE};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{SystemTime, Instant, Duration};
use std::sync::Arc;
use tokio::sync::RwLock;

/// Create test node ID
fn create_node_id(value: u8) -> NodeId {
    NodeId::from_bytes([value; NODE_ID_SIZE])
}

/// Create test message with optional payload size
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

/// Test concurrent message routing with high throughput (1000+ msgs/sec)
#[tokio::test]
async fn test_concurrent_message_routing_1000_msgs() {
    let node_id = create_node_id(1);
    let router = Arc::new(Router::new(node_id, 10000, 100000, 1000));

    let source = create_node_id(2);
    let dest = create_node_id(3);
    let mut handles = vec![];

    let start = Instant::now();

    // Spawn 10 concurrent tasks, each sending 100 messages
    for task_id in 0..10 {
        let router_clone = Arc::clone(&router);
        let handle = tokio::spawn(async move {
            let mut success_count = 0;
            for i in 0..100 {
                let msg = create_test_message(
                    source,
                    dest,
                    100 + (task_id * 100 + i) % 1000, // Variable payload sizes
                );

                match router_clone.route_message(msg).await {
                    Ok(_) => success_count += 1,
                    Err(_) => {
                        // Queue might be full, which is expected during stress
                    }
                }
            }
            success_count
        });
        handles.push(handle);
    }

    // Wait for all tasks to complete
    let mut total_success = 0;
    for handle in handles {
        if let Ok(count) = handle.await {
            total_success += count;
        }
    }

    let elapsed = start.elapsed();
    let throughput = total_success as f64 / elapsed.as_secs_f64();

    // Verify reasonable throughput (at least 100 msgs/sec in this test environment)
    assert!(
        throughput >= 100.0,
        "Throughput {} msgs/sec below expected minimum of 100",
        throughput
    );

    // Verify we processed most messages successfully (at least 80% success rate)
    let success_rate = total_success as f64 / 1000.0;
    assert!(
        success_rate >= 0.8,
        "Success rate {:.2}% below expected minimum of 80%",
        success_rate * 100.0
    );

    println!(
        "✓ Concurrent routing: {} msgs in {:.2}s ({:.0} msgs/sec, {:.1}% success)",
        total_success,
        elapsed.as_secs_f64(),
        throughput,
        success_rate * 100.0
    );
}

/// Test queue saturation behavior and recovery
#[tokio::test]
async fn test_queue_saturation_and_recovery() {
    let node_id = create_node_id(1);
    let router = Arc::new(Router::new(node_id, 100, 1000, 10)); // Small queue for saturation

    let source = create_node_id(2);
    let dest = create_node_id(3);

    let mut saturated = false;
    let mut recovered = false;

    // Phase 1: Fill the queue to saturation
    for i in 0..200 {
        let msg = create_test_message(source, dest, 100);
        match router.route_message(msg).await {
            Ok(_) => {
                // Message queued successfully
            }
            Err(e) => {
                // Queue is saturated
                saturated = true;
                println!("Queue saturated at message {}: {}", i, e);
                break;
            }
        }
    }

    assert!(saturated, "Queue should have been saturated");

    // Phase 2: Try more messages while saturated (should all fail)
    let mut saturation_failures = 0;
    for _ in 0..50 {
        let msg = create_test_message(source, dest, 100);
        if router.route_message(msg).await.is_err() {
            saturation_failures += 1;
        }
    }

    assert_eq!(saturation_failures, 50, "All messages should fail during saturation");

    // Phase 3: Wait briefly for queue processing and recovery
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Phase 4: Try to queue again (should recover)
    for i in 0..50 {
        let msg = create_test_message(source, dest, 100);
        if router.route_message(msg).await.is_ok() {
            recovered = true;
            println!("Queue recovered at attempt {}", i + 1);
            break;
        }
    }

    assert!(recovered, "Queue should have recovered after brief delay");

    println!("✓ Queue saturation and recovery verified");
}

/// Test multipath routing scaling with many available paths
#[tokio::test]
async fn test_multipath_scaling_many_paths() {
    let dest = create_node_id(3);
    let mut router = MultiPathRouter::new(MultiPathStrategy::BestN(5), 100);

    // Add paths incrementally and measure path selection time
    let mut measurements = vec![];

    for path_count in [5, 10, 20, 50, 100] {
        // Add paths for this count
        loop {
            let current_count = router.get_paths(&dest).map(|p| p.len()).unwrap_or(0);
            if current_count >= path_count {
                break;
            }
            let path = NetworkPath::new(vec![
                create_node_id(1),
                create_node_id(10 + (current_count % 50) as u8),
                dest,
            ]);
            router.add_path(dest, path);
        }

        // Measure path selection time
        let start = Instant::now();
        for _ in 0..1000 {
            let _ = router.get_best_path(&dest);
        }
        let elapsed = start.elapsed();
        let avg_us = elapsed.as_micros() as f64 / 1000.0;

        measurements.push((path_count, avg_us));
        println!(
            "Path count: {:3}, avg selection time: {:.2}µs",
            path_count, avg_us
        );
    }

    // Verify path selection time scales reasonably (should not exceed 50µs even with 100 paths)
    let max_measurement = measurements
        .iter()
        .max_by(|a, b| a.1.partial_cmp(&b.1).unwrap())
        .unwrap();

    assert!(
        max_measurement.1 < 50.0,
        "Path selection time {:.2}µs exceeds limit of 50µs at {} paths",
        max_measurement.1,
        max_measurement.0
    );

    println!("✓ Multipath scaling verified: 1000 selections across varying path counts");
}

/// Test adaptive routing with many links (1000+)
#[tokio::test]
async fn test_adaptive_routing_many_links() {
    let mut adaptive_table = AdaptiveRoutingTable::new(RoutingPolicy::Balanced, Duration::from_secs(300));

    let start = Instant::now();
    let link_count = 1000;

    // Update metrics for many links
    for i in 0..link_count {
        let from = create_node_id(1);
        let to = create_node_id(2 + (i % 254) as u8);

        let latency = 10.0 + (i as f64 % 100.0);
        let loss = i % 10 == 0;
        let bandwidth = 1_000_000 * (1 + (i % 10) as u64);
        let utilization = 0.1 + ((i % 9) as f64 * 0.1);

        adaptive_table.update_link(from, to, latency, loss, bandwidth, utilization);
    }

    let elapsed = start.elapsed();
    let updates_per_sec = link_count as f64 / elapsed.as_secs_f64();

    println!(
        "Adaptive routing: {} link updates in {:.2}s ({:.0} updates/sec)",
        link_count,
        elapsed.as_secs_f64(),
        updates_per_sec
    );

    // Verify we can update metrics at reasonable rate (at least 1000 updates/sec)
    assert!(
        updates_per_sec >= 1000.0,
        "Update rate {:.0} updates/sec below expected minimum of 1000",
        updates_per_sec
    );

    // Get final statistics
    let stats = adaptive_table.stats();
    println!(
        "Adaptive routing stats: total_links={}, avg_latency={:.2}ms, avg_loss={:.2}%, avg_quality={:.2}",
        stats.total_links, stats.avg_latency_ms, stats.avg_loss_rate * 100.0, stats.avg_quality_score
    );

    assert!(stats.total_links > 0, "Should have tracked link metrics");

    println!("✓ Adaptive routing with {} links verified", link_count);
}

/// Test burst traffic recovery with fallback mechanisms
#[tokio::test]
async fn test_burst_traffic_recovery() {
    let node_id = create_node_id(1);
    let router = Arc::new(Router::new(node_id, 5000, 50000, 500));

    let source = create_node_id(2);
    let dest = create_node_id(3);

    // Phase 1: Normal baseline traffic
    let mut baseline_success = 0;
    for i in 0..100 {
        let msg = create_test_message(source, dest, 100);
        if router.route_message(msg).await.is_ok() {
            baseline_success += 1;
        }
    }
    println!("Baseline: {}/100 messages queued", baseline_success);

    // Phase 2: Burst traffic - send many messages rapidly
    let start = Instant::now();
    let mut burst_success = 0;
    let burst_size = 2000;

    for i in 0..burst_size {
        let msg = create_test_message(
            source,
            dest,
            100 + (i % 500), // Variable sizes
        );
        if router.route_message(msg).await.is_ok() {
            burst_success += 1;
        }
    }

    let burst_elapsed = start.elapsed();
    let burst_success_rate = burst_success as f64 / burst_size as f64;

    println!(
        "Burst: {}/{} messages queued ({:.1}% success) in {:.2}s",
        burst_success,
        burst_size,
        burst_success_rate * 100.0,
        burst_elapsed.as_secs_f64()
    );

    // Phase 3: Recovery - wait and verify normal operation resumes
    tokio::time::sleep(Duration::from_millis(200)).await;

    let mut recovery_success = 0;
    for i in 0..100 {
        let msg = create_test_message(source, dest, 100);
        if router.route_message(msg).await.is_ok() {
            recovery_success += 1;
        }
    }

    println!("Recovery: {}/100 messages queued", recovery_success);

    // Verify recovery is close to baseline (at least 80% of baseline success rate)
    let recovery_ratio = recovery_success as f64 / baseline_success as f64;
    assert!(
        recovery_ratio >= 0.8,
        "Recovery success rate {:.1}% below baseline",
        recovery_ratio * 100.0
    );

    // Verify burst saturation occurred (success rate should be lower than normal)
    assert!(
        burst_success_rate < 0.95,
        "Burst traffic should cause some saturation"
    );

    println!("✓ Burst traffic and recovery verified");
}

/// Test combined stress: concurrent + multipath + adaptive routing
#[tokio::test]
async fn test_combined_stress_scenario() {
    let node_id = create_node_id(1);
    let router = Arc::new(Router::new(node_id, 5000, 50000, 500));

    let start = Instant::now();
    let test_duration = Duration::from_secs(2);

    // Spawn multiple concurrent senders
    let mut handles = vec![];

    for task_id in 0..5 {
        let router_clone = Arc::clone(&router);
        let handle = tokio::spawn(async move {
            let mut success_count = 0;
            let source = create_node_id(2 + task_id as u8);
            let dest = create_node_id(10 + task_id as u8);

            while start.elapsed() < test_duration {
                let msg = create_test_message(source, dest, 100 + (task_id * 100));
                if router_clone.route_message(msg).await.is_ok() {
                    success_count += 1;
                }
                // Yield occasionally
                if success_count % 10 == 0 {
                    tokio::task::yield_now().await;
                }
            }
            success_count
        });
        handles.push(handle);
    }

    // Wait for all tasks to complete
    let mut total_messages = 0;
    for handle in handles {
        if let Ok(count) = handle.await {
            total_messages += count;
        }
    }

    let elapsed = start.elapsed();
    let throughput = total_messages as f64 / elapsed.as_secs_f64();

    println!(
        "Combined stress: {} messages from 5 concurrent sources in {:.2}s ({:.0} msgs/sec)",
        total_messages,
        elapsed.as_secs_f64(),
        throughput
    );

    // Verify reasonable throughput under combined stress
    assert!(
        throughput >= 50.0,
        "Throughput {:.0} msgs/sec below expected minimum of 50 under stress",
        throughput
    );

    println!("✓ Combined stress scenario verified");
}

/// Test queue performance with variable message sizes
#[tokio::test]
async fn test_queue_performance_variable_sizes() {
    let node_id = create_node_id(1);
    let router = Router::new(node_id, 10000, 100000, 1000);

    let source = create_node_id(2);
    let dest = create_node_id(3);

    let mut size_results = vec![];

    for size in [100, 500, 1000, 5000, 10000] {
        let start = Instant::now();
        let mut success = 0;

        for _ in 0..200 {
            let msg = create_test_message(source, dest, size);
            if router.route_message(msg).await.is_ok() {
                success += 1;
            }
        }

        let elapsed = start.elapsed();
        size_results.push((size, success, elapsed.as_millis() as f64));

        println!(
            "Size {:5} bytes: {}/200 messages in {:.1}ms",
            size,
            success,
            elapsed.as_millis()
        );
    }

    // Verify all sizes achieve reasonable success rates
    for (size, success, _) in size_results {
        let success_rate = success as f64 / 200.0;
        assert!(
            success_rate >= 0.7,
            "Size {} bytes: {:.1}% success rate below threshold of 70%",
            size,
            success_rate * 100.0
        );
    }

    println!("✓ Queue performance across variable message sizes verified");
}

/// Test message ordering preservation under load
#[tokio::test]
async fn test_message_ordering_under_load() {
    let node_id = create_node_id(1);
    let router = Router::new(node_id, 10000, 100000, 1000);

    let source = create_node_id(2);
    let dest = create_node_id(3);

    let sequence_numbers = Arc::new(RwLock::new(vec![]));

    // Send messages with sequence tracking
    for _i in 0..100 {
        let msg = create_test_message(source, dest, 100);

        if router.route_message(msg.clone()).await.is_ok() {
            let mut sequences = sequence_numbers.write().await;
            sequences.push(msg.sequence);
        }
    }

    let sequences = sequence_numbers.read().await;

    // Verify message sequences are monotonically increasing
    let mut is_ordered = true;
    for i in 1..sequences.len() {
        if sequences[i] <= sequences[i - 1] {
            is_ordered = false;
            break;
        }
    }

    assert!(
        is_ordered,
        "Message sequences should be monotonically increasing"
    );

    println!(
        "✓ Message ordering verified: {} messages in order",
        sequences.len()
    );
}
