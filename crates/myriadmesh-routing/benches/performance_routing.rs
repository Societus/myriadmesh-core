//! Sprint 3 Performance Testing Framework
//!
//! Benchmarks for:
//! - Message routing throughput
//! - Path selection latency
//! - Multipath routing overhead
//! - Adaptive routing metric updates

use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId, Throughput};
use myriadmesh_routing::{Router, MultiPathRouter, MultiPathStrategy, NetworkPath};
use myriadmesh_protocol::{message::Message, NodeId, types::NODE_ID_SIZE};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::SystemTime;
use std::sync::Arc;

/// Create test node ID
fn create_node_id(value: u8) -> NodeId {
    NodeId::from_bytes([value; NODE_ID_SIZE])
}

/// Create test message
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
    }
}

/// Benchmark: Message routing throughput (simulated async with sync setup)
fn bench_router_throughput(c: &mut Criterion) {
    let mut group = c.benchmark_group("router_throughput");

    for msg_size in [100, 1000, 10000].iter() {
        group.throughput(Throughput::Bytes(*msg_size as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(msg_size),
            msg_size,
            |b, &size| {
                b.iter(|| {
                    let rt = tokio::runtime::Runtime::new().unwrap();
                    rt.block_on(async {
                        let node_id = create_node_id(1);
                        let router = Router::new(node_id, 10000, 100000, 1000);

                        let source = create_node_id(2);
                        let dest = create_node_id(3);
                        let msg = create_test_message(source, dest, size);

                        black_box(router.route_message(black_box(msg)).await).ok()
                    })
                });
            },
        );
    }

    group.finish();
}

/// Benchmark: Multipath routing path selection
fn bench_multipath_selection(c: &mut Criterion) {
    let mut group = c.benchmark_group("multipath_selection");

    for path_count in [1, 5, 10, 20].iter() {
        group.bench_with_input(
            BenchmarkId::from_parameter(path_count),
            path_count,
            |b, &count| {
                b.iter(|| {
                    let mut router = MultiPathRouter::new(MultiPathStrategy::BestN(2), 20);
                    let dest = create_node_id(3);

                    // Add paths
                    for i in 0..count {
                        let path = NetworkPath::new(vec![
                            create_node_id(1),
                            create_node_id(10 + i as u8),
                            dest,
                        ]);
                        router.add_path(dest, path);
                    }

                    // Get best path
                    black_box(router.get_best_path(&dest))
                });
            },
        );
    }

    group.finish();
}

/// Benchmark: Adaptive routing metric updates
fn bench_adaptive_metrics(c: &mut Criterion) {
    let mut group = c.benchmark_group("adaptive_metrics");

    for link_count in [10, 100, 1000].iter() {
        group.bench_with_input(
            BenchmarkId::from_parameter(link_count),
            link_count,
            |b, &count| {
                b.iter(|| {
                    let rt = tokio::runtime::Runtime::new().unwrap();
                    rt.block_on(async {
                        let node_id = create_node_id(1);
                        let router = Router::new(node_id, 10000, 100000, 1000);

                        // Update metrics for multiple links
                        for i in 0..count {
                            let from = create_node_id(1);
                            let to = create_node_id(2 + (i % 50) as u8);

                            router.update_link_metrics(
                                &from,
                                &to,
                                50.0 + (i as f64 % 10.0),
                                i % 10 == 0,
                                10_000_000,
                                0.5,
                            ).await;
                        }

                        black_box(router.get_adaptive_routing_stats().await)
                    })
                });
            },
        );
    }

    group.finish();
}

/// Benchmark: Message queuing performance
fn bench_message_queuing(c: &mut Criterion) {
    c.bench_function("message_queuing_100_msgs", |b| {
        b.iter(|| {
            let rt = tokio::runtime::Runtime::new().unwrap();
            rt.block_on(async {
                let node_id = create_node_id(1);
                let router = Router::new(node_id, 10000, 100000, 1000);

                let source = create_node_id(2);
                let dest = create_node_id(3);

                // Queue 100 messages
                for _ in 0..100 {
                    let msg = create_test_message(source, dest, 1000);
                    black_box(router.route_message(black_box(msg)).await.ok());
                }
            })
        });
    });
}

/// Benchmark: Priority value processing
fn bench_priority_processing(c: &mut Criterion) {
    c.bench_function("priority_matching", |b| {
        b.iter(|| {
            // Simulate priority matching logic
            for priority in black_box([50u8, 160, 200, 240].iter()) {
                let _result = match priority {
                    224..=255 => "Emergency",
                    192..=223 => "High",
                    128..=191 => "Normal",
                    _ => "LowBackground",
                };
                black_box(_result);
            }
        });
    });
}

criterion_group!(
    benches,
    bench_router_throughput,
    bench_multipath_selection,
    bench_adaptive_metrics,
    bench_message_queuing,
    bench_priority_processing,
);

criterion_main!(benches);
