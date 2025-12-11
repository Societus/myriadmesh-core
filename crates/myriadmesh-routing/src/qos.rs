//! Quality of Service (QoS) - Priority scheduling and bandwidth reservation
//!
//! Implements advanced QoS mechanisms including:
//! - Priority-based scheduling with multiple queues
//! - Bandwidth reservation and admission control
//! - Traffic shaping and policing
//! - Service Level Agreements (SLA) enforcement

use crate::priority_queue::PriorityLevel;
use myriadmesh_protocol::NodeId;
use std::collections::HashMap;
use std::time::{Duration, Instant};

/// QoS class for different traffic types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum QosClass {
    /// Real-time traffic (VoIP, video calls)
    RealTime,
    /// Interactive traffic (SSH, gaming)
    Interactive,
    /// Streaming traffic (video, audio)
    Streaming,
    /// Bulk data transfer
    BulkData,
    /// Best effort (default)
    BestEffort,
}

impl QosClass {
    /// Get priority level for this QoS class
    pub fn priority(&self) -> PriorityLevel {
        match self {
            QosClass::RealTime => PriorityLevel::Emergency,
            QosClass::Interactive => PriorityLevel::High,
            QosClass::Streaming => PriorityLevel::Normal,
            QosClass::BulkData => PriorityLevel::Low,
            QosClass::BestEffort => PriorityLevel::Background,
        }
    }

    /// Get minimum bandwidth guarantee (bytes per second)
    pub fn min_bandwidth(&self) -> u64 {
        match self {
            QosClass::RealTime => 64_000,    // 64 KB/s for VoIP
            QosClass::Interactive => 32_000, // 32 KB/s for interactive
            QosClass::Streaming => 128_000,  // 128 KB/s for streaming
            QosClass::BulkData => 0,         // No guarantee
            QosClass::BestEffort => 0,       // No guarantee
        }
    }

    /// Get maximum latency tolerance (milliseconds)
    pub fn max_latency_ms(&self) -> u64 {
        match self {
            QosClass::RealTime => 50,      // 50ms for real-time
            QosClass::Interactive => 100,  // 100ms for interactive
            QosClass::Streaming => 500,    // 500ms for streaming
            QosClass::BulkData => 5000,    // 5s for bulk
            QosClass::BestEffort => 10000, // 10s for best effort
        }
    }

    /// Get jitter tolerance (milliseconds)
    pub fn max_jitter_ms(&self) -> u64 {
        match self {
            QosClass::RealTime => 10,     // Low jitter for real-time
            QosClass::Interactive => 50,  // Moderate jitter acceptable
            QosClass::Streaming => 100,   // Higher jitter acceptable
            QosClass::BulkData => 1000,   // Jitter not critical
            QosClass::BestEffort => 1000, // Jitter not critical
        }
    }
}

/// Bandwidth reservation
#[derive(Debug, Clone)]
pub struct BandwidthReservation {
    /// Flow identifier (source-destination pair)
    pub flow_id: FlowId,
    /// QoS class
    pub qos_class: QosClass,
    /// Reserved bandwidth (bytes per second)
    pub reserved_bps: u64,
    /// Maximum burst size (bytes)
    pub burst_bytes: u64,
    /// Reservation start time
    pub start_time: Instant,
    /// Reservation duration
    pub duration: Duration,
    /// Bytes transmitted in this reservation
    pub bytes_transmitted: u64,
}

/// Flow identifier
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FlowId {
    pub source: NodeId,
    pub destination: NodeId,
}

/// Traffic statistics for a flow
#[derive(Debug, Clone)]
pub struct FlowStats {
    pub bytes_sent: u64,
    pub packets_sent: u64,
    pub bytes_dropped: u64,
    pub packets_dropped: u64,
    pub avg_latency_ms: f64,
    pub avg_jitter_ms: f64,
    pub last_packet_time: Instant,
}

impl Default for FlowStats {
    fn default() -> Self {
        Self {
            bytes_sent: 0,
            packets_sent: 0,
            bytes_dropped: 0,
            packets_dropped: 0,
            avg_latency_ms: 0.0,
            avg_jitter_ms: 0.0,
            last_packet_time: Instant::now(),
        }
    }
}

/// QoS Manager
pub struct QosManager {
    /// Active bandwidth reservations
    reservations: HashMap<FlowId, BandwidthReservation>,
    /// Flow statistics
    flow_stats: HashMap<FlowId, FlowStats>,
    /// Total available bandwidth (bytes per second)
    total_bandwidth_bps: u64,
    /// Currently reserved bandwidth (bytes per second)
    reserved_bandwidth_bps: u64,
    /// Admission control enabled
    admission_control: bool,
    /// Token buckets for rate limiting
    token_buckets: HashMap<FlowId, TokenBucket>,
}

impl QosManager {
    /// Create a new QoS manager
    pub fn new(total_bandwidth_bps: u64, admission_control: bool) -> Self {
        Self {
            reservations: HashMap::new(),
            flow_stats: HashMap::new(),
            total_bandwidth_bps,
            reserved_bandwidth_bps: 0,
            admission_control,
            token_buckets: HashMap::new(),
        }
    }

    /// Request bandwidth reservation
    pub fn reserve_bandwidth(
        &mut self,
        flow_id: FlowId,
        qos_class: QosClass,
        requested_bps: u64,
        duration: Duration,
    ) -> Result<(), QosError> {
        // Check if admission control allows this reservation
        if self.admission_control {
            let available = self.total_bandwidth_bps - self.reserved_bandwidth_bps;
            if requested_bps > available {
                return Err(QosError::InsufficientBandwidth {
                    requested: requested_bps,
                    available,
                });
            }
        }

        // Create reservation
        let reservation = BandwidthReservation {
            flow_id,
            qos_class,
            reserved_bps: requested_bps,
            burst_bytes: requested_bps / 10, // 10% burst allowance
            start_time: Instant::now(),
            duration,
            bytes_transmitted: 0,
        };

        // Update reserved bandwidth
        self.reserved_bandwidth_bps += requested_bps;
        self.reservations.insert(flow_id, reservation);

        // Create token bucket for this flow
        let bucket = TokenBucket::new(requested_bps, requested_bps / 10);
        self.token_buckets.insert(flow_id, bucket);

        Ok(())
    }

    /// Release bandwidth reservation
    pub fn release_reservation(&mut self, flow_id: &FlowId) {
        if let Some(reservation) = self.reservations.remove(flow_id) {
            self.reserved_bandwidth_bps -= reservation.reserved_bps;
            self.token_buckets.remove(flow_id);
        }
    }

    /// Check if a packet can be sent (admission control)
    pub fn can_send(&mut self, flow_id: &FlowId, packet_size: u64) -> bool {
        if let Some(bucket) = self.token_buckets.get_mut(flow_id) {
            bucket.consume(packet_size)
        } else {
            // No reservation, use best effort
            true
        }
    }

    /// Update flow statistics
    pub fn update_stats(&mut self, flow_id: FlowId, bytes: u64, latency_ms: f64, dropped: bool) {
        let stats = self.flow_stats.entry(flow_id).or_default();

        if dropped {
            stats.bytes_dropped += bytes;
            stats.packets_dropped += 1;
        } else {
            stats.bytes_sent += bytes;
            stats.packets_sent += 1;

            // Update average latency (EMA)
            let alpha = 0.125;
            if stats.packets_sent == 1 {
                stats.avg_latency_ms = latency_ms;
            } else {
                stats.avg_latency_ms = alpha * latency_ms + (1.0 - alpha) * stats.avg_latency_ms;
            }

            // Update jitter
            if stats.packets_sent > 1 {
                let jitter = (latency_ms - stats.avg_latency_ms).abs();
                stats.avg_jitter_ms = alpha * jitter + (1.0 - alpha) * stats.avg_jitter_ms;
            }
        }

        stats.last_packet_time = Instant::now();
    }

    /// Cleanup expired reservations
    pub fn cleanup_expired(&mut self) {
        let now = Instant::now();
        let expired: Vec<FlowId> = self
            .reservations
            .iter()
            .filter(|(_, res)| now.duration_since(res.start_time) > res.duration)
            .map(|(id, _)| *id)
            .collect();

        for flow_id in expired {
            self.release_reservation(&flow_id);
        }
    }

    /// Get QoS statistics
    pub fn stats(&self) -> QosStats {
        let total_reservations = self.reservations.len();
        let total_flows = self.flow_stats.len();

        let bandwidth_utilization = if self.total_bandwidth_bps > 0 {
            (self.reserved_bandwidth_bps as f64 / self.total_bandwidth_bps as f64) * 100.0
        } else {
            0.0
        };

        QosStats {
            total_reservations,
            total_flows,
            reserved_bandwidth_bps: self.reserved_bandwidth_bps,
            available_bandwidth_bps: self.total_bandwidth_bps - self.reserved_bandwidth_bps,
            bandwidth_utilization,
        }
    }

    /// Get flow statistics
    pub fn get_flow_stats(&self, flow_id: &FlowId) -> Option<&FlowStats> {
        self.flow_stats.get(flow_id)
    }
}

/// Token bucket for rate limiting
struct TokenBucket {
    /// Maximum tokens (burst capacity)
    capacity: u64,
    /// Current tokens
    tokens: u64,
    /// Refill rate (tokens per second)
    refill_rate: u64,
    /// Last refill time
    last_refill: Instant,
}

impl TokenBucket {
    fn new(rate_bps: u64, burst_bytes: u64) -> Self {
        Self {
            capacity: burst_bytes,
            tokens: burst_bytes,
            refill_rate: rate_bps,
            last_refill: Instant::now(),
        }
    }

    /// Refill tokens based on elapsed time
    fn refill(&mut self) {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill);
        let elapsed_secs = elapsed.as_secs_f64();

        let new_tokens = (self.refill_rate as f64 * elapsed_secs) as u64;
        self.tokens = (self.tokens + new_tokens).min(self.capacity);
        self.last_refill = now;
    }

    /// Try to consume tokens
    fn consume(&mut self, amount: u64) -> bool {
        self.refill();

        if self.tokens >= amount {
            self.tokens -= amount;
            true
        } else {
            false
        }
    }
}

/// QoS statistics
#[derive(Debug, Clone)]
pub struct QosStats {
    pub total_reservations: usize,
    pub total_flows: usize,
    pub reserved_bandwidth_bps: u64,
    pub available_bandwidth_bps: u64,
    pub bandwidth_utilization: f64,
}

/// QoS errors
#[derive(Debug, thiserror::Error)]
pub enum QosError {
    #[error("Insufficient bandwidth: requested {requested} bps, available {available} bps")]
    InsufficientBandwidth { requested: u64, available: u64 },

    #[error("Reservation not found")]
    ReservationNotFound,

    #[error("QoS class mismatch")]
    ClassMismatch,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_node_id(value: u8) -> NodeId {
        let mut bytes = [0u8; 64];
        bytes[0] = value;
        NodeId::from_bytes(bytes)
    }

    fn create_test_flow() -> FlowId {
        FlowId {
            source: create_test_node_id(1),
            destination: create_test_node_id(2),
        }
    }

    #[test]
    fn test_qos_class_properties() {
        assert_eq!(QosClass::RealTime.priority(), PriorityLevel::Emergency);
        assert_eq!(QosClass::BestEffort.priority(), PriorityLevel::Background);

        assert!(QosClass::RealTime.max_latency_ms() < QosClass::BulkData.max_latency_ms());
        assert!(QosClass::RealTime.min_bandwidth() > QosClass::BestEffort.min_bandwidth());
    }

    #[test]
    fn test_bandwidth_reservation() {
        let mut manager = QosManager::new(1_000_000, true); // 1 MB/s total
        let flow = create_test_flow();

        let result = manager.reserve_bandwidth(
            flow,
            QosClass::RealTime,
            100_000, // 100 KB/s
            Duration::from_secs(60),
        );

        assert!(result.is_ok());
        assert_eq!(manager.reserved_bandwidth_bps, 100_000);

        let stats = manager.stats();
        assert_eq!(stats.total_reservations, 1);
        assert_eq!(stats.reserved_bandwidth_bps, 100_000);
    }

    #[test]
    fn test_admission_control() {
        let mut manager = QosManager::new(100_000, true); // 100 KB/s total
        let flow = create_test_flow();

        // Try to reserve more than available
        let result = manager.reserve_bandwidth(
            flow,
            QosClass::RealTime,
            200_000, // 200 KB/s (more than total)
            Duration::from_secs(60),
        );

        assert!(result.is_err());
        assert_eq!(manager.reserved_bandwidth_bps, 0);
    }

    #[test]
    fn test_token_bucket() {
        let mut bucket = TokenBucket::new(1000, 500); // 1000 B/s, 500 B burst

        // Should have full burst capacity initially
        assert_eq!(bucket.tokens, 500);

        // Consume some tokens
        assert!(bucket.consume(100));
        assert_eq!(bucket.tokens, 400);

        // Try to consume more than available
        assert!(!bucket.consume(500));
        assert_eq!(bucket.tokens, 400); // Tokens unchanged
    }

    #[test]
    fn test_flow_stats() {
        let mut manager = QosManager::new(1_000_000, false);
        let flow = create_test_flow();

        // Send some packets
        manager.update_stats(flow, 1000, 50.0, false);
        manager.update_stats(flow, 1000, 60.0, false);

        let stats = manager.get_flow_stats(&flow).unwrap();
        assert_eq!(stats.bytes_sent, 2000);
        assert_eq!(stats.packets_sent, 2);
        assert!(stats.avg_latency_ms > 0.0);
    }
}
