//! Advanced Error Recovery and Circuit Breaking
//!
//! Implements the circuit breaker pattern for failed routes and congested paths.
//! Prevents cascading failures by temporarily removing routes from rotation
//! and automatically testing recovery.
//!
//! State Machine:
//! - Closed: Normal operation, all requests pass through
//! - Open: Too many failures, requests immediately rejected
//! - Half-Open: Testing if route has recovered
//!
//! Thresholds:
//! - Open after 5 consecutive failures
//! - Half-Open after 30 seconds
//! - Close after 3 successes in Half-Open state

use serde::{Deserialize, Serialize};
use std::time::{Duration, Instant};

/// Threshold for opening circuit (failures)
const FAILURE_THRESHOLD: u32 = 5;

/// Timeout before transitioning from Open to Half-Open (seconds)
const HALF_OPEN_TIMEOUT_SECS: u64 = 30;

/// Successes needed in Half-Open to close circuit
const HALF_OPEN_SUCCESS_THRESHOLD: u32 = 3;

/// Circuit breaker state
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CircuitState {
    /// Circuit is closed - normal operation
    Closed,
    /// Circuit is open - rejecting requests
    Open,
    /// Circuit is half-open - testing recovery
    HalfOpen,
}

impl CircuitState {
    /// Returns true if requests can be sent in this state
    pub fn can_send(&self) -> bool {
        matches!(self, CircuitState::Closed | CircuitState::HalfOpen)
    }

    /// Returns a human-readable description
    pub fn description(&self) -> &'static str {
        match self {
            CircuitState::Closed => "Circuit closed (normal operation)",
            CircuitState::Open => "Circuit open (rejecting requests)",
            CircuitState::HalfOpen => "Circuit half-open (testing recovery)",
        }
    }
}

/// Statistics for a circuit breaker
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CircuitBreakerStats {
    /// Total successful operations
    pub successes: u64,
    /// Total failed operations
    pub failures: u64,
    /// Current consecutive failures (in Closed state)
    pub consecutive_failures: u32,
    /// Number of times circuit opened
    pub total_opens: u32,
    /// Number of times circuit recovered to Closed
    pub total_recoveries: u32,
}

impl Default for CircuitBreakerStats {
    fn default() -> Self {
        Self {
            successes: 0,
            failures: 0,
            consecutive_failures: 0,
            total_opens: 0,
            total_recoveries: 0,
        }
    }
}

/// Circuit breaker for a single path or route
///
/// Tracks failures and automatically prevents cascading failures
/// by rejecting requests to broken paths while periodically testing recovery.
#[derive(Debug, Clone)]
pub struct CircuitBreaker {
    /// Current state of the circuit
    state: CircuitState,
    /// Timestamp of last state change
    state_changed_at: Instant,
    /// Statistics
    stats: CircuitBreakerStats,
    /// Successes in Half-Open state
    half_open_successes: u32,
}

impl CircuitBreaker {
    /// Create a new circuit breaker
    pub fn new() -> Self {
        Self {
            state: CircuitState::Closed,
            state_changed_at: Instant::now(),
            stats: CircuitBreakerStats::default(),
            half_open_successes: 0,
        }
    }

    /// Record the result of an operation
    ///
    /// # Arguments
    /// * `success` - Whether the operation succeeded
    ///
    /// Updates internal state and transitions between states as needed.
    pub fn record_result(&mut self, success: bool) {
        if success {
            self.stats.successes += 1;
            match self.state {
                CircuitState::Closed => {
                    // Reset failure counter on success
                    self.stats.consecutive_failures = 0;
                }
                CircuitState::HalfOpen => {
                    // Track successes in half-open state
                    self.half_open_successes += 1;
                    if self.half_open_successes >= HALF_OPEN_SUCCESS_THRESHOLD {
                        // Recovered! Close the circuit
                        self.state = CircuitState::Closed;
                        self.state_changed_at = Instant::now();
                        self.stats.total_recoveries += 1;
                        self.stats.consecutive_failures = 0;
                        self.half_open_successes = 0;
                    }
                }
                CircuitState::Open => {
                    // Ignore successes when open
                }
            }
        } else {
            self.stats.failures += 1;
            match self.state {
                CircuitState::Closed => {
                    self.stats.consecutive_failures += 1;
                    if self.stats.consecutive_failures >= FAILURE_THRESHOLD {
                        // Too many failures, open the circuit
                        self.state = CircuitState::Open;
                        self.state_changed_at = Instant::now();
                        self.stats.total_opens += 1;
                    }
                }
                CircuitState::HalfOpen => {
                    // Any failure in half-open goes back to open
                    self.state = CircuitState::Open;
                    self.state_changed_at = Instant::now();
                    self.half_open_successes = 0;
                }
                CircuitState::Open => {
                    // Already open, ignore additional failures
                }
            }
        }
    }

    /// Check if requests can be sent through this circuit
    ///
    /// In Open state, checks if timeout has elapsed to transition to Half-Open.
    /// Returns false if circuit is Open and timeout hasn't elapsed.
    pub fn can_send(&mut self) -> bool {
        match self.state {
            CircuitState::Closed | CircuitState::HalfOpen => true,
            CircuitState::Open => {
                // Check if we should transition to half-open
                if self.state_changed_at.elapsed()
                    > Duration::from_secs(HALF_OPEN_TIMEOUT_SECS)
                {
                    self.state = CircuitState::HalfOpen;
                    self.state_changed_at = Instant::now();
                    self.half_open_successes = 0;
                    true
                } else {
                    false
                }
            }
        }
    }

    /// Get the current state of the circuit
    pub fn get_state(&self) -> CircuitState {
        self.state
    }

    /// Manually reset the circuit to closed state
    ///
    /// Useful for administrative reset or when external monitoring
    /// determines the route is healthy again.
    pub fn manual_reset(&mut self) {
        self.state = CircuitState::Closed;
        self.state_changed_at = Instant::now();
        self.stats.consecutive_failures = 0;
        self.half_open_successes = 0;
    }

    /// Get current statistics
    pub fn get_stats(&self) -> CircuitBreakerStats {
        self.stats.clone()
    }

    /// Get time since last state change
    pub fn time_in_current_state(&self) -> Duration {
        self.state_changed_at.elapsed()
    }

    /// Get number of successes needed to recover from half-open
    pub fn successes_to_recover(&self) -> u32 {
        if self.state == CircuitState::HalfOpen {
            HALF_OPEN_SUCCESS_THRESHOLD.saturating_sub(self.half_open_successes)
        } else {
            0
        }
    }

    /// Set the circuit state directly (for testing/administrative purposes)
    ///
    /// This is a backdoor method for testing frameworks or admin tools
    /// that need to simulate state transitions without going through
    /// the normal failure/recovery path.
    pub fn force_state_transition(&mut self, new_state: CircuitState) {
        self.state = new_state;
        self.state_changed_at = Instant::now();
        if new_state == CircuitState::HalfOpen {
            self.half_open_successes = 0;
        }
    }
}

impl Default for CircuitBreaker {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_state_transitions_closed_to_open() {
        let mut cb = CircuitBreaker::new();
        assert_eq!(cb.get_state(), CircuitState::Closed);

        // Record 5 failures to trigger open
        for _ in 0..5 {
            cb.record_result(false);
        }

        assert_eq!(cb.get_state(), CircuitState::Open);
        assert_eq!(cb.get_stats().consecutive_failures, 5);
    }

    #[test]
    fn test_failure_threshold() {
        let mut cb = CircuitBreaker::new();

        // 4 failures should keep circuit closed
        for _ in 0..4 {
            cb.record_result(false);
        }
        assert_eq!(cb.get_state(), CircuitState::Closed);

        // 5th failure should open
        cb.record_result(false);
        assert_eq!(cb.get_state(), CircuitState::Open);
    }

    #[test]
    fn test_success_resets_counter() {
        let mut cb = CircuitBreaker::new();

        // Record 3 failures
        for _ in 0..3 {
            cb.record_result(false);
        }
        assert_eq!(cb.get_stats().consecutive_failures, 3);

        // Success should reset counter
        cb.record_result(true);
        assert_eq!(cb.get_stats().consecutive_failures, 0);

        // Need 5 more failures to open
        for _ in 0..5 {
            cb.record_result(false);
        }
        assert_eq!(cb.get_state(), CircuitState::Open);
    }

    #[test]
    fn test_open_to_half_open_timeout() {
        let mut cb = CircuitBreaker::new();

        // Open the circuit
        for _ in 0..5 {
            cb.record_result(false);
        }
        assert_eq!(cb.get_state(), CircuitState::Open);
        assert!(!cb.can_send());

        // Immediately after opening, should not be able to send
        assert!(!cb.can_send());

        // Simulate passage of time (normally handled by system time)
        // We'll manually set the state to test half-open behavior
        cb.force_state_transition(CircuitState::HalfOpen);
        assert!(cb.can_send());
    }

    #[test]
    fn test_half_open_recovery() {
        let mut cb = CircuitBreaker::new();

        // Open the circuit
        for _ in 0..5 {
            cb.record_result(false);
        }
        assert_eq!(cb.get_state(), CircuitState::Open);

        // Manually transition to half-open
        cb.force_state_transition(CircuitState::HalfOpen);
        assert_eq!(cb.get_state(), CircuitState::HalfOpen);

        // Record 2 successes
        cb.record_result(true);
        cb.record_result(true);
        assert_eq!(cb.get_state(), CircuitState::HalfOpen);
        assert_eq!(cb.successes_to_recover(), 1);

        // 3rd success should close circuit
        cb.record_result(true);
        assert_eq!(cb.get_state(), CircuitState::Closed);
        assert_eq!(cb.get_stats().total_recoveries, 1);
    }

    #[test]
    fn test_half_open_failure_returns_to_open() {
        let mut cb = CircuitBreaker::new();

        // Open and transition to half-open
        for _ in 0..5 {
            cb.record_result(false);
        }
        cb.force_state_transition(CircuitState::HalfOpen);

        // Single failure should return to open
        cb.record_result(false);
        assert_eq!(cb.get_state(), CircuitState::Open);
    }

    #[test]
    fn test_manual_reset() {
        let mut cb = CircuitBreaker::new();

        // Open the circuit
        for _ in 0..5 {
            cb.record_result(false);
        }
        assert_eq!(cb.get_state(), CircuitState::Open);

        // Manually reset
        cb.manual_reset();
        assert_eq!(cb.get_state(), CircuitState::Closed);
        assert_eq!(cb.get_stats().consecutive_failures, 0);
        assert!(cb.can_send());
    }

    #[test]
    fn test_statistics_tracking() {
        let mut cb = CircuitBreaker::new();

        // Record mix of successes and failures
        for _ in 0..3 {
            cb.record_result(true);
            cb.record_result(false);
        }

        let stats = cb.get_stats();
        assert_eq!(stats.successes, 3);
        assert_eq!(stats.failures, 3);
        assert_eq!(stats.total_opens, 0); // Didn't reach threshold
    }

    #[test]
    fn test_integration_scenario() {
        let mut cb = CircuitBreaker::new();

        // Simulate a healthy service
        for _ in 0..10 {
            assert!(cb.can_send());
            cb.record_result(true);
        }
        assert_eq!(cb.get_state(), CircuitState::Closed);

        // Service starts failing
        for _ in 0..5 {
            cb.record_result(false);
        }
        assert_eq!(cb.get_state(), CircuitState::Open);
        assert!(!cb.can_send());

        // Service recovers
        cb.force_state_transition(CircuitState::HalfOpen); // Simulate timeout
        for _ in 0..3 {
            assert!(cb.can_send());
            cb.record_result(true);
        }
        assert_eq!(cb.get_state(), CircuitState::Closed);

        // Back to normal operation
        for _ in 0..5 {
            assert!(cb.can_send());
            cb.record_result(true);
        }
        assert_eq!(cb.get_state(), CircuitState::Closed);
    }

    #[test]
    fn test_can_send_consistency() {
        let mut cb = CircuitBreaker::new();

        // Closed: can always send
        for _ in 0..10 {
            assert!(cb.can_send());
            cb.record_result(true);
        }

        // Open: cannot send
        for _ in 0..5 {
            cb.record_result(false);
        }
        assert_eq!(cb.get_state(), CircuitState::Open);
        assert!(!cb.can_send());

        // Half-open: can send
        cb.force_state_transition(CircuitState::HalfOpen);
        assert!(cb.can_send());
    }
}
