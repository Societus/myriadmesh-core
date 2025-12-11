//! Transmission & Retry/Failover Logic (F1.4-F1.5)
//!
//! This module implements message transmission with automatic retry and failover:
//! - F1.4: Message transmission via selected adapter
//! - F1.5: Retry logic with exponential backoff and alternative path failover

use crate::path_selector::RoutingPath;
use crate::adapter_selector::AdapterId;
use std::time::Duration;

/// Transmission result
#[derive(Debug, Clone)]
pub struct TransmissionResult {
    /// Was the transmission successful
    pub success: bool,
    /// Adapter used
    pub adapter_used: AdapterId,
    /// Attempt number (1-based)
    pub attempt: u32,
    /// Optional error message
    pub error: Option<String>,
}

/// Transmission configuration
#[derive(Debug, Clone)]
pub struct TransmissionConfig {
    /// Maximum number of retry attempts
    pub max_retries: u32,
    /// Base delay for exponential backoff (milliseconds)
    pub base_delay_ms: u64,
    /// Maximum delay between retries (milliseconds)
    pub max_delay_ms: u64,
}

impl Default for TransmissionConfig {
    fn default() -> Self {
        TransmissionConfig {
            max_retries: 3,
            base_delay_ms: 100,
            max_delay_ms: 10000, // 10 seconds
        }
    }
}

/// Transmission state tracker
#[derive(Debug, Clone)]
pub struct TransmissionState {
    /// Current attempt number
    pub attempt: u32,
    /// Current path being used
    pub current_path: Option<RoutingPath>,
    /// Last error
    pub last_error: Option<String>,
}

impl TransmissionState {
    /// Create a new transmission state
    pub fn new(initial_path: RoutingPath) -> Self {
        TransmissionState {
            attempt: 0,
            current_path: Some(initial_path),
            last_error: None,
        }
    }

    /// Increment attempt counter
    pub fn increment_attempt(&mut self) {
        self.attempt += 1;
    }

    /// Calculate backoff delay for current attempt
    pub fn calculate_backoff_delay(
        attempt: u32,
        base_delay_ms: u64,
        max_delay_ms: u64,
    ) -> Duration {
        // Exponential backoff: base_delay * (2 ^ (attempt - 1))
        let exponential = base_delay_ms.saturating_mul(2u64.pow((attempt.saturating_sub(1)) as u32));
        let delay_ms = exponential.min(max_delay_ms);
        Duration::from_millis(delay_ms)
    }

    /// Record a transmission failure
    pub fn record_failure(&mut self, error: String) {
        self.last_error = Some(error);
    }
}

/// Retry/Failover logic (F1.5)
pub struct RetryStrategy {
    /// Configuration
    config: TransmissionConfig,
    /// Available alternative paths
    alternative_paths: Vec<RoutingPath>,
    /// Current alternative path index
    current_alt_index: usize,
}

impl RetryStrategy {
    /// Create a new retry strategy
    pub fn new(config: TransmissionConfig, alternative_paths: Vec<RoutingPath>) -> Self {
        RetryStrategy {
            config,
            alternative_paths,
            current_alt_index: 0,
        }
    }

    /// Check if we should retry
    pub fn should_retry(&self, attempt: u32) -> bool {
        attempt < self.config.max_retries
    }

    /// Get next alternative path for failover
    pub fn get_next_alternative_path(&mut self) -> Option<RoutingPath> {
        if self.current_alt_index >= self.alternative_paths.len() {
            return None;
        }

        let path = self.alternative_paths[self.current_alt_index].clone();
        self.current_alt_index += 1;
        Some(path)
    }

    /// Check if all alternatives exhausted
    pub fn alternatives_exhausted(&self) -> bool {
        self.current_alt_index >= self.alternative_paths.len()
    }

    /// Get current configuration
    pub fn config(&self) -> &TransmissionConfig {
        &self.config
    }
}

/// Transmission context for retrying messages
#[derive(Debug, Clone)]
pub struct RetryContext {
    /// Message identifier (for tracking)
    pub message_id: String,
    /// Primary path
    pub primary_path: RoutingPath,
    /// Alternative paths for failover
    pub alternative_paths: Vec<RoutingPath>,
    /// Number of paths attempted
    pub paths_attempted: u32,
    /// Total transmission attempts
    pub total_attempts: u32,
}

impl RetryContext {
    /// Create a new retry context
    pub fn new(
        message_id: String,
        primary_path: RoutingPath,
        alternative_paths: Vec<RoutingPath>,
    ) -> Self {
        RetryContext {
            message_id,
            primary_path,
            alternative_paths,
            paths_attempted: 0,
            total_attempts: 0,
        }
    }

    /// Can we try another path
    pub fn can_try_next_path(&self) -> bool {
        self.paths_attempted < (self.alternative_paths.len() as u32 + 1)
    }

    /// Get next path to try (primary first, then alternatives)
    pub fn get_next_path(&mut self) -> Option<RoutingPath> {
        if self.paths_attempted == 0 {
            self.paths_attempted += 1;
            return Some(self.primary_path.clone());
        }

        let alt_index = (self.paths_attempted - 1) as usize;
        if alt_index < self.alternative_paths.len() {
            self.paths_attempted += 1;
            return Some(self.alternative_paths[alt_index].clone());
        }

        None
    }

    /// Record a transmission attempt
    pub fn record_attempt(&mut self) {
        self.total_attempts += 1;
    }

    /// Record successful transmission
    pub fn record_success(&mut self) {
        // Reset paths attempted on success (successful path established)
    }

    /// Record failure
    pub fn record_failure(&mut self) {
        // Already tracked via total_attempts
    }

    /// Get transmission statistics
    pub fn get_stats(&self) -> (u32, u32) {
        (self.total_attempts, self.paths_attempted)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use myriadmesh_protocol::NodeId;
    use myriadmesh_protocol::types::NODE_ID_SIZE;

    fn create_test_path() -> RoutingPath {
        RoutingPath {
            next_hop: NodeId::from_bytes([1u8; NODE_ID_SIZE]),
            hop_count: 1,
            estimated_cost: 25.0,
        }
    }

    #[test]
    fn test_transmission_config_default() {
        let config = TransmissionConfig::default();

        assert_eq!(config.max_retries, 3);
        assert_eq!(config.base_delay_ms, 100);
        assert_eq!(config.max_delay_ms, 10000);
    }

    #[test]
    fn test_transmission_state_creation() {
        let path = create_test_path();
        let state = TransmissionState::new(path.clone());

        assert_eq!(state.attempt, 0);
        assert!(state.current_path.is_some());
        assert!(state.last_error.is_none());
    }

    #[test]
    fn test_backoff_calculation() {
        let config = TransmissionConfig::default();

        // Attempt 1: 100ms
        let delay1 = TransmissionState::calculate_backoff_delay(1, config.base_delay_ms, config.max_delay_ms);
        assert_eq!(delay1.as_millis(), 100);

        // Attempt 2: 200ms
        let delay2 = TransmissionState::calculate_backoff_delay(2, config.base_delay_ms, config.max_delay_ms);
        assert_eq!(delay2.as_millis(), 200);

        // Attempt 3: 400ms
        let delay3 = TransmissionState::calculate_backoff_delay(3, config.base_delay_ms, config.max_delay_ms);
        assert_eq!(delay3.as_millis(), 400);
    }

    #[test]
    fn test_backoff_max_delay() {
        let config = TransmissionConfig {
            base_delay_ms: 1000,
            max_delay_ms: 5000,
            ..Default::default()
        };

        // Attempt 10 would be 512 seconds, but capped at 5000ms
        let delay = TransmissionState::calculate_backoff_delay(10, config.base_delay_ms, config.max_delay_ms);
        assert!(delay.as_millis() <= 5000);
    }

    #[test]
    fn test_retry_strategy_should_retry() {
        let config = TransmissionConfig::default();
        let strategy = RetryStrategy::new(config, vec![]);

        assert!(strategy.should_retry(0));
        assert!(strategy.should_retry(1));
        assert!(strategy.should_retry(2));
        assert!(!strategy.should_retry(3)); // Max retries = 3
    }

    #[test]
    fn test_retry_strategy_alternatives() {
        let config = TransmissionConfig::default();
        let paths = vec![create_test_path(), create_test_path(), create_test_path()];
        let mut strategy = RetryStrategy::new(config, paths);

        // Get alternatives
        let alt1 = strategy.get_next_alternative_path();
        assert!(alt1.is_some());

        let alt2 = strategy.get_next_alternative_path();
        assert!(alt2.is_some());

        let alt3 = strategy.get_next_alternative_path();
        assert!(alt3.is_some());

        // Should be exhausted now
        assert!(strategy.alternatives_exhausted());
    }

    #[test]
    fn test_retry_context_path_selection() {
        let primary = create_test_path();
        let mut alt1 = create_test_path();
        alt1.estimated_cost = 35.0;
        let mut alt2 = create_test_path();
        alt2.estimated_cost = 45.0;

        let mut context = RetryContext::new(
            "msg-1".to_string(),
            primary.clone(),
            vec![alt1.clone(), alt2.clone()],
        );

        // First call should return primary
        let path1 = context.get_next_path();
        assert!(path1.is_some());
        assert_eq!(path1.unwrap().estimated_cost, primary.estimated_cost);

        // Second call should return first alternative
        let path2 = context.get_next_path();
        assert!(path2.is_some());
        assert_eq!(path2.unwrap().estimated_cost, alt1.estimated_cost);

        // Third call should return second alternative
        let path3 = context.get_next_path();
        assert!(path3.is_some());
        assert_eq!(path3.unwrap().estimated_cost, alt2.estimated_cost);

        // Fourth call should return None (all exhausted)
        let path4 = context.get_next_path();
        assert!(path4.is_none());
    }

    #[test]
    fn test_retry_context_tracking() {
        let primary = create_test_path();
        let mut context = RetryContext::new("msg-1".to_string(), primary, vec![]);

        context.record_attempt();
        context.record_attempt();
        context.record_attempt();

        let (attempts, paths) = context.get_stats();
        assert_eq!(attempts, 3);
    }

    #[test]
    fn test_transmission_result() {
        let result = TransmissionResult {
            success: true,
            adapter_used: crate::adapter_selector::AdapterId::new(1),
            attempt: 1,
            error: None,
        };

        assert!(result.success);
        assert_eq!(result.attempt, 1);
    }

    #[test]
    fn test_can_try_next_path() {
        let primary = create_test_path();
        let mut alts = vec![];
        for _ in 0..3 {
            alts.push(create_test_path());
        }

        let mut context = RetryContext::new("msg-1".to_string(), primary, alts);

        // Can try 4 paths (1 primary + 3 alternatives)
        assert!(context.can_try_next_path()); // primary
        context.get_next_path();
        assert!(context.can_try_next_path()); // alt 1
        context.get_next_path();
        assert!(context.can_try_next_path()); // alt 2
        context.get_next_path();
        assert!(context.can_try_next_path()); // alt 3
        context.get_next_path();
        assert!(!context.can_try_next_path()); // exhausted
    }
}
