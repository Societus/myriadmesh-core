//! Priority queue system for message routing

use myriadmesh_protocol::Message;
use std::collections::VecDeque;

/// Priority levels for message routing
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum PriorityLevel {
    /// Emergency priority (224-255)
    Emergency = 4,
    /// High priority (192-223)
    High = 3,
    /// Normal priority (128-191)
    Normal = 2,
    /// Low priority (64-127)
    Low = 1,
    /// Background priority (0-63)
    Background = 0,
}

impl PriorityLevel {
    /// Convert from message priority value (0-255)
    pub fn from_priority(priority: u8) -> Self {
        match priority {
            224..=255 => PriorityLevel::Emergency,
            192..=223 => PriorityLevel::High,
            128..=191 => PriorityLevel::Normal,
            64..=127 => PriorityLevel::Low,
            0..=63 => PriorityLevel::Background,
        }
    }

    /// Get queue index (0-4)
    pub fn queue_index(&self) -> usize {
        *self as usize
    }
}

impl From<myriadmesh_protocol::types::Priority> for PriorityLevel {
    fn from(priority: myriadmesh_protocol::types::Priority) -> Self {
        // Priority is now u8 (0-255), convert using value ranges
        PriorityLevel::from_priority(priority.as_u8())
    }
}

/// Message with routing metadata
#[derive(Debug, Clone)]
pub struct QueuedMessage {
    /// The message
    pub message: Message,

    /// When the message was received/queued
    pub received_at: u64,

    /// Retry count for failed deliveries
    pub retry_count: u32,

    /// Next retry time (if applicable)
    pub next_retry: Option<u64>,
}

impl QueuedMessage {
    /// Create a new queued message
    pub fn new(message: Message) -> Self {
        use std::time::{SystemTime, UNIX_EPOCH};
        let now = match SystemTime::now().duration_since(UNIX_EPOCH) {
            Ok(duration) => duration.as_secs(),
            Err(e) => {
                eprintln!("WARNING: System time error in priority queue message: {}. Using fallback timestamp.", e);
                1500000000
            }
        };

        QueuedMessage {
            message,
            received_at: now,
            retry_count: 0,
            next_retry: None,
        }
    }
}

/// Priority queue system with 5 priority levels
#[derive(Debug)]
pub struct PriorityQueue {
    /// Five queues, one per priority level
    queues: [VecDeque<QueuedMessage>; 5],

    /// Maximum messages per queue
    max_per_queue: usize,

    /// Total messages across all queues
    total_messages: usize,
}

impl PriorityQueue {
    /// Create a new priority queue
    pub fn new(max_per_queue: usize) -> Self {
        PriorityQueue {
            queues: [
                VecDeque::new(),
                VecDeque::new(),
                VecDeque::new(),
                VecDeque::new(),
                VecDeque::new(),
            ],
            max_per_queue,
            total_messages: 0,
        }
    }

    /// Enqueue a message with automatic priority detection
    pub fn enqueue(&mut self, message: Message) -> Result<(), String> {
        let priority = PriorityLevel::from(message.priority);
        self.enqueue_with_priority(message, priority)
    }

    /// Enqueue a message with explicit priority
    pub fn enqueue_with_priority(
        &mut self,
        message: Message,
        priority: PriorityLevel,
    ) -> Result<(), String> {
        let queue_idx = priority.queue_index();
        let queue = &mut self.queues[queue_idx];

        // Check queue capacity
        if queue.len() >= self.max_per_queue {
            return Err(format!(
                "Priority queue {} is full (max {})",
                priority.queue_index(),
                self.max_per_queue
            ));
        }

        queue.push_back(QueuedMessage::new(message));
        self.total_messages += 1;
        Ok(())
    }

    /// Dequeue the highest priority message
    pub fn dequeue(&mut self) -> Option<QueuedMessage> {
        // Check queues from highest to lowest priority
        for queue in self.queues.iter_mut().rev() {
            if let Some(msg) = queue.pop_front() {
                self.total_messages -= 1;
                return Some(msg);
            }
        }
        None
    }

    /// Peek at the highest priority message without removing it
    pub fn peek(&self) -> Option<&QueuedMessage> {
        for queue in self.queues.iter().rev() {
            if let Some(msg) = queue.front() {
                return Some(msg);
            }
        }
        None
    }

    /// Get total number of messages across all queues
    pub fn len(&self) -> usize {
        self.total_messages
    }

    /// Check if all queues are empty
    pub fn is_empty(&self) -> bool {
        self.total_messages == 0
    }

    /// Get number of messages in a specific priority queue
    pub fn len_for_priority(&self, priority: PriorityLevel) -> usize {
        self.queues[priority.queue_index()].len()
    }

    /// Clear all queues
    pub fn clear(&mut self) {
        for queue in &mut self.queues {
            queue.clear();
        }
        self.total_messages = 0;
    }

    /// Get statistics for all queues
    pub fn stats(&self) -> PriorityQueueStats {
        PriorityQueueStats {
            emergency: self.queues[4].len(),
            high: self.queues[3].len(),
            normal: self.queues[2].len(),
            low: self.queues[1].len(),
            background: self.queues[0].len(),
            total: self.total_messages,
        }
    }

    /// Re-enqueue a message with updated retry metadata
    /// Used for implementing exponential backoff on failed transmissions
    pub fn requeue_with_retry(
        &mut self,
        mut queued_msg: QueuedMessage,
        retry_delay_secs: u64,
    ) -> Result<(), String> {
        use std::time::{SystemTime, UNIX_EPOCH};
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        queued_msg.retry_count += 1;
        queued_msg.next_retry = Some(now + retry_delay_secs);

        let priority = PriorityLevel::from(queued_msg.message.priority);
        let queue_idx = priority.queue_index();
        let queue = &mut self.queues[queue_idx];

        if queue.len() >= self.max_per_queue {
            return Err(format!(
                "Priority queue {} is full (max {})",
                priority.queue_index(),
                self.max_per_queue
            ));
        }

        queue.push_back(queued_msg);
        self.total_messages += 1;
        Ok(())
    }

    /// Dequeue messages that are ready for retry (past their next_retry time)
    /// Returns None if no messages are ready
    pub fn dequeue_ready_for_retry(&mut self) -> Option<QueuedMessage> {
        use std::time::{SystemTime, UNIX_EPOCH};
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Check queues from highest to lowest priority
        for queue in self.queues.iter_mut().rev() {
            // Find first message that's ready (either no retry time or past retry time)
            if let Some(pos) = queue
                .iter()
                .position(|msg| msg.next_retry.is_none_or(|retry_time| now >= retry_time))
            {
                let msg = queue.remove(pos).unwrap();
                self.total_messages -= 1;
                return Some(msg);
            }
        }

        None
    }
}

impl Default for PriorityQueue {
    fn default() -> Self {
        Self::new(1000) // Default: 1000 messages per priority level
    }
}

/// Statistics for priority queues
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PriorityQueueStats {
    pub emergency: usize,
    pub high: usize,
    pub normal: usize,
    pub low: usize,
    pub background: usize,
    pub total: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use myriadmesh_protocol::types::{Priority, NODE_ID_SIZE};
    use myriadmesh_protocol::{MessageType, NodeId};

    fn create_test_message(priority: Priority) -> Message {
        Message::new(
            NodeId::from_bytes([1u8; NODE_ID_SIZE]),
            NodeId::from_bytes([2u8; NODE_ID_SIZE]),
            MessageType::Data,
            b"test".to_vec(),
        )
        .unwrap()
        .with_priority(priority)
    }

    #[test]
    fn test_priority_level_conversion() {
        assert_eq!(PriorityLevel::from_priority(255), PriorityLevel::Emergency);
        assert_eq!(PriorityLevel::from_priority(200), PriorityLevel::High);
        assert_eq!(PriorityLevel::from_priority(150), PriorityLevel::Normal);
        assert_eq!(PriorityLevel::from_priority(100), PriorityLevel::Low);
        assert_eq!(PriorityLevel::from_priority(50), PriorityLevel::Background);
    }

    #[test]
    fn test_enqueue_dequeue() {
        let mut queue = PriorityQueue::new(100);

        let msg = create_test_message(Priority::normal());
        queue.enqueue(msg).unwrap();

        assert_eq!(queue.len(), 1);
        assert!(!queue.is_empty());

        let _dequeued = queue.dequeue().unwrap();
        assert_eq!(queue.len(), 0);
        assert!(queue.is_empty());
    }

    #[test]
    fn test_priority_ordering() {
        let mut queue = PriorityQueue::new(100);

        // Enqueue in random order
        queue.enqueue(create_test_message(Priority::low())).unwrap();
        queue
            .enqueue(create_test_message(Priority::emergency()))
            .unwrap();
        queue
            .enqueue(create_test_message(Priority::normal()))
            .unwrap();

        assert_eq!(queue.len(), 3);

        // Should dequeue in priority order (Emergency first)
        let first = queue.dequeue().unwrap();
        assert_eq!(first.message.priority, Priority::emergency());

        let second = queue.dequeue().unwrap();
        assert_eq!(second.message.priority, Priority::normal());

        let third = queue.dequeue().unwrap();
        assert_eq!(third.message.priority, Priority::low());
    }

    #[test]
    fn test_queue_capacity() {
        let mut queue = PriorityQueue::new(2);

        // Fill queue
        queue
            .enqueue(create_test_message(Priority::normal()))
            .unwrap();
        queue
            .enqueue(create_test_message(Priority::normal()))
            .unwrap();

        // Should fail (queue full)
        let result = queue.enqueue(create_test_message(Priority::normal()));
        assert!(result.is_err());
    }

    #[test]
    fn test_peek() {
        let mut queue = PriorityQueue::new(100);

        assert!(queue.peek().is_none());

        queue
            .enqueue(create_test_message(Priority::high()))
            .unwrap();

        let peeked = queue.peek().unwrap();
        assert_eq!(peeked.message.priority, Priority::high());

        // Queue should still have the message
        assert_eq!(queue.len(), 1);
    }

    #[test]
    fn test_stats() {
        let mut queue = PriorityQueue::new(100);

        queue
            .enqueue(create_test_message(Priority::emergency()))
            .unwrap();
        queue
            .enqueue(create_test_message(Priority::emergency()))
            .unwrap();
        queue
            .enqueue(create_test_message(Priority::normal()))
            .unwrap();

        let stats = queue.stats();
        assert_eq!(stats.emergency, 2); // emergency is 224-255
        assert_eq!(stats.normal, 1);
        assert_eq!(stats.total, 3);
    }

    #[test]
    fn test_clear() {
        let mut queue = PriorityQueue::new(100);

        queue
            .enqueue(create_test_message(Priority::normal()))
            .unwrap();
        queue
            .enqueue(create_test_message(Priority::high()))
            .unwrap();

        assert_eq!(queue.len(), 2);

        queue.clear();
        assert_eq!(queue.len(), 0);
        assert!(queue.is_empty());
    }
}
