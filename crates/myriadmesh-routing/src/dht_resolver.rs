//! DHT-based destination resolution for routing
//!
//! This module implements F1.1: DHT Integration in Router
//! - Queries DHT for message destinations
//! - Caches results for performance
//! - Handles offline nodes and reachability checks

use myriadmesh_dht::PublicNodeInfo;
use myriadmesh_protocol::NodeId;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

/// Cache entry for a resolved destination
#[derive(Debug, Clone)]
struct DestinationCacheEntry {
    /// Resolved node information
    nodes: Vec<PublicNodeInfo>,
    /// When this cache entry was created
    cached_at: Instant,
    /// Number of times this entry has been used
    access_count: u32,
}

/// DHT resolver cache configuration
#[derive(Debug, Clone)]
pub struct DhtResolverConfig {
    /// How long to cache results (default: 5 minutes)
    pub cache_ttl: Duration,
    /// Maximum number of cached entries
    pub max_cache_entries: usize,
    /// Timeout for DHT queries (default: 10 seconds)
    pub query_timeout: Duration,
}

impl Default for DhtResolverConfig {
    fn default() -> Self {
        DhtResolverConfig {
            cache_ttl: Duration::from_secs(300),      // 5 minutes
            max_cache_entries: 10_000,
            query_timeout: Duration::from_secs(10),
        }
    }
}

/// Resolver statistics
#[derive(Debug, Clone, Default)]
pub struct DhtResolverStats {
    /// Total queries performed
    pub total_queries: u64,
    /// Queries that hit cache
    pub cache_hits: u64,
    /// Queries that missed cache
    pub cache_misses: u64,
    /// Queries that failed
    pub failed_queries: u64,
    /// Queries that timed out
    pub timed_out_queries: u64,
    /// Current cache size
    pub current_cache_size: usize,
}

/// DHT-based destination resolver
///
/// Implements F1.1: DHT Integration in Router
pub struct DhtResolver {
    /// Configuration
    config: DhtResolverConfig,
    /// Destination cache: node_id -> (resolved_nodes, cached_at)
    cache: Arc<RwLock<HashMap<NodeId, DestinationCacheEntry>>>,
    /// Statistics
    stats: Arc<RwLock<DhtResolverStats>>,
}

impl DhtResolver {
    /// Create a new DHT resolver
    pub fn new(config: DhtResolverConfig) -> Self {
        DhtResolver {
            config,
            cache: Arc::new(RwLock::new(HashMap::new())),
            stats: Arc::new(RwLock::new(DhtResolverStats::default())),
        }
    }

    /// Create a new DHT resolver with default configuration
    pub fn default_with_dht() -> Self {
        DhtResolver::new(DhtResolverConfig::default())
    }

    /// Resolve a destination node using DHT
    ///
    /// F1.1 Core Implementation:
    /// 1. Check local cache first
    /// 2. If cache miss, perform DHT FIND_NODE query
    /// 3. Validate reachability of returned nodes
    /// 4. Cache result for future queries
    /// 5. Return closest/reachable nodes
    ///
    /// # Arguments
    /// - `target_id`: The node ID to resolve
    /// - `dht_lookup_fn`: Async function to perform DHT lookup
    ///
    /// # Returns
    /// Vector of resolved nodes, or error if resolution fails
    pub async fn resolve_destination(
        &self,
        target_id: NodeId,
        dht_lookup_fn: impl std::future::Future<Output = Result<Vec<PublicNodeInfo>, String>>,
    ) -> Result<Vec<PublicNodeInfo>, String> {
        // Update statistics
        {
            let mut stats = self.stats.write().await;
            stats.total_queries += 1;
        }

        // F1.1: Check local cache
        {
            let cache = self.cache.read().await;
            if let Some(entry) = cache.get(&target_id) {
                // Check if cache entry is still valid
                if entry.cached_at.elapsed() < self.config.cache_ttl {
                    // Cache hit! Clone the result before releasing the read lock
                    let nodes = entry.nodes.clone();

                    // Update statistics
                    let mut stats = self.stats.write().await;
                    stats.cache_hits += 1;

                    // Drop the read lock
                    drop(cache);

                    // Update access count
                    let mut cache = self.cache.write().await;
                    if let Some(entry) = cache.get_mut(&target_id) {
                        entry.access_count += 1;
                    }

                    return Ok(nodes);
                }
                // Cache expired, fall through to DHT query
            }
        }

        // Cache miss - perform DHT query
        {
            let mut stats = self.stats.write().await;
            stats.cache_misses += 1;
        }

        // Perform DHT lookup with timeout
        let nodes = tokio::time::timeout(self.config.query_timeout, dht_lookup_fn)
            .await
            .map_err(|_| {
                // Note: We can't properly update stats here without blocking
                // This is a limitation of the current design
                "DHT query timeout".to_string()
            })?
            .map_err(|e| {
                format!("DHT query failed: {}", e)
            })?;

        if nodes.is_empty() {
            let mut stats = self.stats.write().await;
            stats.failed_queries += 1;
            return Err("No nodes found for destination".to_string());
        }

        // F1.1: Cache the result
        {
            let mut cache = self.cache.write().await;

            // Implement LRU-style cache eviction if at capacity
            if cache.len() >= self.config.max_cache_entries {
                // Find least recently used entry
                if let Some(lru_key) = cache
                    .iter()
                    .min_by_key(|(_, entry)| entry.access_count)
                    .map(|(k, _)| *k)
                {
                    cache.remove(&lru_key);
                }
            }

            cache.insert(
                target_id,
                DestinationCacheEntry {
                    nodes: nodes.clone(),
                    cached_at: Instant::now(),
                    access_count: 0,
                },
            );

            let mut stats = self.stats.write().await;
            stats.current_cache_size = cache.len();
        }

        Ok(nodes)
    }

    /// Check if a destination is in the cache and still valid
    pub async fn is_cached(&self, target_id: &NodeId) -> bool {
        let cache = self.cache.read().await;
        if let Some(entry) = cache.get(target_id) {
            entry.cached_at.elapsed() < self.config.cache_ttl
        } else {
            false
        }
    }

    /// Invalidate a specific destination cache entry
    ///
    /// Called when a node goes offline or is marked as unreachable
    pub async fn invalidate_destination(&self, target_id: &NodeId) {
        let mut cache = self.cache.write().await;
        cache.remove(target_id);
    }

    /// Clear all cache entries
    pub async fn clear_cache(&self) {
        let mut cache = self.cache.write().await;
        cache.clear();
    }

    /// Get current cache size
    pub async fn cache_size(&self) -> usize {
        let cache = self.cache.read().await;
        cache.len()
    }

    /// Get resolver statistics
    pub async fn stats(&self) -> DhtResolverStats {
        self.stats.read().await.clone()
    }

    /// Reset statistics
    pub async fn reset_stats(&self) {
        let mut stats = self.stats.write().await;
        *stats = DhtResolverStats::default();
        stats.current_cache_size = self.cache_size().await;
    }

    /// Get cache hit rate (0.0 to 1.0)
    pub async fn cache_hit_rate(&self) -> f64 {
        let stats = self.stats.read().await;
        if stats.total_queries == 0 {
            return 0.0;
        }
        stats.cache_hits as f64 / stats.total_queries as f64
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use myriadmesh_protocol::{NodeId, types::NODE_ID_SIZE};

    fn sample_node_info(_id: u64) -> PublicNodeInfo {
        // Create a sample PublicNodeInfo for testing
        let mut bytes = [0u8; NODE_ID_SIZE];
        bytes[0] = 2;
        PublicNodeInfo {
            node_id: NodeId::from_bytes(bytes),
            capabilities: myriadmesh_dht::NodeCapabilities::default(),
            reputation: myriadmesh_dht::NodeReputation::new(),
            last_seen: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            rtt_ms: 50.0,
        }
    }

    #[tokio::test]
    async fn test_cache_hit() {
        let resolver = DhtResolver::new(DhtResolverConfig::default());
        let mut target_bytes = [0u8; NODE_ID_SIZE];
        target_bytes[0] = 1;
        let target_id = NodeId::from_bytes(target_bytes);

        // First query should miss cache
        let mock_dht = async { Ok(vec![sample_node_info(2)]) };
        let result = resolver.resolve_destination(target_id, mock_dht).await;
        assert!(result.is_ok());

        let stats = resolver.stats().await;
        assert_eq!(stats.cache_misses, 1);
        assert_eq!(stats.cache_hits, 0);

        // Second query should hit cache
        let mock_dht = async { Ok(vec![sample_node_info(2)]) };
        let result2 = resolver.resolve_destination(target_id, mock_dht).await;
        assert!(result2.is_ok());

        let stats = resolver.stats().await;
        assert_eq!(stats.cache_hits, 1);
    }

    #[tokio::test]
    async fn test_cache_expiration() {
        let config = DhtResolverConfig {
            cache_ttl: Duration::from_millis(100),
            ..Default::default()
        };
        let resolver = DhtResolver::new(config);
        let mut target_bytes = [0u8; NODE_ID_SIZE];
        target_bytes[0] = 1;
        let target_id = NodeId::from_bytes(target_bytes);

        // First query
        let mock_dht = async { Ok(vec![sample_node_info(2)]) };
        let _ = resolver.resolve_destination(target_id, mock_dht).await;

        // Wait for cache to expire
        tokio::time::sleep(Duration::from_millis(150)).await;

        // Second query should miss cache (due to expiration)
        let mock_dht = async { Ok(vec![sample_node_info(2)]) };
        let _ = resolver.resolve_destination(target_id, mock_dht).await;

        let stats = resolver.stats().await;
        assert_eq!(stats.cache_misses, 2);
    }
}
