# MyriadMesh Core Repository Roadmap

**Status:** 🚀 START HERE - Critical Path Repository
**Last Updated:** 2025-12-07
**Priority:** #1 of 5 repositories - Complete this first
**Target:** Complete DHT and routing implementations enabling all other repos

---

## Why Complete Core First?

1. **Every other repository is blocked by this one**
   - Node team needs DHT for bootstrap
   - Server team needs Router for message transmission
   - Protocol refinements depend on implementation feedback

2. **Highest technical risk - tackle early**
   - Kademlia DHT is the most complex component
   - Better to discover issues now than later

3. **Foundation is solid**
   - ✅ Cryptographic primitives complete (libsodium bindings)
   - ✅ Security hardening done (all critical/high issues fixed)
   - ✅ Data structures in place (k-buckets, routing table)

---

## Current State Assessment

### What's Complete ✅
- `myriadmesh-crypto/` - Ed25519 signing, X25519 key exchange, XSalsa20-Poly1305 encryption
- `myriadmesh-dht/src/kbucket.rs` - K-bucket data structure
- `myriadmesh-dht/src/routing_table.rs` - Routing table with distance metrics
- `myriadmesh-dht/src/dht.rs` - DHT node structure and basic operations
- `myriadmesh-routing/src/router.rs` - Router skeleton with strategy selection
- `myriadmesh-routing/src/adaptive.rs` - Adaptive routing strategy

### What's Missing (Critical) ❌
- `iterative_find_node()` - Cannot discover peers without this
- `iterative_find_value()` - Cannot retrieve stored data without this
- DHT RPC transport - Cannot communicate with other nodes
- Router-DHT integration - Cannot route messages to discovered peers

---

## Phase 1: DHT Query Implementation [CRITICAL]

**Estimated Effort:** 75-95 hours
**This is the #1 priority for the entire project**

### Task 1.1: iterative_find_node()

**File:** `myriadmesh-dht/src/iterative_lookup.rs`
**Effort:** 30-40 hours
**Status:** Not Started → START HERE

```rust
// What needs to be implemented:
pub struct IterativeLookup {
    target: NodeId,
    alpha: usize,        // Parallel queries (default 3)
    k: usize,            // Results to return (default 20)
    timeout: Duration,   // Per-query timeout (default 5s)
}

impl IterativeLookup {
    pub async fn find_node(&self, dht: &Dht) -> Result<Vec<NodeInfo>> {
        // 1. Get k-closest nodes from local routing table
        // 2. Query alpha nodes in parallel
        // 3. Merge results, sort by XOR distance
        // 4. Repeat with closer nodes until no improvement
        // 5. Return k-closest nodes found
    }
}
```

**Implementation Checklist:**
- [ ] Create `IterativeLookup` struct with configuration
- [ ] Implement XOR distance calculation between NodeIds
- [ ] Query local routing table for initial k-closest
- [ ] Parallel query dispatch (tokio::spawn for alpha queries)
- [ ] Query timeout handling (tokio::time::timeout)
- [ ] Result merging and deduplication
- [ ] Termination condition (no closer nodes found in round)
- [ ] Return sorted k-closest nodes

**Tests Required:**
- [ ] Unit: 5-node simulated lookup
- [ ] Unit: Timeout handling (slow nodes)
- [ ] Unit: Duplicate node filtering
- [ ] Unit: Distance sorting correctness

### Task 1.2: iterative_find_value()

**File:** `myriadmesh-dht/src/iterative_lookup.rs`
**Effort:** 25-35 hours
**Depends On:** Task 1.1 (shares infrastructure)

```rust
impl IterativeLookup {
    pub async fn find_value(&self, key: &[u8; 32], dht: &Dht) -> Result<Option<DhtValue>> {
        // 1. Check local cache first
        // 2. Query k-closest nodes to key
        // 3. If any node returns value:
        //    - Verify signature (prevent poisoning)
        //    - Cache locally
        //    - Return immediately
        // 4. If no value found, return None (with k-closest for caller)
    }
}
```

**Implementation Checklist:**
- [ ] Local cache lookup before network query
- [ ] Query nodes in order of distance to key
- [ ] Value signature verification (use myriadmesh-crypto)
- [ ] Publisher ID validation
- [ ] Timestamp freshness check
- [ ] Local caching with TTL
- [ ] LRU eviction for cache bounds

**Tests Required:**
- [ ] Unit: Find existing value
- [ ] Unit: Value not found → returns None
- [ ] Unit: Invalid signature rejected
- [ ] Unit: Cache hit skips network
- [ ] Unit: Expired value treated as not found

### Task 1.3: DHT RPC Transport

**File:** `myriadmesh-dht/src/rpc.rs` (create new)
**Effort:** 20-25 hours
**Depends On:** Tasks 1.1 and 1.2 (uses RPC layer)

```rust
pub struct DhtRpc {
    adapter: Box<dyn NetworkAdapter>,
    pending: HashMap<RequestId, oneshot::Sender<Response>>,
    timeout: Duration,
}

impl DhtRpc {
    pub async fn find_node(&self, target: &NodeId, peer: &NodeInfo) -> Result<Vec<NodeInfo>>
    pub async fn find_value(&self, key: &[u8; 32], peer: &NodeInfo) -> Result<FindValueResponse>
    pub async fn store(&self, key: &[u8; 32], value: &DhtValue, peer: &NodeInfo) -> Result<()>
}
```

**Implementation Checklist:**
- [ ] Request/response message serialization (use protocol wire format)
- [ ] Request ID generation and tracking
- [ ] Timeout and retry logic
- [ ] Response parsing and validation
- [ ] Error classification (transient vs permanent)
- [ ] Node reliability tracking (for routing decisions)

**Tests Required:**
- [ ] Unit: Message serialization roundtrip
- [ ] Unit: Timeout handling
- [ ] Unit: Malformed response handling
- [ ] Integration: Two-node exchange (with mock adapter)

---

## Phase 2: Router-DHT Integration

**Estimated Effort:** 40-50 hours
**Start after:** Phase 1 complete

### Task 2.1: Router Integration

**File:** `myriadmesh-routing/src/router.rs`
**Target Lines:** 395-456 (forward_message implementation)

```rust
impl Router {
    pub async fn forward_message(&self, msg: &Message) -> Result<DeliveryStatus> {
        // Line 395: DHT Integration
        let dest_info = self.dht.find_value(&msg.destination).await?;

        // Line 405: Path Selection
        let paths = self.find_paths_to(&dest_info)?;
        let best_path = self.adaptive.select_best_path(&paths);

        // Line 427: Adapter Selection
        let adapter = self.select_adapter_for_path(&best_path)?;

        // Line 439: Transmission
        let result = adapter.send(&msg.serialize()?).await;

        // Line 456: Error Handling
        match result {
            Ok(_) => Ok(DeliveryStatus::Sent),
            Err(e) => self.handle_send_failure(msg, e).await,
        }
    }
}
```

**Implementation Checklist:**
- [ ] DHT lookup for destination node
- [ ] Cache DHT results (5-minute TTL)
- [ ] Path discovery using DHT k-closest
- [ ] Adapter scoring and selection
- [ ] Transmission with result capture
- [ ] Exponential backoff on failure (1s, 2s, 4s, 8s, 16s)
- [ ] Offline cache fallback after N failures

**Tests Required:**
- [ ] Unit: DHT lookup integration
- [ ] Unit: Path selection algorithm
- [ ] Unit: Adapter failover
- [ ] Integration: End-to-end 3-node message routing

---

## Phase 3: Advanced Routing [Lower Priority]

**Estimated Effort:** 55-70 hours
**Can be deferred to after Node/Server work begins**

### Task 3.1: Multipath Routing
**File:** `myriadmesh-routing/src/multipath.rs`
**Effort:** 30-40 hours

- [ ] Parallel path discovery (maintain 2-3 routes)
- [ ] Load balancing across paths
- [ ] Path reliability tracking
- [ ] Automatic failover

### Task 3.2: Geographic Routing
**File:** `myriadmesh-routing/src/geographic.rs`
**Effort:** 20-25 hours

- [ ] Greedy forwarding toward coordinates
- [ ] Perimeter routing around holes
- [ ] Integration with DHT for coordinate storage

### Task 3.3: Security Hardening (Medium Issues)
**Effort:** 25-35 hours

- [ ] M5: Blacklist mechanism for malicious nodes
- [ ] M7: Input validation across all modules
- [ ] M8: Adapter authentication

---

## Dependency Graph

```
myriadmesh-core (YOU ARE HERE)
    │
    ├── Provides to myriadmesh-node:
    │   • DHT queries for bootstrap
    │   • Router for message handling
    │
    ├── Provides to myriadmesh-server:
    │   • Router for API message sending
    │   • DHT for status APIs
    │
    └── Provides to myriadmesh-clients:
        • Crypto libs for mobile FFI
```

**Your work unblocks:**
- Node team: Once DHT works, they can implement node.start()
- Server team: Once Router works, they can implement /api/messages/send
- Protocol team: Your implementation informs spec refinements

---

## Work Summary

| Task | Effort | Priority | Status |
|------|--------|----------|--------|
| iterative_find_node() | 30-40h | P0 CRITICAL | Not Started |
| iterative_find_value() | 25-35h | P0 CRITICAL | Not Started |
| DHT RPC Transport | 20-25h | P0 CRITICAL | Not Started |
| Router-DHT Integration | 40-50h | P0 CRITICAL | Blocked by above |
| Multipath Routing | 30-40h | P1 | Defer |
| Geographic Routing | 20-25h | P2 | Defer |
| Security Hardening | 25-35h | P1 | Defer |

**Critical Path Total:** ~115-150 hours
**With Lower Priority:** ~190-250 hours

---

## Getting Started

### Step 1: Set up development environment
```bash
cd myriadmesh-core
cargo build
cargo test
```

### Step 2: Create iterative_lookup.rs
```bash
touch crates/myriadmesh-dht/src/iterative_lookup.rs
# Add to crates/myriadmesh-dht/src/lib.rs: pub mod iterative_lookup;
```

### Step 3: Start with find_node()
Focus on the simplest case first:
1. Local routing table query
2. Single remote query
3. Then add parallelism and iteration

### Step 4: Test as you go
```bash
cargo test -p myriadmesh-dht
```

---

## Success Criteria

### Phase 1 Complete When:
- [ ] Can locate any node in a 5+ node test network
- [ ] Can retrieve stored DHT values with signature verification
- [ ] DHT RPC messages work with mock adapter
- [ ] >90% test coverage on new code

### Phase 2 Complete When:
- [ ] Messages route successfully through 3-node network
- [ ] Adapter failover works (test by killing adapter)
- [ ] Offline cache stores messages for unreachable destinations

### Ready for Node Team When:
- [ ] DHT.find_node() works reliably
- [ ] Router.forward_message() handles basic case
- [ ] API is documented with examples

---

## Files to Create/Modify

**Create:**
- `crates/myriadmesh-dht/src/iterative_lookup.rs`
- `crates/myriadmesh-dht/src/rpc.rs`
- `crates/myriadmesh-dht/src/cache.rs`

**Modify:**
- `crates/myriadmesh-dht/src/lib.rs` - Add new modules
- `crates/myriadmesh-dht/src/dht.rs` - Integrate iterative lookup
- `crates/myriadmesh-routing/src/router.rs` - DHT integration

---

## Notes

- **Don't over-engineer** - Get basic find_node() working first
- **Test with mocks** - Don't need real network for unit tests
- **Document as you go** - Other repos will consume these APIs
- **Ask questions** - Protocol team can clarify wire format

---

**Owner:** Core Developer
**Next Milestone:** iterative_find_node() working
**Review:** When Phase 1 tasks complete
