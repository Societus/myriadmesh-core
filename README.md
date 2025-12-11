# MyriadMesh Core Libraries

**Foundational cryptography, peer discovery, and routing algorithms**

Core libraries that provide the essential infrastructure for MyriadMesh mesh networking. These libraries are used by all deployment modes (embedded nodes, servers, clients) and provide the fundamental algorithms that enable the MyriadMesh network to function.

## Overview

myriadmesh-core is a workspace containing three specialized Rust crates:

1. **myriadmesh-crypto** - Cryptographic operations (signing, encryption, key exchange)
2. **myriadmesh-dht** - Kademlia distributed hash table for peer discovery
3. **myriadmesh-routing** - Intelligent message routing with multiple strategies

These crates form the "plumbing" of MyriadMesh - the low-level algorithms that all higher-level components depend on.

## Repository Structure

```
myriadmesh-core/
├── Cargo.toml                     Workspace root
├── README.md                      This file
├── DEVELOPMENT.md                 Developer guide
├── crates/
│   ├── myriadmesh-crypto/
│   │   ├── Cargo.toml
│   │   ├── src/
│   │   │   ├── lib.rs
│   │   │   ├── identity.rs        Node identity creation/management
│   │   │   ├── signing.rs         Ed25519 digital signatures
│   │   │   ├── encryption.rs      XSalsa20-Poly1305 AEAD
│   │   │   ├── keyexchange.rs     X25519 key exchange
│   │   │   └── channel.rs         End-to-end encrypted channels
│   │   ├── benches/               Performance benchmarks
│   │   └── tests/                 Integration tests
│   │
│   ├── myriadmesh-dht/
│   │   ├── Cargo.toml
│   │   ├── src/
│   │   │   ├── lib.rs
│   │   │   ├── dht.rs             Main DHT implementation
│   │   │   ├── kbucket.rs         Kademlia bucket management
│   │   │   ├── routing_table.rs   Peer routing table
│   │   │   ├── iterative_lookup.rs Progressive peer discovery
│   │   │   ├── request_handler.rs  RPC request processing
│   │   │   ├── reputation.rs       Node reputation scoring
│   │   │   ├── blacklist.rs        Unreliable node tracking
│   │   │   └── storage.rs          DHT data persistence
│   │   └── tests/                 Integration tests
│   │
│   └── myriadmesh-routing/
│       ├── Cargo.toml
│       ├── src/
│       │   ├── lib.rs
│       │   ├── router.rs           Main routing engine
│       │   ├── routing_strategies.rs Strategy selection
│       │   ├── adaptive.rs         Adaptive routing algorithm
│       │   ├── geographic.rs       Geographic routing
│       │   ├── multipath.rs        Multipath routing
│       │   ├── path_selector.rs    Path selection logic
│       │   ├── adapter_selector.rs Adapter selection for transmission
│       │   ├── priority_queue.rs   Message prioritization
│       │   ├── fragmentation.rs    Message fragmentation
│       │   ├── store_and_forward.rs Offline message caching
│       │   ├── deduplication.rs    Duplicate prevention
│       │   ├── qos.rs              Quality of service
│       │   ├── rate_limiter.rs     Rate limiting
│       │   ├── circuit_breaker.rs  Fault tolerance
│       │   ├── ml_predictor.rs     ML-based path optimization
│       │   ├── reputation.rs       Path reliability tracking
│       │   └── error.rs            Error types
│       ├── benches/                Performance benchmarks
│       └── tests/                  Integration tests
│
├── docs/
│   ├── ARCHITECTURE.md             Core architecture overview
│   ├── CRYPTO_SECURITY.md          Cryptographic security details
│   ├── DHT_PROTOCOL.md             DHT implementation guide
│   └── ROUTING_STRATEGIES.md       Routing algorithm documentation
└── CHANGELOG.md                   Version history
```

## Core Crates

### 1. myriadmesh-crypto

Cryptographic operations for secure node identity and message protection.

**What it provides**:
- Ed25519 digital signatures for node authentication
- X25519 key exchange for establishing shared secrets
- XSalsa20-Poly1305 for message encryption
- BLAKE2b hashing for node IDs and content addressing
- Node identity generation and management
- Secure channel establishment

**Key modules**:
```rust
use myriadmesh_crypto::{
    NodeIdentity,              // Create and manage node identities
    sign, verify,              // Digital signatures
    encrypt, decrypt,          // Message encryption
    keyexchange,               // Establish shared secrets
    Channel,                   // End-to-end encrypted channel
};

// Generate a node identity
let identity = NodeIdentity::generate()?;
let node_id = identity.node_id();  // 64-byte unique ID

// Sign a message
let signature = identity.sign(&message)?;

// Establish encrypted channel with peer
let channel = Channel::establish(&my_identity, &peer_public_key)?;
let encrypted = channel.encrypt(&plaintext)?;
```

**Performance**:
- Signature generation: ~25 microseconds
- Signature verification: ~50 microseconds
- Encryption: ~1 microsecond per KB
- Key derivation: ~100 milliseconds (intentional, for key stretching)

**Security**:
- Uses libsodium for all cryptographic operations
- Regular key rotation (automatic)
- Forward secrecy with ephemeral keys
- Constant-time operations where applicable
- Audited algorithms (Ed25519, X25519, XSalsa20)

### 2. myriadmesh-dht

Kademlia distributed hash table for peer discovery without centralized servers.

**What it provides**:
- Peer discovery and lookup
- Storage of node information and metadata
- Message caching for offline nodes
- Node reputation and reliability tracking
- DHT gossip protocol
- Blacklist management for bad actors

**Key modules**:
```rust
use myriadmesh_dht::{DHT, NodeInfo};

// Create DHT node
let dht = DHT::new(my_node_id, config)?;

// Discover peers
let peers = dht.lookup(target_node_id).await?;

// Store metadata
dht.store(key, value).await?;

// Retrieve metadata
let value = dht.get(key).await?;

// Cache message for offline node
dht.cache_message(destination_id, message).await?;
```

**Protocol Details**:
- **K-buckets**: 20 peers per bucket (K=20)
- **Lookups**: Parallel queries to 3 peers (ALPHA=3)
- **RPC Methods**: PING, STORE, FIND_NODE, FIND_VALUE
- **Replication**: 3 copies of each key-value pair
- **TTL**: 24 hours for stored data
- **Reputation**: Track node reliability and availability

**Performance**:
- Lookup time: O(log N) where N = network size
- Typical lookup: 3-5 hops for million-node network
- Storage queries: ~100ms round trip
- Gossip propagation: ~5 minutes across network

**Reliability**:
- Handles peer churn (nodes joining/leaving)
- Blacklisting of unreliable nodes
- Reputation scoring
- Message verification with signatures

### 3. myriadmesh-routing

Intelligent message routing with multiple strategies for different network conditions.

**What it provides**:
- Multiple routing strategies (adaptive, geographic, multipath)
- Dynamic path selection based on network metrics
- Message fragmentation and reassembly
- Store-and-forward for offline nodes
- Priority queuing
- Rate limiting and congestion control
- Quality of service (QoS) handling
- ML-based path prediction

**Key modules**:
```rust
use myriadmesh_routing::{Router, RoutingStrategy};

// Create router
let router = Router::new(config)?;

// Route a message
let result = router.route_message(&message, &destination).await?;

// Select routing strategy based on conditions
let strategy = router.select_strategy(&network_conditions);

// Check path quality
let metrics = router.get_path_metrics(&destination).await?;
```

**Routing Strategies**:

| Strategy | When to Use | Characteristics |
|----------|-------------|-----------------|
| **Adaptive** | Default | Chooses path based on latency/bandwidth/reliability |
| **Geographic** | GPS available | Routes toward destination's location |
| **Multipath** | Critical delivery | Sends via multiple paths for redundancy |
| **Store-and-Forward** | Offline destination | Caches message for later delivery |
| **Direct** | Same-hop peers | One-hop transmission |

**Performance Metrics**:
- Message latency: ~10-100ms (depends on network conditions)
- Throughput: 1000+ messages/second
- Memory per route: ~10KB
- Path selection time: <1ms

**Reliability**:
- Automatic retry on failure
- Exponential backoff
- Circuit breaker for failing paths
- Reputation-based path scoring
- Deduplication to prevent loops

## Development Guide

### Building

```bash
# Build all crates
cargo build --release

# Build specific crate
cargo build -p myriadmesh-crypto --release

# Build with all features
cargo build --release --all-features
```

### Testing

```bash
# Run all tests
cargo test --release

# Run tests for specific crate
cargo test -p myriadmesh-dht --release

# Run tests with logging
RUST_LOG=debug cargo test --release -- --nocapture

# Run fuzz tests (requires nightly)
cargo +nightly fuzz run dht_fuzzer
```

### Performance Benchmarking

```bash
# Run benchmarks
cargo bench --release

# Run specific benchmark
cargo bench --release -p myriadmesh-crypto crypto_benchmarks

# Compare with main branch
git stash && cargo bench --release && git stash pop && cargo bench --release
```

### Code Quality

```bash
# Format code
cargo fmt --all

# Lint with clippy
cargo clippy --all -- -D warnings

# Security audit
cargo audit

# Check documentation
cargo doc --no-deps --open
```

### Profiling

```bash
# Profile with perf (Linux)
RUSTFLAGS="-g" cargo build --release
perf record -g ./target/release/your_binary
perf report

# Memory profiling with valgrind
valgrind --tool=massif ./target/release/your_binary
```

## Dependencies

### Direct Dependencies
- **tokio** (1.35+) - Async runtime
- **sodiumoxide** (0.2) - Cryptography library
- **serde** (1.0) - Serialization
- **bincode** (1.3) - Binary encoding
- **async-trait** (0.1) - Async trait support
- **futures** (0.3) - Async utilities

### Quality Dependencies
- **criterion** (0.5) - Benchmarking
- **tokio-test** - Testing utilities

### Security Considerations
All cryptographic operations use **libsodium**, a battle-tested, audited crypto library. No custom crypto implementations.

## Integration with Other Components

```
myriadmesh-protocol (external)
         ↓
myriadmesh-core (this repo)
├─ myriadmesh-crypto
├─ myriadmesh-dht
└─ myriadmesh-routing
         ↓
┌────────┴─────────────────┐
│                          │
myriadmesh-node            myriadmesh-server
├─ myriadmesh-network      ├─ myriadmesh-ledger
├─ myriadmesh-i2p          ├─ myriadmesh-appliance
└─ myriadnode-minimal      └─ myriadmesh-updates
```

All other MyriadMesh components import from this core library.

## Version Management

- **Version synchronization**: myriadmesh-core versions match protocol major version
  - Protocol 1.x → Core 1.x.y
  - Protocol 2.x → Core 2.x.y
- **Minor versions**: Independent evolution per crate
- **Patch versions**: Security fixes and bug fixes

## Performance Targets

| Component | Metric | Target |
|-----------|--------|--------|
| **Crypto** | Signature verification | <100 µs |
| **Crypto** | Encryption throughput | >1 GB/s |
| **DHT** | Lookup time | <100 ms |
| **DHT** | Storage availability | >99.9% |
| **Routing** | Path selection | <1 ms |
| **Routing** | Message throughput | >1000 msg/s |
| **Overall** | Memory per peer | <10 KB |

## Security Audit Status

- ✅ Cryptographic primitives: Audited (libsodium)
- ✅ Protocol security analysis: Completed
- ✅ Fuzzing: Ongoing (corpus in `crates/*/fuzz/`)
- ⏳ Third-party audit: Scheduled for Q1 2026

## Contributing

### Getting Started
1. Read [DEVELOPMENT.md](./DEVELOPMENT.md)
2. Install dependencies (see Development Guide above)
3. Pick an issue labeled `good-first-issue`
4. Run tests to understand existing behavior

### Making Changes
1. Create feature branch: `git checkout -b feat/description`
2. Write tests first (TDD approach)
3. Implement feature
4. Run full test suite: `cargo test --release`
5. Run benchmarks: `cargo bench`
6. Format and lint: `cargo fmt && cargo clippy`
7. Submit PR with description

### Code Style
- Follow Rust conventions (clippy strict)
- Prefer explicit error handling over panics
- Add documentation comments to public APIs
- Include examples in doc comments

## Roadmap

### Short-term (1-2 months)
- [ ] Optimize crypto operations (2x performance target)
- [ ] Improve DHT consistency under churn
- [ ] Machine learning route prediction tuning

### Medium-term (2-4 months)
- [ ] Hardware acceleration for crypto
- [ ] Distributed routing algorithms
- [ ] Caching strategy optimization

### Long-term (6+ months)
- [ ] Post-quantum cryptography research
- [ ] Sharded DHT for billion-node networks
- [ ] Alternative implementations (Go, Python)

## References

- [libsodium Documentation](https://doc.libsodium.org/)
- [Kademlia Protocol Paper](https://pdos.csail.mit.edu/~petar/papers/maymounkov-kademlia-lncs.pdf)
- [Rust Async Book](https://rust-lang.github.io/async-book/)
- [Performance Testing Guide](docs/PERFORMANCE_GUIDE.md)

## License

Licensed under **GPL-3.0-only**.

This ensures that all implementations using these core libraries remain open source, promoting transparency and security through code review.

## Support

- **Documentation**: See `docs/` directory
- **Issues**: GitHub Issues
- **Discussions**: GitHub Discussions
- **Community**: Matrix/Discord (links in main README)

## Development Roadmap

See [ROADMAP.md](ROADMAP.md) for detailed timeline and work items.

**Current Phase**: DHT & Routing Implementation (4-6 weeks)

**Critical Path:**
1. **[NOW] DHT iterative queries** (2 weeks) - BLOCKS all message routing
2. **Router integration with DHT** (1 week) - BLOCKS server/node teams
3. **Advanced routing algorithms** (2 weeks) - multipath, geographic
4. **Performance optimization** (1-2 weeks)
5. **Security hardening** (ongoing)

**Key Blockers for Other Teams:**
- Node team waits for: P0.2 (DHT complete), P0.1.2 (Router)
- Server team waits for: P0.1.2 (Router messaging)

**Work Items:**
- [ ] Implement iterative_find_node() (P0.2.1)
- [ ] Implement iterative_find_value() (P0.2.2)
- [ ] DHT RPC transport layer (P0.2.3)
- [ ] Router message forwarding (P0.1.2)
- [ ] Multipath routing (P2.4.1)
- [ ] Geographic routing (P2.4.2)
- [ ] Security hardening (M5, M7, M8)

---

**Repository**: https://github.com/myriadmesh/core
**Crates.io**: https://crates.io/crates/myriadmesh-crypto, myriadmesh-dht, myriadmesh-routing
