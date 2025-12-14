# LLM Development Guide - myriadmesh-core

**Quick reference for LLMs working on the myriadmesh-core repository**

---

## Repository Purpose

myriadmesh-core provides the foundational libraries and algorithms used by all other components of MyriadMesh:

1. **Cryptography** (`myriadmesh-crypto`)
   - Ed25519 digital signatures for message authentication
   - X25519 for encrypted key exchange
   - XSalsa20-Poly1305 AEAD encryption
   - Used by: All other repositories

2. **Distributed Hash Table** (`myriadmesh-dht`)
   - Kademlia DHT for decentralized peer discovery
   - Peer routing and reputation scoring
   - Used by: Servers, nodes, clients for peer discovery

3. **Routing & Consensus** (`myriadmesh-routing`)
   - Adaptive routing algorithms
   - Byzantine Fault Tolerant consensus
   - Relay scoring and selection
   - Failure detection
   - Used by: Servers and nodes for message routing

**Key Principle**: myriadmesh-core provides **reliable, tested, secure libraries** that are used across the entire system.

---

## Target Audience

**Primary Audience**: Developers and contributors

**User Types**:
- Contributors working on MyriadMesh internals
- Operators understanding how the network works
- Security researchers auditing the code
- Developers integrating with MyriadMesh

**Documentation Level**: Technical with code examples, assuming understanding of Rust and distributed systems

---

## Documentation Standards

### Language & Tone

- Assume knowledge of Rust
- Assume understanding of distributed systems concepts
- Include code examples liberally
- Explain design decisions
- Document trade-offs clearly
- Include performance characteristics

### Structure for API Documentation

1. **Overview** (What this does and why)
2. **Core Concepts** (Key ideas explained)
3. **API Reference** (Types and functions documented)
4. **Integration Patterns** (How to use in real code)
5. **Design Decisions** (Why this approach)
6. **Performance** (Time/space complexity, benchmarks)
7. **Examples** (Real usage patterns)
8. **Testing** (How to test your code using this)

### Code Examples

- Should be syntactically correct and compilable
- Include both happy path and error cases
- Show realistic usage patterns
- Include error handling
- Comment non-obvious parts
- Use actual API names from the codebase

### Formal Specifications (if protocol-related)

- Use precise mathematical notation
- Define all terms clearly
- State all invariants
- Provide test vectors
- Show state machines

---

## Code Organization

```
myriadmesh-core/
├── crates/
│   ├── myriadmesh-crypto/           Cryptographic operations
│   │   ├── src/
│   │   │   ├── lib.rs              Public API
│   │   │   ├── ed25519.rs          Ed25519 signing
│   │   │   ├── x25519.rs           Key exchange
│   │   │   ├── xsalsa20poly1305.rs AEAD encryption
│   │   │   └── error.rs            Error types
│   │   ├── tests/                  Comprehensive test suite
│   │   ├── benches/               Benchmarks
│   │   └── Cargo.toml
│   │
│   ├── myriadmesh-dht/             Kademlia DHT implementation
│   │   ├── src/
│   │   │   ├── lib.rs             Public API
│   │   │   ├── kademlia.rs        Core DHT
│   │   │   ├── routing_table.rs   Peer routing
│   │   │   ├── bucket.rs          k-buckets
│   │   │   └── scoring.rs         Reputation scoring
│   │   ├── tests/
│   │   ├── benches/
│   │   └── Cargo.toml
│   │
│   └── myriadmesh-routing/         Routing and consensus
│       ├── src/
│       │   ├── lib.rs             Public API
│       │   ├── algorithms/        Routing algorithms
│       │   ├── consensus/         Byzantine consensus
│       │   ├── scoring/           Relay scoring
│       │   └── failure_detection/ Failure detection
│       ├── tests/
│       ├── benches/
│       └── Cargo.toml
│
├── docs/                           Architecture documentation
│   ├── CRYPTO_DESIGN.md           Design rationale for crypto
│   ├── DHT_DESIGN.md              DHT implementation details
│   └── ROUTING_DESIGN.md          Routing algorithm design
│
└── examples/                       Usage examples
```

---

## Key Files to Know

- `README.md` - Core libraries overview
- `LLM_DEVELOPMENT_GUIDE.md` - This file
- `ROADMAP.md` - Planned enhancements
- `Cargo.toml` - Workspace manifest
- `Cargo.lock` - Dependency lock

---

## Common Development Tasks

### Adding a New Cryptographic Function

1. **Design the function**
   - What problem does it solve?
   - What are the security properties?
   - What are the performance characteristics?

2. **Implement in myriadmesh-crypto**
   - Follow existing code patterns
   - Add comprehensive error handling
   - Include detailed documentation
   - Document security properties

3. **Write comprehensive tests**
   - Unit tests for each component
   - Integration tests with other functions
   - Property-based tests for invariants
   - Test vectors from standards if available

4. **Benchmark performance**
   - Measure single operation performance
   - Test with realistic data sizes
   - Compare with alternatives if relevant

5. **Document thoroughly**
   - API documentation with examples
   - Design decision documentation
   - Security considerations
   - Performance characteristics

6. **Update dependent repos**
   - myriadmesh-server might use it
   - myriadmesh-node might use it
   - myriadmesh-clients might use it

### Improving Routing Algorithm

1. **Understand current algorithm**
   - Read existing code and docs
   - Understand performance characteristics
   - Identify bottlenecks

2. **Design improvement**
   - Mathematical formulation
   - Expected performance gain
   - Trade-offs vs current approach
   - Compatibility with existing code

3. **Implement algorithm**
   - Add to `myriadmesh-routing`
   - Follow existing code style
   - Include configuration options
   - Document assumptions

4. **Benchmark thoroughly**
   - Compare with previous algorithm
   - Test with various network topologies
   - Test with various load patterns
   - Measure CPU and memory impact

5. **Test extensively**
   - Unit tests
   - Integration with consensus
   - End-to-end with server and nodes
   - Property-based testing

6. **Document changes**
   - Update algorithm documentation
   - Document trade-offs
   - Update design decisions
   - Provide migration path if breaking

### Fixing a Security Issue

1. **Verify the issue**
   - Understand the vulnerability
   - Confirm impact scope
   - Test reproduction

2. **Develop fix**
   - Minimal changes only
   - Don't refactor unrelated code
   - Ensure backward compatibility if possible
   - Document the fix

3. **Test thoroughly**
   - Test the fix
   - Test edge cases
   - Test in dependent repos
   - Security review if needed

4. **Communicate fix**
   - Document in changelog
   - Update security advisories
   - Coordinate release if needed

---

## Testing Requirements

### Unit Tests (Comprehensive Coverage)

- Test each public function
- Test happy path and error cases
- Test edge cases and boundary conditions
- Test with property-based testing where applicable
- **Target**: 100% coverage of public APIs

```bash
# Run unit tests
cargo test --release

# Run specific test
cargo test crypto::ed25519 --release

# Run with output
cargo test --release -- --nocapture
```

### Integration Tests

- Test interaction between crates
- Test with realistic scenarios
- Test error propagation
- Test performance with realistic data

### Benchmarks

- Benchmark each major operation
- Compare before/after for changes
- Document performance characteristics

```bash
# Run benchmarks
cargo bench --release
```

### Test Coverage Goals

| Component | Coverage Target |
|-----------|-----------------|
| Public APIs | 100% |
| Error paths | 100% |
| Edge cases | 90%+ |
| Implementation details | 80%+ |

---

## Code Standards

### Rust Idioms

- Use idiomatic Rust
- Prefer Option/Result over null checks
- Use pattern matching
- Follow Rust naming conventions
- Use trait objects appropriately

### Error Handling

```rust
// Good: Custom error types with context
#[derive(Debug)]
pub enum CryptoError {
    InvalidSignature(String),
    InvalidKeySize { expected: usize, got: usize },
    EncryptionFailed(String),
}

impl std::fmt::Display for CryptoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidSignature(msg) => write!(f, "Invalid signature: {}", msg),
            Self::InvalidKeySize { expected, got } => {
                write!(f, "Invalid key size: expected {}, got {}", expected, got)
            }
            Self::EncryptionFailed(msg) => write!(f, "Encryption failed: {}", msg),
        }
    }
}
```

### Documentation

- Public functions must be documented
- Explain what, why, and how
- Include examples for complex functions
- Document error conditions
- Document performance characteristics

```rust
/// Verifies an Ed25519 signature.
///
/// This function validates that the given signature was created by the
/// corresponding private key for the given message.
///
/// # Arguments
///
/// * `message` - The message that was signed
/// * `signature` - The Ed25519 signature (64 bytes)
/// * `public_key` - The public key to verify against (32 bytes)
///
/// # Returns
///
/// - `Ok(true)` if signature is valid
/// - `Ok(false)` if signature is invalid
/// - `Err(CryptoError)` if there's an error during verification
///
/// # Example
///
/// ```rust
/// let signature = verify_signature(message, sig, pubkey)?;
/// assert!(signature);
/// ```
///
/// # Performance
///
/// - Time: O(1) - constant time to prevent timing attacks
/// - Space: O(1)
pub fn verify_signature(message: &[u8], signature: &[u8], public_key: &[u8]) -> Result<bool> {
    // Implementation
}
```

### Testing Code

- Every public function should have tests
- Test both success and failure cases
- Use descriptive test names
- Keep tests focused and small

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_signature_verification() {
        let keypair = generate_keypair();
        let message = b"test message";
        let signature = sign(message, &keypair).unwrap();

        assert!(verify_signature(message, &signature, &keypair.public).unwrap());
    }

    #[test]
    fn test_invalid_signature_fails_verification() {
        let keypair = generate_keypair();
        let message = b"test message";
        let mut signature = sign(message, &keypair).unwrap();

        // Corrupt signature
        signature[0] ^= 0xFF;

        assert!(!verify_signature(message, &signature, &keypair.public).unwrap());
    }

    #[test]
    fn test_signature_fails_for_modified_message() {
        let keypair = generate_keypair();
        let message = b"test message";
        let signature = sign(message, &keypair).unwrap();
        let modified_message = b"modified message";

        assert!(!verify_signature(modified_message, &signature, &keypair.public).unwrap());
    }
}
```

---

## Performance Considerations

### Cryptographic Operations

- Document performance per operation
- Measure with realistic data sizes
- Consider CPU vs security trade-offs
- Avoid timing attacks (constant-time where needed)
- Profile memory usage

### DHT Operations

- Document lookup performance (O(log n) expected)
- Measure routing table updates
- Profile peer discovery performance
- Test with various network sizes

### Routing Algorithms

- Measure path computation time
- Profile memory for routing tables
- Document consensus performance
- Test with various topologies

---

## Integration with Other Repositories

### How myriadmesh-core is Used

```
myriadmesh-server:
  └─ Uses: crypto (signing), dht (discovery), routing (message routing)

myriadmesh-node:
  └─ Uses: crypto (signing), dht (discovery), routing (message routing)

myriadmesh-clients:
  └─ Uses: crypto (signing)

myriadmesh-protocol:
  └─ Defines: Specifications that core implements
```

### Cross-Repository Dependencies

When you change an API in myriadmesh-core:

1. **Identify all users**: Check CROSS_REPO_DEPENDENCIES.md
2. **Update all users**: Must update server, node, clients
3. **Test everywhere**: Run tests in all affected repos
4. **Deprecate gracefully**: If breaking change, provide migration path

---

## Common Pitfalls

### Pitfall #1: Ignoring Timing Attacks

❌ Using simple comparison for cryptographic operations
✅ Using constant-time comparison for all crypto operations

### Pitfall #2: Insufficient Testing

❌ Testing only happy path
✅ Testing happy path, error cases, edge cases, and edge values

### Pitfall #3: Not Documenting Design Decisions

❌ Code that works but why it works is unclear
✅ Code with clear documentation of design decisions and trade-offs

### Pitfall #4: Performance Regressions

❌ Making changes without measuring performance impact
✅ Measuring before and after for all performance-critical code

### Pitfall #5: Breaking Changes Without Migration Path

❌ Changing API and forcing all users to update
✅ Deprecating old API, providing new API, updating users gradually

---

## Quick Commands

```bash
# Build core libraries
cargo build --release

# Run all tests
cargo test --release

# Run specific test
cargo test crypto::ed25519 --release

# Test with logging
RUST_LOG=debug cargo test --release -- --nocapture

# Code quality checks
cargo clippy --all-targets --release
cargo fmt -- --check

# Performance benchmarks
cargo bench --release

# Generate documentation
cargo doc --no-deps --open
```

---

## Documentation Templates

Use this template for core library documentation:

**DEVELOPER_DOCUMENTATION_TEMPLATE.md**
- Location: `/root/Projects/myriadmesh-split-workspace/docs/templates/`
- Include: API reference, examples, performance, design decisions
- Code examples must be compilable
- Include test vectors for crypto

---

## File Locations

| Type | Location |
|------|----------|
| This guide | `LLM_DEVELOPMENT_GUIDE.md` |
| Core code | `crates/myriad**/src/` |
| Tests | `crates/myriad**/tests/` |
| Docs | `docs/` |
| Templates | `/root/Projects/myriadmesh-split-workspace/docs/templates/` |
| Cross-repo info | `/root/Projects/myriadmesh-split-workspace/CROSS_REPO_DEPENDENCIES.md` |

---

## Key Principles

1. **Correctness First**
   - Security cannot be compromised
   - Comprehensive testing is mandatory
   - Invariants must be maintained

2. **Performance Matters**
   - Document performance characteristics
   - Benchmark before and after changes
   - Optimize critical paths

3. **Compatibility**
   - Maintain backward compatibility when possible
   - Deprecate gracefully before breaking
   - Update all users of changed APIs

4. **Testing Is Essential**
   - Every line of code should be tested
   - Test error cases not just happy path
   - Use property-based testing for invariants

5. **Documentation Is Code**
   - Every public API must be documented
   - Examples must actually work
   - Design decisions must be recorded

---

## Help and Resources

- **Workspace overview**: `/root/Projects/myriadmesh-split-workspace/README.md`
- **Repository structure**: `/root/Projects/myriadmesh-split-workspace/REPOSITORY_MAP.md`
- **Dependencies**: `/root/Projects/myriadmesh-split-workspace/CROSS_REPO_DEPENDENCIES.md`
- **LLM instructions**: `/root/Projects/myriadmesh-split-workspace/LLM_INSTRUCTIONS.md`

---

**Last Updated**: 2025-12-12

