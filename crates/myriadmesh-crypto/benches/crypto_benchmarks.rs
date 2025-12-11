use criterion::{black_box, criterion_group, criterion_main, Criterion};
use myriadmesh_crypto::*;

fn benchmark_identity_generation(c: &mut Criterion) {
    init().unwrap();

    c.bench_function("generate identity", |b| {
        b.iter(|| identity::NodeIdentity::generate().unwrap());
    });
}

fn benchmark_signing(c: &mut Criterion) {
    init().unwrap();
    let identity = identity::NodeIdentity::generate().unwrap();
    let message = b"Hello, MyriadMesh! This is a test message for benchmarking.";

    c.bench_function("sign message", |b| {
        b.iter(|| signing::sign_message(black_box(&identity), black_box(message)).unwrap());
    });
}

fn benchmark_verification(c: &mut Criterion) {
    init().unwrap();
    let identity = identity::NodeIdentity::generate().unwrap();
    let message = b"Hello, MyriadMesh! This is a test message for benchmarking.";
    let signature = signing::sign_message(&identity, message).unwrap();

    c.bench_function("verify signature", |b| {
        b.iter(|| {
            signing::verify_signature(
                black_box(&identity.public_key),
                black_box(message),
                black_box(&signature),
            )
            .unwrap()
        });
    });
}

fn benchmark_encryption(c: &mut Criterion) {
    init().unwrap();
    let key = encryption::SymmetricKey::generate();
    let plaintext =
        b"Hello, MyriadMesh! This is a test message for benchmarking encryption performance.";

    c.bench_function("encrypt message", |b| {
        b.iter(|| encryption::encrypt(black_box(&key), black_box(plaintext)).unwrap());
    });
}

fn benchmark_decryption(c: &mut Criterion) {
    init().unwrap();
    let key = encryption::SymmetricKey::generate();
    let plaintext =
        b"Hello, MyriadMesh! This is a test message for benchmarking encryption performance.";
    let encrypted = encryption::encrypt(&key, plaintext).unwrap();

    c.bench_function("decrypt message", |b| {
        b.iter(|| encryption::decrypt(black_box(&key), black_box(&encrypted)).unwrap());
    });
}

fn benchmark_key_exchange(c: &mut Criterion) {
    init().unwrap();
    let client_kp = keyexchange::KeyExchangeKeypair::generate();
    let server_kp = keyexchange::KeyExchangeKeypair::generate();
    let server_pub = keyexchange::X25519PublicKey::from(&server_kp.public_key);

    c.bench_function("key exchange", |b| {
        b.iter(|| {
            keyexchange::client_session_keys(black_box(&client_kp), black_box(&server_pub)).unwrap()
        });
    });
}

criterion_group!(
    benches,
    benchmark_identity_generation,
    benchmark_signing,
    benchmark_verification,
    benchmark_encryption,
    benchmark_decryption,
    benchmark_key_exchange
);
criterion_main!(benches);
