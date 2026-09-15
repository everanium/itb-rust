//! Stream-pump throughput vs plaintext size.
//!
//! Env-var overrides identical to `bench_message.rs`:
//!
//! | env var            | default   |
//! |--------------------|-----------|
//! | ITB_NONCE_BITS     | 512       |
//! | ITB_KEY_BITS       | 1024      |
//! | ITB_WITH_PARALLAX  | false     |
//! | ITB_WITH_WRAPPER   | false     |
//! | ITB_INNER_HASH     | (profile) |

use std::env;
use std::io::Cursor;
use std::time::Duration;

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use itb3::{OptsBuilder, Pipeline, set_gc_percent, set_memory_limit};
use rand::RngCore;

fn build_opts() -> OptsBuilder {
    let nonce_bits = env::var("ITB_NONCE_BITS")
        .ok()
        .and_then(|v| v.parse::<i64>().ok())
        .unwrap_or(512);
    let key_bits = env::var("ITB_KEY_BITS")
        .ok()
        .and_then(|v| v.parse::<i64>().ok())
        .unwrap_or(1024);
    let with_parallax = env::var("ITB_WITH_PARALLAX")
        .ok()
        .map(|v| v == "true" || v == "1")
        .unwrap_or(false);
    let with_wrapper = env::var("ITB_WITH_WRAPPER")
        .ok()
        .map(|v| v == "true" || v == "1")
        .unwrap_or(false);

    let mut opts = OptsBuilder::new()
        .with_nonce_bits(nonce_bits)
        .with_key_bits(key_bits)
        .with_parallax(with_parallax)
        .with_wrapper(with_wrapper);
    if let Ok(name) = env::var("ITB_INNER_HASH") {
        if !name.is_empty() {
            opts = opts.with_inner_hash(&name);
        }
    }
    if let Ok(name) = env::var("ITB_MAC_NAME") {
        if !name.is_empty() {
            opts = opts.with_mac_name(&name);
        }
    }
    opts
}

fn profile_name() -> String {
    env::var("ITB_PROFILE").unwrap_or_else(|_| "streaming-noaead-triple-v1".to_string())
}

fn bench_stream(c: &mut Criterion) {
    let _ = set_memory_limit(4 << 30);
    let _ = set_gc_percent(100);
    let opts = build_opts();
    let pipe = Pipeline::init(&profile_name(), &opts).unwrap();
    let mut group = c.benchmark_group("encrypt_stream_pump");
    group
        .sample_size(10)
        .measurement_time(Duration::from_secs(5));
    for size in [1usize << 20, 16 << 20, 64 << 20] {
        let mut plain = vec![0u8; size];
        // CSPRNG-fill so plaintext content matches the root Go bench
        // (crypto/rand). Not in the timing loop.
        rand::rng().fill_bytes(&mut plain);
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_function(format!("{size}B"), |b| {
            b.iter(|| {
                let mut wire = Vec::with_capacity(size + size / 4 + 131_072);
                pipe.encrypt_stream_pump(Cursor::new(&plain), &mut wire)
                    .unwrap();
                wire
            });
        });
    }
    group.finish();

    // Decrypt-side counterpart: pre-encrypt one wire per size outside
    // the timing loop, then time decrypt_stream_pump on that wire.
    let mut dec_group = c.benchmark_group("decrypt_stream_pump");
    dec_group
        .sample_size(10)
        .measurement_time(Duration::from_secs(5));
    for size in [1usize << 20, 16 << 20, 64 << 20] {
        let mut plain = vec![0u8; size];
        rand::rng().fill_bytes(&mut plain);
        let mut wire = Vec::with_capacity(size + size / 4 + 131_072);
        pipe.encrypt_stream_pump(Cursor::new(&plain), &mut wire)
            .unwrap();
        dec_group.throughput(Throughput::Bytes(size as u64));
        dec_group.bench_function(format!("{size}B"), |b| {
            b.iter(|| {
                let mut out = Vec::with_capacity(size + 131_072);
                pipe.decrypt_stream_pump(Cursor::new(&wire), &mut out)
                    .unwrap();
                out
            });
        });
    }
    dec_group.finish();
}

criterion_group!(benches, bench_stream);
criterion_main!(benches);
