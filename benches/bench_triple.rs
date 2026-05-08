//! Easy Mode Triple-Ouroboros benchmarks for the Rust binding.
//!
//! Mirrors the BenchmarkTriple* cohort from itb3_ext_test.go for the
//! nine PRF-grade primitives, locked at 1024-bit ITB key width and 16
//! MiB CSPRNG-filled payload. One mixed-primitive variant
//! ([`itb::Encryptor::mixed_triple`] cycling the same BLAKE family +
//! Areion-SoEM-256 dedicated lockSeed used by bench_single_mixed)
//! covers the Easy Mode Mixed surface alongside the single-primitive
//! grid.
//!
//! Run with::
//!
//!     cargo bench --bench bench_triple
//!
//!     ITB_NONCE_BITS=512 ITB_LOCKSEED=1 \
//!         cargo bench --bench bench_triple
//!
//!     ITB_BENCH_FILTER=blake3_encrypt \
//!         cargo bench --bench bench_triple
//!
//! The harness emits one Go-bench-style line per case (name, iters,
//! ns/op, MB/s). See `common.rs` for the supported environment
//! variables and the convergence policy. The pure bit-soup
//! configuration is intentionally not exercised on the Triple side —
//! the BitSoup/LockSoup overlay routes through the auto-coupled path
//! when ITB_LOCKSEED=1, which already covers the Triple bit-level
//! split surface end-to-end.

#[path = "common.rs"]
mod common;

use itb::Encryptor;

use crate::common::{BenchCase, BenchFn, PAYLOAD_16MB};

// Canonical 9-primitive PRF-grade order, mirroring bench_triple.py.
const PRIMITIVES_CANONICAL: &[&str] = &[
    "areion256",
    "areion512",
    "blake2b256",
    "blake2b512",
    "blake2s",
    "blake3",
    "aescmac",
    "siphash24",
    "chacha20",
];

// Mixed-primitive composition for Triple Ouroboros — the same four
// 256-bit-wide names used by bench_single_mixed are cycled across
// the seven seed slots (noise + 3 data + 3 start) plus
// Areion-SoEM-256 on the dedicated lockSeed slot.
const MIXED_NOISE: &str = "blake3";
const MIXED_DATA1: &str = "blake2s";
const MIXED_DATA2: &str = "blake2b256";
const MIXED_DATA3: &str = "blake3";
const MIXED_START1: &str = "blake2s";
const MIXED_START2: &str = "blake2b256";
const MIXED_START3: &str = "blake3";
const MIXED_LOCK: &str = "areion256";

const KEY_BITS: i32 = 1024;
const MAC_NAME: &str = "hmac-blake3";
const PAYLOAD_BYTES: usize = PAYLOAD_16MB;

/// When `ITB_LOCKSEED` is set the harness flips the dedicated
/// lockSeed channel on every encryptor. Easy Mode auto-couples
/// BitSoup + LockSoup as a side effect.
fn apply_lockseed_if_requested(enc: &Encryptor) {
    if common::env_lock_seed() {
        enc.set_lock_seed(1).expect("set_lock_seed(1)");
    }
}

/// Construct a single-primitive 1024-bit Triple-Ouroboros encryptor
/// with KMAC256 authentication. Triple = mode=3, 7-seed layout.
fn build_triple(primitive: &str) -> Encryptor {
    let enc = Encryptor::new(Some(primitive), Some(KEY_BITS), Some(MAC_NAME), 3)
        .unwrap_or_else(|e| panic!("Encryptor::new({primitive}, mode=3): {e:?}"));
    apply_lockseed_if_requested(&enc);
    enc
}

/// Construct a mixed-primitive Triple-Ouroboros encryptor with the
/// four-name BLAKE family across the seven middle slots. The
/// dedicated Areion-SoEM-256 lockSeed slot is allocated only when
/// `ITB_LOCKSEED` is set, so the no-LockSeed bench arm measures the
/// plain mixed-primitive cost without the BitSoup + LockSoup
/// auto-couple. The four primitive names share the same native hash
/// width so the `Encryptor::mixed_triple` width-check passes.
fn build_mixed_triple() -> Encryptor {
    let prim_l = if common::env_lock_seed() { Some(MIXED_LOCK) } else { None };
    Encryptor::mixed_triple(
        MIXED_NOISE,
        MIXED_DATA1,
        MIXED_DATA2,
        MIXED_DATA3,
        MIXED_START1,
        MIXED_START2,
        MIXED_START3,
        prim_l,
        KEY_BITS,
        MAC_NAME,
    )
    .expect("mixed_triple")
}

fn make_encrypt_case(name: String, mut enc: Encryptor) -> BenchCase {
    let payload = common::random_bytes(PAYLOAD_BYTES);
    let run: BenchFn = Box::new(move |iters: u64| {
        for _ in 0..iters {
            let _ = enc.encrypt(&payload).expect("encrypt");
        }
    });
    BenchCase {
        name,
        run,
        payload_bytes: PAYLOAD_BYTES,
    }
}

fn make_decrypt_case(name: String, mut enc: Encryptor) -> BenchCase {
    let payload = common::random_bytes(PAYLOAD_BYTES);
    let ciphertext = enc.encrypt(&payload).expect("encrypt for decrypt-case");
    let run: BenchFn = Box::new(move |iters: u64| {
        for _ in 0..iters {
            let _ = enc.decrypt(&ciphertext).expect("decrypt");
        }
    });
    BenchCase {
        name,
        run,
        payload_bytes: PAYLOAD_BYTES,
    }
}

fn make_encrypt_auth_case(name: String, mut enc: Encryptor) -> BenchCase {
    let payload = common::random_bytes(PAYLOAD_BYTES);
    let run: BenchFn = Box::new(move |iters: u64| {
        for _ in 0..iters {
            let _ = enc.encrypt_auth(&payload).expect("encrypt_auth");
        }
    });
    BenchCase {
        name,
        run,
        payload_bytes: PAYLOAD_BYTES,
    }
}

fn make_decrypt_auth_case(name: String, mut enc: Encryptor) -> BenchCase {
    let payload = common::random_bytes(PAYLOAD_BYTES);
    let ciphertext = enc
        .encrypt_auth(&payload)
        .expect("encrypt_auth for decrypt-case");
    let run: BenchFn = Box::new(move |iters: u64| {
        for _ in 0..iters {
            let _ = enc.decrypt_auth(&ciphertext).expect("decrypt_auth");
        }
    });
    BenchCase {
        name,
        run,
        payload_bytes: PAYLOAD_BYTES,
    }
}

/// Assemble the full case list: 9 single-primitive entries × 4 ops
/// plus 1 mixed entry × 4 ops = 40 cases. Order is primitive-major /
/// op-minor so a filter on a primitive name keeps all four ops
/// grouped together in the output.
fn build_cases() -> Vec<BenchCase> {
    let mut cases: Vec<BenchCase> = Vec::with_capacity(40);
    for prim in PRIMITIVES_CANONICAL {
        let base = format!("bench_triple_{prim}_{KEY_BITS}bit");
        cases.push(make_encrypt_case(
            format!("{base}_encrypt_16mb"),
            build_triple(prim),
        ));
        cases.push(make_decrypt_case(
            format!("{base}_decrypt_16mb"),
            build_triple(prim),
        ));
        cases.push(make_encrypt_auth_case(
            format!("{base}_encrypt_auth_16mb"),
            build_triple(prim),
        ));
        cases.push(make_decrypt_auth_case(
            format!("{base}_decrypt_auth_16mb"),
            build_triple(prim),
        ));
    }
    let base = format!("bench_triple_mixed_{KEY_BITS}bit");
    cases.push(make_encrypt_case(
        format!("{base}_encrypt_16mb"),
        build_mixed_triple(),
    ));
    cases.push(make_decrypt_case(
        format!("{base}_decrypt_16mb"),
        build_mixed_triple(),
    ));
    cases.push(make_encrypt_auth_case(
        format!("{base}_encrypt_auth_16mb"),
        build_mixed_triple(),
    ));
    cases.push(make_decrypt_auth_case(
        format!("{base}_decrypt_auth_16mb"),
        build_mixed_triple(),
    ));
    append_stream_cases_triple(&mut cases);
    cases
}

fn main() {
    let nonce_bits = common::env_nonce_bits(128);
    itb::set_max_workers(0).expect("set_max_workers(0)");
    itb::set_nonce_bits(nonce_bits).expect("set_nonce_bits");

    println!(
        "# easy_triple primitives={} key_bits={} mac={} nonce_bits={} lockseed={} workers=auto",
        PRIMITIVES_CANONICAL.len(),
        KEY_BITS,
        MAC_NAME,
        nonce_bits,
        if common::env_lock_seed() { "on" } else { "off" },
    );

    let cases = build_cases();
    common::run_all(cases);
}

// ────────────────────────────────────────────────────────────────────
// Streaming benchmarks (Triple Ouroboros, 7-seed).
//
// Eight cases exercising the full Triple-Ouroboros streaming matrix
// at 64 MiB total payload / 16 MiB chunk size under areion512 + 1024
// bit ITB key + hmac-blake3 MAC:
//
//     | Mode      | Op      | Variant   |
//     |-----------|---------|-----------|
//     | Easy      | Encrypt | AEAD-IO   |
//     | Easy      | Encrypt | UserLoop  |
//     | Easy      | Decrypt | AEAD-IO   |
//     | Easy      | Decrypt | UserLoop  |
//     | Low-Level | Encrypt | AEAD-IO   |
//     | Low-Level | Encrypt | UserLoop  |
//     | Low-Level | Decrypt | AEAD-IO   |
//     | Low-Level | Decrypt | UserLoop  |
//
// AEAD-IO  — Streaming AEAD over Read / Write traits. Easy:
//            Encryptor::encrypt_stream_auth / decrypt_stream_auth on a
//            mode=3 encryptor (the same Easy entry points that Single
//            uses; the Easy wrapper dispatches Triple internally).
//            Low-Level: itb::encrypt_stream_auth_triple /
//            decrypt_stream_auth_triple free functions over the
//            7-seed bundle + MAC.
//
// UserLoop — plain Streaming via caller-side per-chunk loop with the
//            4-byte big-endian length-prefix framing convention.
//            Easy: Encryptor::encrypt / decrypt on a mode=3
//            encryptor. Low-Level: itb::encrypt_triple /
//            decrypt_triple free functions over the 7-seed bundle.
//
// Setup discipline: 64 MiB CSPRNG fill, 7 seeds + MAC + Encryptor
// construction, and (for Decrypt cases) the pre-encryption all run
// outside the timer.
// ────────────────────────────────────────────────────────────────────

use std::io::{Cursor, Read, Write};

use itb::{Seed, MAC};

const STREAM_PRIMITIVE: &str = "areion512";
const STREAM_TOTAL_BYTES: usize = 64 << 20;
const STREAM_CHUNK_BYTES: usize = 16 << 20;
const STREAM_MAC_KEY: [u8; 32] = [
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
    0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00,
    0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80,
    0x90, 0xa0, 0xb0, 0xc0, 0xd0, 0xe0, 0xf0, 0x01,
];

/// Triple-Ouroboros 7-seed bundle: 1 noise seed + 3 data seeds +
/// 3 start seeds. All seven share the same primitive / key-bits and
/// pairwise distinct CSPRNG components (Seed::new draws fresh
/// material per call).
struct StreamSeedsTriple {
    noise: Seed,
    data1: Seed,
    data2: Seed,
    data3: Seed,
    start1: Seed,
    start2: Seed,
    start3: Seed,
}

fn build_stream_encryptor_triple() -> Encryptor {
    let enc = Encryptor::new(
        Some(STREAM_PRIMITIVE),
        Some(KEY_BITS),
        Some(MAC_NAME),
        3,
    )
    .unwrap_or_else(|e| panic!("Encryptor::new({STREAM_PRIMITIVE}, mode=3): {e:?}"));
    apply_lockseed_if_requested(&enc);
    enc
}

fn build_stream_seeds_triple() -> StreamSeedsTriple {
    StreamSeedsTriple {
        noise:  Seed::new(STREAM_PRIMITIVE, KEY_BITS).expect("Seed::new noise"),
        data1:  Seed::new(STREAM_PRIMITIVE, KEY_BITS).expect("Seed::new data1"),
        data2:  Seed::new(STREAM_PRIMITIVE, KEY_BITS).expect("Seed::new data2"),
        data3:  Seed::new(STREAM_PRIMITIVE, KEY_BITS).expect("Seed::new data3"),
        start1: Seed::new(STREAM_PRIMITIVE, KEY_BITS).expect("Seed::new start1"),
        start2: Seed::new(STREAM_PRIMITIVE, KEY_BITS).expect("Seed::new start2"),
        start3: Seed::new(STREAM_PRIMITIVE, KEY_BITS).expect("Seed::new start3"),
    }
}

fn build_stream_mac() -> MAC {
    MAC::new(MAC_NAME, &STREAM_MAC_KEY).expect("MAC::new")
}

fn frame_chunk(out: &mut Vec<u8>, ct: &[u8]) {
    let len_be = (ct.len() as u32).to_be_bytes();
    out.write_all(&len_be).expect("write len prefix");
    out.write_all(ct).expect("write ct");
}

fn make_easy_stream_encrypt_aead_io_case_triple(name: String) -> BenchCase {
    let payload = common::random_bytes(STREAM_TOTAL_BYTES);
    let mut enc = build_stream_encryptor_triple();
    let run: BenchFn = Box::new(move |iters: u64| {
        for _ in 0..iters {
            let reader = Cursor::new(&payload[..]);
            let mut writer: Vec<u8> =
                Vec::with_capacity(STREAM_TOTAL_BYTES + (STREAM_TOTAL_BYTES >> 3));
            enc.encrypt_stream_auth(reader, &mut writer, STREAM_CHUNK_BYTES)
                .expect("encrypt_stream_auth (triple)");
        }
    });
    BenchCase { name, run, payload_bytes: STREAM_TOTAL_BYTES }
}

fn make_easy_stream_decrypt_aead_io_case_triple(name: String) -> BenchCase {
    let payload = common::random_bytes(STREAM_TOTAL_BYTES);
    let mut enc = build_stream_encryptor_triple();
    let mut transcript: Vec<u8> =
        Vec::with_capacity(STREAM_TOTAL_BYTES + (STREAM_TOTAL_BYTES >> 3));
    enc.encrypt_stream_auth(Cursor::new(&payload[..]), &mut transcript, STREAM_CHUNK_BYTES)
        .expect("pre-encrypt for triple decrypt-case");
    let run: BenchFn = Box::new(move |iters: u64| {
        for _ in 0..iters {
            let reader = Cursor::new(&transcript[..]);
            let mut writer: Vec<u8> = Vec::with_capacity(STREAM_TOTAL_BYTES);
            enc.decrypt_stream_auth(reader, &mut writer, STREAM_CHUNK_BYTES)
                .expect("decrypt_stream_auth (triple)");
        }
    });
    BenchCase { name, run, payload_bytes: STREAM_TOTAL_BYTES }
}

fn make_easy_stream_encrypt_userloop_case_triple(name: String) -> BenchCase {
    let payload = common::random_bytes(STREAM_TOTAL_BYTES);
    let mut enc = build_stream_encryptor_triple();
    let run: BenchFn = Box::new(move |iters: u64| {
        for _ in 0..iters {
            let mut writer: Vec<u8> =
                Vec::with_capacity(STREAM_TOTAL_BYTES + (STREAM_TOTAL_BYTES >> 3));
            let mut off = 0usize;
            while off < payload.len() {
                let end = std::cmp::min(off + STREAM_CHUNK_BYTES, payload.len());
                let ct = enc.encrypt(&payload[off..end]).expect("encrypt (triple)");
                frame_chunk(&mut writer, &ct);
                off = end;
            }
        }
    });
    BenchCase { name, run, payload_bytes: STREAM_TOTAL_BYTES }
}

fn make_easy_stream_decrypt_userloop_case_triple(name: String) -> BenchCase {
    let payload = common::random_bytes(STREAM_TOTAL_BYTES);
    let mut enc = build_stream_encryptor_triple();
    let mut transcript: Vec<u8> =
        Vec::with_capacity(STREAM_TOTAL_BYTES + (STREAM_TOTAL_BYTES >> 3));
    let mut off = 0usize;
    while off < payload.len() {
        let end = std::cmp::min(off + STREAM_CHUNK_BYTES, payload.len());
        let ct = enc.encrypt(&payload[off..end]).expect("pre-encrypt UserLoop (triple)");
        frame_chunk(&mut transcript, &ct);
        off = end;
    }
    let run: BenchFn = Box::new(move |iters: u64| {
        for _ in 0..iters {
            let mut reader = Cursor::new(&transcript[..]);
            let mut writer: Vec<u8> = Vec::with_capacity(STREAM_TOTAL_BYTES);
            loop {
                let mut hdr = [0u8; 4];
                match reader.read_exact(&mut hdr) {
                    Ok(()) => {}
                    Err(_) => break,
                }
                let n = u32::from_be_bytes(hdr) as usize;
                let mut ct = vec![0u8; n];
                reader.read_exact(&mut ct).expect("read ct (triple)");
                let pt = enc.decrypt(&ct).expect("decrypt (triple)");
                writer.write_all(&pt).expect("write pt");
            }
        }
    });
    BenchCase { name, run, payload_bytes: STREAM_TOTAL_BYTES }
}

fn make_lowlevel_stream_encrypt_aead_io_case_triple(name: String) -> BenchCase {
    let payload = common::random_bytes(STREAM_TOTAL_BYTES);
    let s = build_stream_seeds_triple();
    let mac = build_stream_mac();
    let run: BenchFn = Box::new(move |iters: u64| {
        for _ in 0..iters {
            let reader = Cursor::new(&payload[..]);
            let mut writer: Vec<u8> =
                Vec::with_capacity(STREAM_TOTAL_BYTES + (STREAM_TOTAL_BYTES >> 3));
            itb::encrypt_stream_auth_triple(
                &s.noise,
                &s.data1, &s.data2, &s.data3,
                &s.start1, &s.start2, &s.start3,
                &mac, reader, &mut writer, STREAM_CHUNK_BYTES,
            )
            .expect("encrypt_stream_auth_triple (low-level)");
        }
    });
    BenchCase { name, run, payload_bytes: STREAM_TOTAL_BYTES }
}

fn make_lowlevel_stream_decrypt_aead_io_case_triple(name: String) -> BenchCase {
    let payload = common::random_bytes(STREAM_TOTAL_BYTES);
    let s = build_stream_seeds_triple();
    let mac = build_stream_mac();
    let mut transcript: Vec<u8> =
        Vec::with_capacity(STREAM_TOTAL_BYTES + (STREAM_TOTAL_BYTES >> 3));
    itb::encrypt_stream_auth_triple(
        &s.noise,
        &s.data1, &s.data2, &s.data3,
        &s.start1, &s.start2, &s.start3,
        &mac, Cursor::new(&payload[..]), &mut transcript, STREAM_CHUNK_BYTES,
    )
    .expect("pre-encrypt for low-level triple decrypt-case");
    let run: BenchFn = Box::new(move |iters: u64| {
        for _ in 0..iters {
            let reader = Cursor::new(&transcript[..]);
            let mut writer: Vec<u8> = Vec::with_capacity(STREAM_TOTAL_BYTES);
            itb::decrypt_stream_auth_triple(
                &s.noise,
                &s.data1, &s.data2, &s.data3,
                &s.start1, &s.start2, &s.start3,
                &mac, reader, &mut writer, STREAM_CHUNK_BYTES,
            )
            .expect("decrypt_stream_auth_triple (low-level)");
        }
    });
    BenchCase { name, run, payload_bytes: STREAM_TOTAL_BYTES }
}

fn make_lowlevel_stream_encrypt_userloop_case_triple(name: String) -> BenchCase {
    let payload = common::random_bytes(STREAM_TOTAL_BYTES);
    let s = build_stream_seeds_triple();
    let run: BenchFn = Box::new(move |iters: u64| {
        for _ in 0..iters {
            let mut writer: Vec<u8> =
                Vec::with_capacity(STREAM_TOTAL_BYTES + (STREAM_TOTAL_BYTES >> 3));
            let mut off = 0usize;
            while off < payload.len() {
                let end = std::cmp::min(off + STREAM_CHUNK_BYTES, payload.len());
                let ct = itb::encrypt_triple(
                    &s.noise,
                    &s.data1, &s.data2, &s.data3,
                    &s.start1, &s.start2, &s.start3,
                    &payload[off..end],
                )
                .expect("encrypt_triple (low-level)");
                frame_chunk(&mut writer, &ct);
                off = end;
            }
        }
    });
    BenchCase { name, run, payload_bytes: STREAM_TOTAL_BYTES }
}

fn make_lowlevel_stream_decrypt_userloop_case_triple(name: String) -> BenchCase {
    let payload = common::random_bytes(STREAM_TOTAL_BYTES);
    let s = build_stream_seeds_triple();
    let mut transcript: Vec<u8> =
        Vec::with_capacity(STREAM_TOTAL_BYTES + (STREAM_TOTAL_BYTES >> 3));
    let mut off = 0usize;
    while off < payload.len() {
        let end = std::cmp::min(off + STREAM_CHUNK_BYTES, payload.len());
        let ct = itb::encrypt_triple(
            &s.noise,
            &s.data1, &s.data2, &s.data3,
            &s.start1, &s.start2, &s.start3,
            &payload[off..end],
        )
        .expect("pre-encrypt UserLoop (low-level triple)");
        frame_chunk(&mut transcript, &ct);
        off = end;
    }
    let run: BenchFn = Box::new(move |iters: u64| {
        for _ in 0..iters {
            let mut reader = Cursor::new(&transcript[..]);
            let mut writer: Vec<u8> = Vec::with_capacity(STREAM_TOTAL_BYTES);
            loop {
                let mut hdr = [0u8; 4];
                match reader.read_exact(&mut hdr) {
                    Ok(()) => {}
                    Err(_) => break,
                }
                let n = u32::from_be_bytes(hdr) as usize;
                let mut ct = vec![0u8; n];
                reader.read_exact(&mut ct).expect("read ct (low-level triple)");
                let pt = itb::decrypt_triple(
                    &s.noise,
                    &s.data1, &s.data2, &s.data3,
                    &s.start1, &s.start2, &s.start3,
                    &ct,
                )
                .expect("decrypt_triple (low-level)");
                writer.write_all(&pt).expect("write pt");
            }
        }
    });
    BenchCase { name, run, payload_bytes: STREAM_TOTAL_BYTES }
}

/// Appends the eight Triple-Ouroboros streaming benches to the
/// running case list. Naming convention parallels the Single side:
///
///     bench_triple_stream_<mode>_<op>_<variant>_<primitive>_<bits>bit_<size>mb
fn append_stream_cases_triple(cases: &mut Vec<BenchCase>) {
    let base = format!(
        "bench_triple_stream_{STREAM_PRIMITIVE}_{KEY_BITS}bit_64mb"
    );
    cases.push(make_easy_stream_encrypt_aead_io_case_triple(
        format!("{base}_easy_encrypt_aead_io"),
    ));
    cases.push(make_easy_stream_decrypt_aead_io_case_triple(
        format!("{base}_easy_decrypt_aead_io"),
    ));
    cases.push(make_easy_stream_encrypt_userloop_case_triple(
        format!("{base}_easy_encrypt_userloop"),
    ));
    cases.push(make_easy_stream_decrypt_userloop_case_triple(
        format!("{base}_easy_decrypt_userloop"),
    ));
    cases.push(make_lowlevel_stream_encrypt_aead_io_case_triple(
        format!("{base}_lowlevel_encrypt_aead_io"),
    ));
    cases.push(make_lowlevel_stream_decrypt_aead_io_case_triple(
        format!("{base}_lowlevel_decrypt_aead_io"),
    ));
    cases.push(make_lowlevel_stream_encrypt_userloop_case_triple(
        format!("{base}_lowlevel_encrypt_userloop"),
    ));
    cases.push(make_lowlevel_stream_decrypt_userloop_case_triple(
        format!("{base}_lowlevel_decrypt_userloop"),
    ));
}
