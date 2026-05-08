//! Easy Mode Single-Ouroboros benchmarks for the Rust binding.
//!
//! Mirrors the BenchmarkSingle* cohort from itb_ext_test.go for the
//! nine PRF-grade primitives, locked at 1024-bit ITB key width and 16
//! MiB CSPRNG-filled payload. One mixed-primitive variant
//! ([`itb::Encryptor::mixed_single`] with BLAKE3 / BLAKE2s /
//! BLAKE2b-256 + Areion-SoEM-256 dedicated lockSeed) covers the
//! Easy Mode Mixed surface alongside the single-primitive grid.
//!
//! Run with::
//!
//!     cargo bench --bench bench_single
//!
//!     ITB_NONCE_BITS=512 ITB_LOCKSEED=1 \
//!         cargo bench --bench bench_single
//!
//!     ITB_BENCH_FILTER=blake3_encrypt \
//!         cargo bench --bench bench_single
//!
//! The harness emits one Go-bench-style line per case (name, iters,
//! ns/op, MB/s). See `common.rs` for the supported environment
//! variables and the convergence policy.

#[path = "common.rs"]
mod common;

use itb::Encryptor;

use crate::common::{BenchCase, BenchFn, PAYLOAD_16MB};

// Canonical 9-primitive PRF-grade order, mirroring bench_single.py.
// The three below-spec lab primitives (CRC128, FNV-1a, MD5) are not
// exposed through the libitb registry and are therefore absent here
// by construction.
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

// Mixed-primitive composition used by the bench_single_mixed_*
// cases. noise / data / start cycle through the BLAKE family while
// Areion-SoEM-256 takes the dedicated lockSeed slot — every name
// resolves to a 256-bit native hash width so the
// Encryptor::mixed_single width-check passes.
const MIXED_NOISE: &str = "blake3";
const MIXED_DATA: &str = "blake2s";
const MIXED_START: &str = "blake2b256";
const MIXED_LOCK: &str = "areion256";

const KEY_BITS: i32 = 1024;
const MAC_NAME: &str = "hmac-blake3";
const PAYLOAD_BYTES: usize = PAYLOAD_16MB;

/// When `ITB_LOCKSEED` is set the harness flips the dedicated
/// lockSeed channel on every encryptor. Easy Mode auto-couples
/// BitSoup + LockSoup as a side effect, so no separate calls are
/// issued.
fn apply_lockseed_if_requested(enc: &Encryptor) {
    if common::env_lock_seed() {
        enc.set_lock_seed(1).expect("set_lock_seed(1)");
    }
}

/// Construct a single-primitive 1024-bit Single-Ouroboros encryptor
/// with KMAC256 authentication, mirroring the shape used by every
/// benchmark in this module.
fn build_single(primitive: &str) -> Encryptor {
    let enc = Encryptor::new(Some(primitive), Some(KEY_BITS), Some(MAC_NAME), 1)
        .unwrap_or_else(|e| panic!("Encryptor::new({primitive}): {e:?}"));
    apply_lockseed_if_requested(&enc);
    enc
}

/// Construct a mixed-primitive Single-Ouroboros encryptor matching
/// the README Quick Start composition (BLAKE3 noise / BLAKE2s data /
/// BLAKE2b-256 start). The dedicated Areion-SoEM-256 lockSeed slot
/// is allocated only when `ITB_LOCKSEED` is set, so the no-LockSeed
/// bench arm measures the plain mixed-primitive cost without the
/// BitSoup + LockSoup auto-couple. The four primitive names share
/// the 256-bit native hash width.
fn build_mixed_single() -> Encryptor {
    // When `primitive_l` is set, mixed_single auto-couples BitSoup +
    // LockSoup on construction; an extra set_lock_seed call would be
    // a redundant no-op against the already-active lockSeed slot.
    // When `primitive_l` is None the encryptor stays in plain mixed
    // mode.
    let prim_l = if common::env_lock_seed() { Some(MIXED_LOCK) } else { None };
    Encryptor::mixed_single(
        MIXED_NOISE,
        MIXED_DATA,
        MIXED_START,
        prim_l,
        KEY_BITS,
        MAC_NAME,
    )
    .expect("mixed_single")
}

/// Build a plain-Encrypt bench case. Encryptor + payload are
/// constructed once outside the measured loop; only the encrypt call
/// is timed.
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

/// Build a plain-Decrypt bench case. Pre-encrypts a single
/// ciphertext outside the measured loop; only the decrypt call is
/// timed.
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

/// Build an authenticated-Encrypt bench case (MAC tag attached).
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

/// Build an authenticated-Decrypt bench case (MAC tag verified on
/// the way back).
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
        let base = format!("bench_single_{prim}_{KEY_BITS}bit");
        cases.push(make_encrypt_case(
            format!("{base}_encrypt_16mb"),
            build_single(prim),
        ));
        cases.push(make_decrypt_case(
            format!("{base}_decrypt_16mb"),
            build_single(prim),
        ));
        cases.push(make_encrypt_auth_case(
            format!("{base}_encrypt_auth_16mb"),
            build_single(prim),
        ));
        cases.push(make_decrypt_auth_case(
            format!("{base}_decrypt_auth_16mb"),
            build_single(prim),
        ));
    }
    let base = format!("bench_single_mixed_{KEY_BITS}bit");
    cases.push(make_encrypt_case(
        format!("{base}_encrypt_16mb"),
        build_mixed_single(),
    ));
    cases.push(make_decrypt_case(
        format!("{base}_decrypt_16mb"),
        build_mixed_single(),
    ));
    cases.push(make_encrypt_auth_case(
        format!("{base}_encrypt_auth_16mb"),
        build_mixed_single(),
    ));
    cases.push(make_decrypt_auth_case(
        format!("{base}_decrypt_auth_16mb"),
        build_mixed_single(),
    ));
    append_stream_cases_single(&mut cases);
    cases
}

fn main() {
    let nonce_bits = common::env_nonce_bits(128);
    itb::set_max_workers(0).expect("set_max_workers(0)");
    itb::set_nonce_bits(nonce_bits).expect("set_nonce_bits");

    println!(
        "# easy_single primitives={} key_bits={} mac={} nonce_bits={} lockseed={} workers=auto",
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
// Streaming benchmarks (Single Ouroboros).
//
// Eight cases exercising the full Single-Ouroboros streaming matrix
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
//            Encryptor::encrypt_stream_auth / decrypt_stream_auth.
//            Low-Level: itb::encrypt_stream_auth / decrypt_stream_auth
//            free functions over (noise, data, start, mac).
//
// UserLoop — plain Streaming via caller-side per-chunk loop; framing
//            convention is a 4-byte big-endian ciphertext-length
//            prefix preceding each chunk's ciphertext bytes (matching
//            the canonical pattern in tmp/itb_examples/rust/main.rs).
//            Easy uses Encryptor::encrypt / decrypt; Low-Level uses
//            the itb::encrypt / decrypt free functions.
//
// Setup discipline: 64 MiB CSPRNG fill, Encryptor / Seed / MAC
// construction, and (for Decrypt cases) the pre-encryption all run
// outside the timer. Each measured iteration walks a fresh
// Cursor / output Vec over the prepared inputs and tears them down.
// ────────────────────────────────────────────────────────────────────

use std::io::{Cursor, Read, Write};

use itb::{Seed, MAC};

const STREAM_PRIMITIVE: &str = "areion512";
const STREAM_TOTAL_BYTES: usize = 64 << 20;
const STREAM_CHUNK_BYTES: usize = 16 << 20;
// Fixed 32-byte MAC key — matches the canonical .NEXTBIND.md /
// .MACSTREAM.md MAC-key length and `MAC::new`'s 32-byte hmac-blake3
// requirement. Value contents are immaterial for throughput
// measurement; the MAC executes in O(MAC-key-length) per absorb
// regardless of byte distribution.
const STREAM_MAC_KEY: [u8; 32] = [
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
    0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00,
    0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80,
    0x90, 0xa0, 0xb0, 0xc0, 0xd0, 0xe0, 0xf0, 0x01,
];

fn build_stream_encryptor() -> Encryptor {
    let enc = Encryptor::new(
        Some(STREAM_PRIMITIVE),
        Some(KEY_BITS),
        Some(MAC_NAME),
        1,
    )
    .unwrap_or_else(|e| panic!("Encryptor::new({STREAM_PRIMITIVE}, mode=1): {e:?}"));
    apply_lockseed_if_requested(&enc);
    enc
}

fn build_stream_seeds_single() -> (Seed, Seed, Seed) {
    let n = Seed::new(STREAM_PRIMITIVE, KEY_BITS).expect("Seed::new noise");
    let d = Seed::new(STREAM_PRIMITIVE, KEY_BITS).expect("Seed::new data");
    let s = Seed::new(STREAM_PRIMITIVE, KEY_BITS).expect("Seed::new start");
    (n, d, s)
}

fn build_stream_mac() -> MAC {
    MAC::new(MAC_NAME, &STREAM_MAC_KEY).expect("MAC::new")
}

/// Frames a single chunk of plaintext under the UserLoop convention:
/// 4-byte big-endian ciphertext-length prefix followed by ciphertext.
fn frame_chunk(out: &mut Vec<u8>, ct: &[u8]) {
    let len_be = (ct.len() as u32).to_be_bytes();
    out.write_all(&len_be).expect("write len prefix");
    out.write_all(ct).expect("write ct");
}

/// Easy AEAD-IO encrypt: per iteration, runs `encrypt_stream_auth`
/// over a fresh Cursor reader / Vec writer.
fn make_easy_stream_encrypt_aead_io_case(name: String) -> BenchCase {
    let payload = common::random_bytes(STREAM_TOTAL_BYTES);
    let mut enc = build_stream_encryptor();
    let run: BenchFn = Box::new(move |iters: u64| {
        for _ in 0..iters {
            let reader = Cursor::new(&payload[..]);
            let mut writer: Vec<u8> = Vec::with_capacity(STREAM_TOTAL_BYTES + (STREAM_TOTAL_BYTES >> 3));
            enc.encrypt_stream_auth(reader, &mut writer, STREAM_CHUNK_BYTES)
                .expect("encrypt_stream_auth");
        }
    });
    BenchCase { name, run, payload_bytes: STREAM_TOTAL_BYTES }
}

/// Easy AEAD-IO decrypt: pre-encrypts once, then per iter decrypts
/// the stored transcript through `decrypt_stream_auth`.
fn make_easy_stream_decrypt_aead_io_case(name: String) -> BenchCase {
    let payload = common::random_bytes(STREAM_TOTAL_BYTES);
    let mut enc = build_stream_encryptor();
    let mut transcript: Vec<u8> = Vec::with_capacity(STREAM_TOTAL_BYTES + (STREAM_TOTAL_BYTES >> 3));
    enc.encrypt_stream_auth(Cursor::new(&payload[..]), &mut transcript, STREAM_CHUNK_BYTES)
        .expect("pre-encrypt for decrypt-case");
    let run: BenchFn = Box::new(move |iters: u64| {
        for _ in 0..iters {
            let reader = Cursor::new(&transcript[..]);
            let mut writer: Vec<u8> = Vec::with_capacity(STREAM_TOTAL_BYTES);
            enc.decrypt_stream_auth(reader, &mut writer, STREAM_CHUNK_BYTES)
                .expect("decrypt_stream_auth");
        }
    });
    BenchCase { name, run, payload_bytes: STREAM_TOTAL_BYTES }
}

/// Easy UserLoop encrypt: per iter, walks the plaintext in 16 MiB
/// chunks and emits 4-byte BE-length-prefixed ciphertexts via
/// `Encryptor::encrypt`.
fn make_easy_stream_encrypt_userloop_case(name: String) -> BenchCase {
    let payload = common::random_bytes(STREAM_TOTAL_BYTES);
    let mut enc = build_stream_encryptor();
    let run: BenchFn = Box::new(move |iters: u64| {
        for _ in 0..iters {
            let mut writer: Vec<u8> =
                Vec::with_capacity(STREAM_TOTAL_BYTES + (STREAM_TOTAL_BYTES >> 3));
            let mut off = 0usize;
            while off < payload.len() {
                let end = std::cmp::min(off + STREAM_CHUNK_BYTES, payload.len());
                let ct = enc.encrypt(&payload[off..end]).expect("encrypt");
                frame_chunk(&mut writer, &ct);
                off = end;
            }
        }
    });
    BenchCase { name, run, payload_bytes: STREAM_TOTAL_BYTES }
}

/// Easy UserLoop decrypt: pre-frames the transcript once, then per
/// iter parses the framing and calls `Encryptor::decrypt` per chunk.
fn make_easy_stream_decrypt_userloop_case(name: String) -> BenchCase {
    let payload = common::random_bytes(STREAM_TOTAL_BYTES);
    let mut enc = build_stream_encryptor();
    let mut transcript: Vec<u8> =
        Vec::with_capacity(STREAM_TOTAL_BYTES + (STREAM_TOTAL_BYTES >> 3));
    let mut off = 0usize;
    while off < payload.len() {
        let end = std::cmp::min(off + STREAM_CHUNK_BYTES, payload.len());
        let ct = enc.encrypt(&payload[off..end]).expect("pre-encrypt UserLoop");
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
                reader.read_exact(&mut ct).expect("read ct");
                let pt = enc.decrypt(&ct).expect("decrypt");
                writer.write_all(&pt).expect("write pt");
            }
        }
    });
    BenchCase { name, run, payload_bytes: STREAM_TOTAL_BYTES }
}

/// Low-Level AEAD-IO encrypt: per iter, runs `itb::encrypt_stream_auth`
/// over the (noise, data, start, mac) handles + fresh I/O wrappers.
fn make_lowlevel_stream_encrypt_aead_io_case(name: String) -> BenchCase {
    let payload = common::random_bytes(STREAM_TOTAL_BYTES);
    let (n_seed, d_seed, s_seed) = build_stream_seeds_single();
    let mac = build_stream_mac();
    let run: BenchFn = Box::new(move |iters: u64| {
        for _ in 0..iters {
            let reader = Cursor::new(&payload[..]);
            let mut writer: Vec<u8> =
                Vec::with_capacity(STREAM_TOTAL_BYTES + (STREAM_TOTAL_BYTES >> 3));
            itb::encrypt_stream_auth(
                &n_seed, &d_seed, &s_seed, &mac,
                reader, &mut writer, STREAM_CHUNK_BYTES,
            )
            .expect("encrypt_stream_auth (low-level)");
        }
    });
    BenchCase { name, run, payload_bytes: STREAM_TOTAL_BYTES }
}

/// Low-Level AEAD-IO decrypt: pre-encrypts once with the same seeds /
/// MAC, then per iter walks the transcript through
/// `itb::decrypt_stream_auth`.
fn make_lowlevel_stream_decrypt_aead_io_case(name: String) -> BenchCase {
    let payload = common::random_bytes(STREAM_TOTAL_BYTES);
    let (n_seed, d_seed, s_seed) = build_stream_seeds_single();
    let mac = build_stream_mac();
    let mut transcript: Vec<u8> =
        Vec::with_capacity(STREAM_TOTAL_BYTES + (STREAM_TOTAL_BYTES >> 3));
    itb::encrypt_stream_auth(
        &n_seed, &d_seed, &s_seed, &mac,
        Cursor::new(&payload[..]), &mut transcript, STREAM_CHUNK_BYTES,
    )
    .expect("pre-encrypt for low-level decrypt-case");
    let run: BenchFn = Box::new(move |iters: u64| {
        for _ in 0..iters {
            let reader = Cursor::new(&transcript[..]);
            let mut writer: Vec<u8> = Vec::with_capacity(STREAM_TOTAL_BYTES);
            itb::decrypt_stream_auth(
                &n_seed, &d_seed, &s_seed, &mac,
                reader, &mut writer, STREAM_CHUNK_BYTES,
            )
            .expect("decrypt_stream_auth (low-level)");
        }
    });
    BenchCase { name, run, payload_bytes: STREAM_TOTAL_BYTES }
}

/// Low-Level UserLoop encrypt: per iter, walks the plaintext in
/// 16 MiB chunks and frames each ciphertext via the free function
/// `itb::encrypt`.
fn make_lowlevel_stream_encrypt_userloop_case(name: String) -> BenchCase {
    let payload = common::random_bytes(STREAM_TOTAL_BYTES);
    let (n_seed, d_seed, s_seed) = build_stream_seeds_single();
    let run: BenchFn = Box::new(move |iters: u64| {
        for _ in 0..iters {
            let mut writer: Vec<u8> =
                Vec::with_capacity(STREAM_TOTAL_BYTES + (STREAM_TOTAL_BYTES >> 3));
            let mut off = 0usize;
            while off < payload.len() {
                let end = std::cmp::min(off + STREAM_CHUNK_BYTES, payload.len());
                let ct = itb::encrypt(&n_seed, &d_seed, &s_seed, &payload[off..end])
                    .expect("encrypt (low-level)");
                frame_chunk(&mut writer, &ct);
                off = end;
            }
        }
    });
    BenchCase { name, run, payload_bytes: STREAM_TOTAL_BYTES }
}

/// Low-Level UserLoop decrypt: pre-frames the transcript once, then
/// per iter walks the framing and calls `itb::decrypt` per chunk.
fn make_lowlevel_stream_decrypt_userloop_case(name: String) -> BenchCase {
    let payload = common::random_bytes(STREAM_TOTAL_BYTES);
    let (n_seed, d_seed, s_seed) = build_stream_seeds_single();
    let mut transcript: Vec<u8> =
        Vec::with_capacity(STREAM_TOTAL_BYTES + (STREAM_TOTAL_BYTES >> 3));
    let mut off = 0usize;
    while off < payload.len() {
        let end = std::cmp::min(off + STREAM_CHUNK_BYTES, payload.len());
        let ct = itb::encrypt(&n_seed, &d_seed, &s_seed, &payload[off..end])
            .expect("pre-encrypt UserLoop (low-level)");
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
                reader.read_exact(&mut ct).expect("read ct (low-level)");
                let pt = itb::decrypt(&n_seed, &d_seed, &s_seed, &ct)
                    .expect("decrypt (low-level)");
                writer.write_all(&pt).expect("write pt");
            }
        }
    });
    BenchCase { name, run, payload_bytes: STREAM_TOTAL_BYTES }
}

/// Appends the eight Single-Ouroboros streaming benches to the
/// running case list.  Naming convention:
///
///     bench_single_stream_<mode>_<op>_<variant>_<primitive>_<bits>bit_<size>mb
///
/// where `mode ∈ {easy, lowlevel}`, `op ∈ {encrypt, decrypt}`,
/// `variant ∈ {aead_io, userloop}`. Order is mode-major /
/// variant-minor / op-minor for filter-friendly grouping.
fn append_stream_cases_single(cases: &mut Vec<BenchCase>) {
    let base = format!(
        "bench_single_stream_{STREAM_PRIMITIVE}_{KEY_BITS}bit_64mb"
    );
    cases.push(make_easy_stream_encrypt_aead_io_case(
        format!("{base}_easy_encrypt_aead_io"),
    ));
    cases.push(make_easy_stream_decrypt_aead_io_case(
        format!("{base}_easy_decrypt_aead_io"),
    ));
    cases.push(make_easy_stream_encrypt_userloop_case(
        format!("{base}_easy_encrypt_userloop"),
    ));
    cases.push(make_easy_stream_decrypt_userloop_case(
        format!("{base}_easy_decrypt_userloop"),
    ));
    cases.push(make_lowlevel_stream_encrypt_aead_io_case(
        format!("{base}_lowlevel_encrypt_aead_io"),
    ));
    cases.push(make_lowlevel_stream_decrypt_aead_io_case(
        format!("{base}_lowlevel_decrypt_aead_io"),
    ));
    cases.push(make_lowlevel_stream_encrypt_userloop_case(
        format!("{base}_lowlevel_encrypt_userloop"),
    ));
    cases.push(make_lowlevel_stream_decrypt_userloop_case(
        format!("{base}_lowlevel_decrypt_userloop"),
    ));
}
