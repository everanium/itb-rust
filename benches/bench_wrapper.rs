//! Format-deniability wrapper benchmarks for the Rust binding.
//!
//! Mirrors `bindings/python/wrapper/benchmarks/bench_wrapper.py` and
//! `wrapper/bench_test.go` from the repo root. Three test scopes:
//!
//!   * Wrapper Only — pure outer cipher round-trip throughput on a
//!     16 MiB random buffer (no ITB call). Two shapes: `wrap` (alloc
//!     fresh wire) and `wrap_in_place` (mutate caller's buffer).
//!     Encrypt + decrypt timed together — one round-trip per iter.
//!     6 sub-benches = 3 ciphers × 2 shapes.
//!
//!   * Message — full ITB encrypt-then-wrap and unwrap-then-decrypt
//!     timed separately on a 16 MiB plaintext. 4 modes (Easy No MAC,
//!     Easy Auth, Low-Level No MAC, Low-Level Auth) × 3 ciphers × 2
//!     directions = 24 per Single, 24 per Triple = 48 sub-benches.
//!
//!   * Streaming — full ITB streaming encrypt-then-wrap and
//!     unwrap-then-decrypt timed separately on a 64 MiB plaintext
//!     through 16 MiB chunks. 4 modes (AEAD Easy IO-Driven, AEAD
//!     Low-Level IO-Driven, No MAC Easy User-Driven Loop, No MAC
//!     Low-Level User-Driven Loop) × 3 ciphers × 2 directions = 24
//!     per Single, 24 per Triple = 48 sub-benches.
//!
//! Total: 6 + 48 + 48 = 102 sub-benches.
//!
//! Binding asymmetry — the Rust binding exposes Streaming AEAD
//! (`encrypt_stream_auth` / `decrypt_stream_auth`) but does NOT
//! expose a `Read` / `Write` adapter pair for the No MAC streaming
//! path. The Non-AEAD streaming arm therefore covers the User-Driven
//! Loop variant only (per-chunk encrypt + caller-side u32_LE
//! framing pushed through one wrap-stream session). See CLAUDE.md.
//!
//! Run with::
//!
//!     cargo bench --bench bench_wrapper
//!
//!     ITB_BENCH_FILTER=wrapper_only \
//!         cargo bench --bench bench_wrapper
//!
//!     ITB_BENCH_FILTER=msg_single_easy_nomac/aes/encrypt \
//!         cargo bench --bench bench_wrapper
//!
//! The harness emits one Go-bench-style line per case (name, iters,
//! ns/op, MB/s). See `common.rs` for the supported environment
//! variables and the convergence policy.

#[path = "common.rs"]
mod common;

use std::io::Cursor;

use itb::wrapper::{self, Cipher, UnwrapStreamReader, WrapStreamWriter};
use itb::{Encryptor, Seed, MAC};

use crate::common::{BenchCase, BenchFn};

const PRIMITIVE: &str = "areion512";
const KEY_BITS_SINGLE: i32 = 1024;
const KEY_BITS_TRIPLE: i32 = 1024;
const MAC_NAME: &str = "hmac-blake3";

const MESSAGE_BYTES: usize = 16 << 20;
const STREAM_TOTAL_BYTES: usize = 64 << 20;
const STREAM_CHUNK_BYTES: usize = 16 << 20;

const MAC_KEY: [u8; 32] = [
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
    0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00,
    0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80,
    0x90, 0xa0, 0xb0, 0xc0, 0xd0, 0xe0, 0xf0, 0x01,
];

const CIPHERS: [Cipher; 3] = [Cipher::Aes128Ctr, Cipher::ChaCha20, Cipher::SipHash24];

fn cipher_tag(c: Cipher) -> &'static str {
    match c {
        Cipher::Aes128Ctr => "aes",
        Cipher::ChaCha20 => "chacha",
        Cipher::SipHash24 => "siphash",
    }
}

// --------------------------------------------------------------------
// Builders shared across scopes
// --------------------------------------------------------------------

fn build_encryptor_single(mac: Option<&str>) -> Encryptor {
    Encryptor::new(Some(PRIMITIVE), Some(KEY_BITS_SINGLE), mac, 1)
        .unwrap_or_else(|e| panic!("Encryptor::new(single): {e:?}"))
}

fn build_encryptor_triple(mac: Option<&str>) -> Encryptor {
    Encryptor::new(Some(PRIMITIVE), Some(KEY_BITS_TRIPLE), mac, 3)
        .unwrap_or_else(|e| panic!("Encryptor::new(triple): {e:?}"))
}

fn build_seeds_single() -> [Seed; 3] {
    [
        Seed::new(PRIMITIVE, KEY_BITS_SINGLE).expect("Seed::new noise"),
        Seed::new(PRIMITIVE, KEY_BITS_SINGLE).expect("Seed::new data"),
        Seed::new(PRIMITIVE, KEY_BITS_SINGLE).expect("Seed::new start"),
    ]
}

fn build_seeds_triple() -> [Seed; 7] {
    [
        Seed::new(PRIMITIVE, KEY_BITS_TRIPLE).expect("Seed::new noise"),
        Seed::new(PRIMITIVE, KEY_BITS_TRIPLE).expect("Seed::new data1"),
        Seed::new(PRIMITIVE, KEY_BITS_TRIPLE).expect("Seed::new data2"),
        Seed::new(PRIMITIVE, KEY_BITS_TRIPLE).expect("Seed::new data3"),
        Seed::new(PRIMITIVE, KEY_BITS_TRIPLE).expect("Seed::new start1"),
        Seed::new(PRIMITIVE, KEY_BITS_TRIPLE).expect("Seed::new start2"),
        Seed::new(PRIMITIVE, KEY_BITS_TRIPLE).expect("Seed::new start3"),
    ]
}

fn build_mac() -> MAC {
    MAC::new(MAC_NAME, &MAC_KEY).expect("MAC::new")
}

// --------------------------------------------------------------------
// Scope 1 — wrapper only round-trip on a 16 MiB random buffer.
// --------------------------------------------------------------------

fn make_wrapper_only_alloc(cipher: Cipher) -> BenchCase {
    let key = wrapper::generate_key(cipher).expect("generate_key");
    let blob = common::random_bytes(MESSAGE_BYTES);
    let run: BenchFn = Box::new(move |iters: u64| {
        for _ in 0..iters {
            let wire = wrapper::wrap(cipher, &key, &blob).expect("wrap");
            let _ = wrapper::unwrap(cipher, &key, &wire).expect("unwrap");
        }
    });
    BenchCase {
        name: format!("bench_wrapper_only_alloc/{}", cipher_tag(cipher)),
        run,
        payload_bytes: MESSAGE_BYTES,
    }
}

fn make_wrapper_only_inplace(cipher: Cipher) -> BenchCase {
    let key = wrapper::generate_key(cipher).expect("generate_key");
    let blob = common::random_bytes(MESSAGE_BYTES);
    let run: BenchFn = Box::new(move |iters: u64| {
        for _ in 0..iters {
            let mut buf = blob.clone();
            let nonce = wrapper::wrap_in_place(cipher, &key, &mut buf).expect("wrap_in_place");
            // Compose wire = nonce || mutated body, then unwrap_in_place.
            let mut wire = nonce.clone();
            wire.extend_from_slice(&buf);
            let _ = wrapper::unwrap_in_place(cipher, &key, &mut wire).expect("unwrap_in_place");
        }
    });
    BenchCase {
        name: format!("bench_wrapper_only_inplace/{}", cipher_tag(cipher)),
        run,
        payload_bytes: MESSAGE_BYTES,
    }
}

// --------------------------------------------------------------------
// Scope 2 — Message benches, Single + Triple, 4 modes × 3 ciphers
// × 2 directions. Encrypt and Decrypt are SEPARATE sub-benches; the
// Decrypt body refreshes the working wire from a pristine clone each
// iter via Vec::clone() so the keystream XOR consumes a fresh copy.
// --------------------------------------------------------------------

fn make_msg_single_easy_nomac_encrypt(cipher: Cipher) -> BenchCase {
    let key = wrapper::generate_key(cipher).expect("generate_key");
    let payload = common::random_bytes(MESSAGE_BYTES);
    let run: BenchFn = Box::new(move |iters: u64| {
        let mut enc = build_encryptor_single(None);
        for _ in 0..iters {
            let mut ct = enc.encrypt(&payload).expect("encrypt");
            let _ = wrapper::wrap_in_place(cipher, &key, &mut ct).expect("wrap_in_place");
        }
    });
    BenchCase {
        name: format!(
            "bench_msg_single_easy_nomac/{}/encrypt",
            cipher_tag(cipher)
        ),
        run,
        payload_bytes: MESSAGE_BYTES,
    }
}

fn make_msg_single_easy_nomac_decrypt(cipher: Cipher) -> BenchCase {
    let key = wrapper::generate_key(cipher).expect("generate_key");
    let payload = common::random_bytes(MESSAGE_BYTES);
    // Pre-encrypt once outside the timer. Inside the loop, refresh
    // the wire from a pristine clone so the XOR consumes a fresh
    // buffer (the in-place path mutates it).
    let mut enc = build_encryptor_single(None);
    let pristine_wire = {
        let mut ct = enc.encrypt(&payload).expect("pre-encrypt");
        let nonce = wrapper::wrap_in_place(cipher, &key, &mut ct).expect("pre-wrap");
        let mut wire = nonce;
        wire.extend_from_slice(&ct);
        wire
    };
    let run: BenchFn = Box::new(move |iters: u64| {
        for _ in 0..iters {
            let mut wire = pristine_wire.clone();
            let body = wrapper::unwrap_in_place(cipher, &key, &mut wire).expect("unwrap_in_place");
            let _ = enc.decrypt(body).expect("decrypt");
        }
    });
    BenchCase {
        name: format!(
            "bench_msg_single_easy_nomac/{}/decrypt",
            cipher_tag(cipher)
        ),
        run,
        payload_bytes: MESSAGE_BYTES,
    }
}

fn make_msg_single_easy_auth_encrypt(cipher: Cipher) -> BenchCase {
    let key = wrapper::generate_key(cipher).expect("generate_key");
    let payload = common::random_bytes(MESSAGE_BYTES);
    let run: BenchFn = Box::new(move |iters: u64| {
        let mut enc = build_encryptor_single(Some(MAC_NAME));
        for _ in 0..iters {
            let mut ct = enc.encrypt_auth(&payload).expect("encrypt_auth");
            let _ = wrapper::wrap_in_place(cipher, &key, &mut ct).expect("wrap_in_place");
        }
    });
    BenchCase {
        name: format!(
            "bench_msg_single_easy_auth/{}/encrypt",
            cipher_tag(cipher)
        ),
        run,
        payload_bytes: MESSAGE_BYTES,
    }
}

fn make_msg_single_easy_auth_decrypt(cipher: Cipher) -> BenchCase {
    let key = wrapper::generate_key(cipher).expect("generate_key");
    let payload = common::random_bytes(MESSAGE_BYTES);
    let mut enc = build_encryptor_single(Some(MAC_NAME));
    let pristine_wire = {
        let mut ct = enc.encrypt_auth(&payload).expect("pre-encrypt_auth");
        let nonce = wrapper::wrap_in_place(cipher, &key, &mut ct).expect("pre-wrap");
        let mut wire = nonce;
        wire.extend_from_slice(&ct);
        wire
    };
    let run: BenchFn = Box::new(move |iters: u64| {
        for _ in 0..iters {
            let mut wire = pristine_wire.clone();
            let body = wrapper::unwrap_in_place(cipher, &key, &mut wire).expect("unwrap_in_place");
            let _ = enc.decrypt_auth(body).expect("decrypt_auth");
        }
    });
    BenchCase {
        name: format!(
            "bench_msg_single_easy_auth/{}/decrypt",
            cipher_tag(cipher)
        ),
        run,
        payload_bytes: MESSAGE_BYTES,
    }
}

fn make_msg_single_lowlevel_nomac_encrypt(cipher: Cipher) -> BenchCase {
    let key = wrapper::generate_key(cipher).expect("generate_key");
    let payload = common::random_bytes(MESSAGE_BYTES);
    let seeds = build_seeds_single();
    let run: BenchFn = Box::new(move |iters: u64| {
        for _ in 0..iters {
            let mut ct = itb::encrypt(&seeds[0], &seeds[1], &seeds[2], &payload).expect("encrypt");
            let _ = wrapper::wrap_in_place(cipher, &key, &mut ct).expect("wrap_in_place");
        }
    });
    BenchCase {
        name: format!(
            "bench_msg_single_lowlevel_nomac/{}/encrypt",
            cipher_tag(cipher)
        ),
        run,
        payload_bytes: MESSAGE_BYTES,
    }
}

fn make_msg_single_lowlevel_nomac_decrypt(cipher: Cipher) -> BenchCase {
    let key = wrapper::generate_key(cipher).expect("generate_key");
    let payload = common::random_bytes(MESSAGE_BYTES);
    let seeds = build_seeds_single();
    let pristine_wire = {
        let mut ct = itb::encrypt(&seeds[0], &seeds[1], &seeds[2], &payload).expect("pre-encrypt");
        let nonce = wrapper::wrap_in_place(cipher, &key, &mut ct).expect("pre-wrap");
        let mut wire = nonce;
        wire.extend_from_slice(&ct);
        wire
    };
    let run: BenchFn = Box::new(move |iters: u64| {
        for _ in 0..iters {
            let mut wire = pristine_wire.clone();
            let body = wrapper::unwrap_in_place(cipher, &key, &mut wire).expect("unwrap_in_place");
            let _ = itb::decrypt(&seeds[0], &seeds[1], &seeds[2], body).expect("decrypt");
        }
    });
    BenchCase {
        name: format!(
            "bench_msg_single_lowlevel_nomac/{}/decrypt",
            cipher_tag(cipher)
        ),
        run,
        payload_bytes: MESSAGE_BYTES,
    }
}

fn make_msg_single_lowlevel_auth_encrypt(cipher: Cipher) -> BenchCase {
    let key = wrapper::generate_key(cipher).expect("generate_key");
    let payload = common::random_bytes(MESSAGE_BYTES);
    let seeds = build_seeds_single();
    let mac = build_mac();
    let run: BenchFn = Box::new(move |iters: u64| {
        for _ in 0..iters {
            let mut ct = itb::encrypt_auth(&seeds[0], &seeds[1], &seeds[2], &mac, &payload)
                .expect("encrypt_auth");
            let _ = wrapper::wrap_in_place(cipher, &key, &mut ct).expect("wrap_in_place");
        }
    });
    BenchCase {
        name: format!(
            "bench_msg_single_lowlevel_auth/{}/encrypt",
            cipher_tag(cipher)
        ),
        run,
        payload_bytes: MESSAGE_BYTES,
    }
}

fn make_msg_single_lowlevel_auth_decrypt(cipher: Cipher) -> BenchCase {
    let key = wrapper::generate_key(cipher).expect("generate_key");
    let payload = common::random_bytes(MESSAGE_BYTES);
    let seeds = build_seeds_single();
    let mac = build_mac();
    let pristine_wire = {
        let mut ct = itb::encrypt_auth(&seeds[0], &seeds[1], &seeds[2], &mac, &payload)
            .expect("pre-encrypt_auth");
        let nonce = wrapper::wrap_in_place(cipher, &key, &mut ct).expect("pre-wrap");
        let mut wire = nonce;
        wire.extend_from_slice(&ct);
        wire
    };
    let run: BenchFn = Box::new(move |iters: u64| {
        for _ in 0..iters {
            let mut wire = pristine_wire.clone();
            let body = wrapper::unwrap_in_place(cipher, &key, &mut wire).expect("unwrap_in_place");
            let _ = itb::decrypt_auth(&seeds[0], &seeds[1], &seeds[2], &mac, body)
                .expect("decrypt_auth");
        }
    });
    BenchCase {
        name: format!(
            "bench_msg_single_lowlevel_auth/{}/decrypt",
            cipher_tag(cipher)
        ),
        run,
        payload_bytes: MESSAGE_BYTES,
    }
}

// Triple-Ouroboros message variants — same shape with 7-seed
// encrypt_triple / decrypt_triple / encrypt_auth_triple /
// decrypt_auth_triple plus mode=3 Encryptor.

fn make_msg_triple_easy_nomac_encrypt(cipher: Cipher) -> BenchCase {
    let key = wrapper::generate_key(cipher).expect("generate_key");
    let payload = common::random_bytes(MESSAGE_BYTES);
    let run: BenchFn = Box::new(move |iters: u64| {
        let mut enc = build_encryptor_triple(None);
        for _ in 0..iters {
            let mut ct = enc.encrypt(&payload).expect("encrypt");
            let _ = wrapper::wrap_in_place(cipher, &key, &mut ct).expect("wrap_in_place");
        }
    });
    BenchCase {
        name: format!(
            "bench_msg_triple_easy_nomac/{}/encrypt",
            cipher_tag(cipher)
        ),
        run,
        payload_bytes: MESSAGE_BYTES,
    }
}

fn make_msg_triple_easy_nomac_decrypt(cipher: Cipher) -> BenchCase {
    let key = wrapper::generate_key(cipher).expect("generate_key");
    let payload = common::random_bytes(MESSAGE_BYTES);
    let mut enc = build_encryptor_triple(None);
    let pristine_wire = {
        let mut ct = enc.encrypt(&payload).expect("pre-encrypt");
        let nonce = wrapper::wrap_in_place(cipher, &key, &mut ct).expect("pre-wrap");
        let mut wire = nonce;
        wire.extend_from_slice(&ct);
        wire
    };
    let run: BenchFn = Box::new(move |iters: u64| {
        for _ in 0..iters {
            let mut wire = pristine_wire.clone();
            let body = wrapper::unwrap_in_place(cipher, &key, &mut wire).expect("unwrap_in_place");
            let _ = enc.decrypt(body).expect("decrypt");
        }
    });
    BenchCase {
        name: format!(
            "bench_msg_triple_easy_nomac/{}/decrypt",
            cipher_tag(cipher)
        ),
        run,
        payload_bytes: MESSAGE_BYTES,
    }
}

fn make_msg_triple_easy_auth_encrypt(cipher: Cipher) -> BenchCase {
    let key = wrapper::generate_key(cipher).expect("generate_key");
    let payload = common::random_bytes(MESSAGE_BYTES);
    let run: BenchFn = Box::new(move |iters: u64| {
        let mut enc = build_encryptor_triple(Some(MAC_NAME));
        for _ in 0..iters {
            let mut ct = enc.encrypt_auth(&payload).expect("encrypt_auth");
            let _ = wrapper::wrap_in_place(cipher, &key, &mut ct).expect("wrap_in_place");
        }
    });
    BenchCase {
        name: format!(
            "bench_msg_triple_easy_auth/{}/encrypt",
            cipher_tag(cipher)
        ),
        run,
        payload_bytes: MESSAGE_BYTES,
    }
}

fn make_msg_triple_easy_auth_decrypt(cipher: Cipher) -> BenchCase {
    let key = wrapper::generate_key(cipher).expect("generate_key");
    let payload = common::random_bytes(MESSAGE_BYTES);
    let mut enc = build_encryptor_triple(Some(MAC_NAME));
    let pristine_wire = {
        let mut ct = enc.encrypt_auth(&payload).expect("pre-encrypt_auth");
        let nonce = wrapper::wrap_in_place(cipher, &key, &mut ct).expect("pre-wrap");
        let mut wire = nonce;
        wire.extend_from_slice(&ct);
        wire
    };
    let run: BenchFn = Box::new(move |iters: u64| {
        for _ in 0..iters {
            let mut wire = pristine_wire.clone();
            let body = wrapper::unwrap_in_place(cipher, &key, &mut wire).expect("unwrap_in_place");
            let _ = enc.decrypt_auth(body).expect("decrypt_auth");
        }
    });
    BenchCase {
        name: format!(
            "bench_msg_triple_easy_auth/{}/decrypt",
            cipher_tag(cipher)
        ),
        run,
        payload_bytes: MESSAGE_BYTES,
    }
}

fn make_msg_triple_lowlevel_nomac_encrypt(cipher: Cipher) -> BenchCase {
    let key = wrapper::generate_key(cipher).expect("generate_key");
    let payload = common::random_bytes(MESSAGE_BYTES);
    let s = build_seeds_triple();
    let run: BenchFn = Box::new(move |iters: u64| {
        for _ in 0..iters {
            let mut ct = itb::encrypt_triple(
                &s[0], &s[1], &s[2], &s[3], &s[4], &s[5], &s[6], &payload,
            )
            .expect("encrypt_triple");
            let _ = wrapper::wrap_in_place(cipher, &key, &mut ct).expect("wrap_in_place");
        }
    });
    BenchCase {
        name: format!(
            "bench_msg_triple_lowlevel_nomac/{}/encrypt",
            cipher_tag(cipher)
        ),
        run,
        payload_bytes: MESSAGE_BYTES,
    }
}

fn make_msg_triple_lowlevel_nomac_decrypt(cipher: Cipher) -> BenchCase {
    let key = wrapper::generate_key(cipher).expect("generate_key");
    let payload = common::random_bytes(MESSAGE_BYTES);
    let s = build_seeds_triple();
    let pristine_wire = {
        let mut ct = itb::encrypt_triple(
            &s[0], &s[1], &s[2], &s[3], &s[4], &s[5], &s[6], &payload,
        )
        .expect("pre-encrypt_triple");
        let nonce = wrapper::wrap_in_place(cipher, &key, &mut ct).expect("pre-wrap");
        let mut wire = nonce;
        wire.extend_from_slice(&ct);
        wire
    };
    let run: BenchFn = Box::new(move |iters: u64| {
        for _ in 0..iters {
            let mut wire = pristine_wire.clone();
            let body = wrapper::unwrap_in_place(cipher, &key, &mut wire).expect("unwrap_in_place");
            let _ = itb::decrypt_triple(
                &s[0], &s[1], &s[2], &s[3], &s[4], &s[5], &s[6], body,
            )
            .expect("decrypt_triple");
        }
    });
    BenchCase {
        name: format!(
            "bench_msg_triple_lowlevel_nomac/{}/decrypt",
            cipher_tag(cipher)
        ),
        run,
        payload_bytes: MESSAGE_BYTES,
    }
}

fn make_msg_triple_lowlevel_auth_encrypt(cipher: Cipher) -> BenchCase {
    let key = wrapper::generate_key(cipher).expect("generate_key");
    let payload = common::random_bytes(MESSAGE_BYTES);
    let s = build_seeds_triple();
    let mac = build_mac();
    let run: BenchFn = Box::new(move |iters: u64| {
        for _ in 0..iters {
            let mut ct = itb::encrypt_auth_triple(
                &s[0], &s[1], &s[2], &s[3], &s[4], &s[5], &s[6], &mac, &payload,
            )
            .expect("encrypt_auth_triple");
            let _ = wrapper::wrap_in_place(cipher, &key, &mut ct).expect("wrap_in_place");
        }
    });
    BenchCase {
        name: format!(
            "bench_msg_triple_lowlevel_auth/{}/encrypt",
            cipher_tag(cipher)
        ),
        run,
        payload_bytes: MESSAGE_BYTES,
    }
}

fn make_msg_triple_lowlevel_auth_decrypt(cipher: Cipher) -> BenchCase {
    let key = wrapper::generate_key(cipher).expect("generate_key");
    let payload = common::random_bytes(MESSAGE_BYTES);
    let s = build_seeds_triple();
    let mac = build_mac();
    let pristine_wire = {
        let mut ct = itb::encrypt_auth_triple(
            &s[0], &s[1], &s[2], &s[3], &s[4], &s[5], &s[6], &mac, &payload,
        )
        .expect("pre-encrypt_auth_triple");
        let nonce = wrapper::wrap_in_place(cipher, &key, &mut ct).expect("pre-wrap");
        let mut wire = nonce;
        wire.extend_from_slice(&ct);
        wire
    };
    let run: BenchFn = Box::new(move |iters: u64| {
        for _ in 0..iters {
            let mut wire = pristine_wire.clone();
            let body = wrapper::unwrap_in_place(cipher, &key, &mut wire).expect("unwrap_in_place");
            let _ = itb::decrypt_auth_triple(
                &s[0], &s[1], &s[2], &s[3], &s[4], &s[5], &s[6], &mac, body,
            )
            .expect("decrypt_auth_triple");
        }
    });
    BenchCase {
        name: format!(
            "bench_msg_triple_lowlevel_auth/{}/decrypt",
            cipher_tag(cipher)
        ),
        run,
        payload_bytes: MESSAGE_BYTES,
    }
}

// --------------------------------------------------------------------
// Scope 3 — Streaming benches.
//
// AEAD shape — driven by Encryptor::encrypt_stream_auth /
// decrypt_stream_auth (Easy) or itb::encrypt_stream_auth /
// decrypt_stream_auth (Low-Level), with the entire bytestream
// piped through one WrapStreamWriter / UnwrapStreamReader session.
//
// User-Driven Loop — per-chunk encrypt + caller-side u32_LE framing
// emitted through one wrap-stream session so framing bytes XOR
// through alongside the chunk bodies.
// --------------------------------------------------------------------

fn streaming_easy_aead_encrypt(cipher: Cipher, plaintext: &[u8], key: &[u8], enc: &mut Encryptor) -> Vec<u8> {
    let mut inner: Vec<u8> = Vec::with_capacity(plaintext.len() + 4096);
    enc.encrypt_stream_auth(Cursor::new(plaintext), &mut inner, STREAM_CHUNK_BYTES)
        .expect("encrypt_stream_auth");
    let mut writer = WrapStreamWriter::new(cipher, key).expect("WrapStreamWriter::new");
    let mut wire = writer.nonce().to_vec();
    wire.extend_from_slice(&writer.update(&inner).expect("wrap update"));
    writer.close().expect("wrap close");
    wire
}

fn streaming_easy_aead_decrypt(
    cipher: Cipher,
    wire: &[u8],
    key: &[u8],
    enc: &mut Encryptor,
) -> Vec<u8> {
    let nlen = wrapper::nonce_size(cipher).expect("nonce_size");
    let mut reader = UnwrapStreamReader::new(cipher, key, &wire[..nlen]).expect("reader");
    let inner = reader.update(&wire[nlen..]).expect("unwrap update");
    reader.close().expect("unwrap close");
    let mut out: Vec<u8> = Vec::with_capacity(wire.len());
    enc.decrypt_stream_auth(Cursor::new(inner), &mut out, STREAM_CHUNK_BYTES)
        .expect("decrypt_stream_auth");
    out
}

fn streaming_lowlevel_aead_encrypt(
    cipher: Cipher,
    plaintext: &[u8],
    key: &[u8],
    seeds: &[Seed],
    mac: &MAC,
) -> Vec<u8> {
    let mut inner: Vec<u8> = Vec::with_capacity(plaintext.len() + 4096);
    itb::encrypt_stream_auth(
        &seeds[0], &seeds[1], &seeds[2], mac,
        Cursor::new(plaintext), &mut inner, STREAM_CHUNK_BYTES,
    )
    .expect("encrypt_stream_auth");
    let mut writer = WrapStreamWriter::new(cipher, key).expect("WrapStreamWriter::new");
    let mut wire = writer.nonce().to_vec();
    wire.extend_from_slice(&writer.update(&inner).expect("wrap update"));
    writer.close().expect("wrap close");
    wire
}

fn streaming_lowlevel_aead_decrypt(
    cipher: Cipher,
    wire: &[u8],
    key: &[u8],
    seeds: &[Seed],
    mac: &MAC,
) -> Vec<u8> {
    let nlen = wrapper::nonce_size(cipher).expect("nonce_size");
    let mut reader = UnwrapStreamReader::new(cipher, key, &wire[..nlen]).expect("reader");
    let inner = reader.update(&wire[nlen..]).expect("unwrap update");
    reader.close().expect("unwrap close");
    let mut out: Vec<u8> = Vec::with_capacity(wire.len());
    itb::decrypt_stream_auth(
        &seeds[0], &seeds[1], &seeds[2], mac,
        Cursor::new(inner), &mut out, STREAM_CHUNK_BYTES,
    )
    .expect("decrypt_stream_auth");
    out
}

fn streaming_easy_userloop_encrypt(
    cipher: Cipher,
    plaintext: &[u8],
    key: &[u8],
    enc: &mut Encryptor,
) -> Vec<u8> {
    let mut writer = WrapStreamWriter::new(cipher, key).expect("WrapStreamWriter::new");
    let mut wire = writer.nonce().to_vec();
    let mut off = 0;
    while off < plaintext.len() {
        let take = std::cmp::min(STREAM_CHUNK_BYTES, plaintext.len() - off);
        let ct = enc.encrypt(&plaintext[off..off + take]).expect("encrypt");
        let len_le = (ct.len() as u32).to_le_bytes();
        wire.extend_from_slice(&writer.update(&len_le).expect("wrap update len"));
        wire.extend_from_slice(&writer.update(&ct).expect("wrap update ct"));
        off += take;
    }
    writer.close().expect("wrap close");
    wire
}

fn streaming_easy_userloop_decrypt(
    cipher: Cipher,
    wire: &[u8],
    key: &[u8],
    enc: &mut Encryptor,
) -> Vec<u8> {
    let nlen = wrapper::nonce_size(cipher).expect("nonce_size");
    let mut reader = UnwrapStreamReader::new(cipher, key, &wire[..nlen]).expect("reader");
    let decrypted = reader.update(&wire[nlen..]).expect("unwrap update");
    reader.close().expect("unwrap close");
    let mut out: Vec<u8> = Vec::with_capacity(wire.len());
    let mut pos = 0;
    while pos < decrypted.len() {
        let clen = u32::from_le_bytes(decrypted[pos..pos + 4].try_into().unwrap()) as usize;
        pos += 4;
        let ct = &decrypted[pos..pos + clen];
        pos += clen;
        let pt = enc.decrypt(ct).expect("decrypt");
        out.extend_from_slice(&pt);
    }
    out
}

fn streaming_lowlevel_userloop_encrypt(
    cipher: Cipher,
    plaintext: &[u8],
    key: &[u8],
    seeds: &[Seed],
) -> Vec<u8> {
    let mut writer = WrapStreamWriter::new(cipher, key).expect("WrapStreamWriter::new");
    let mut wire = writer.nonce().to_vec();
    let mut off = 0;
    while off < plaintext.len() {
        let take = std::cmp::min(STREAM_CHUNK_BYTES, plaintext.len() - off);
        let ct = itb::encrypt(&seeds[0], &seeds[1], &seeds[2], &plaintext[off..off + take])
            .expect("encrypt");
        let len_le = (ct.len() as u32).to_le_bytes();
        wire.extend_from_slice(&writer.update(&len_le).expect("wrap update len"));
        wire.extend_from_slice(&writer.update(&ct).expect("wrap update ct"));
        off += take;
    }
    writer.close().expect("wrap close");
    wire
}

fn streaming_lowlevel_userloop_decrypt(
    cipher: Cipher,
    wire: &[u8],
    key: &[u8],
    seeds: &[Seed],
) -> Vec<u8> {
    let nlen = wrapper::nonce_size(cipher).expect("nonce_size");
    let mut reader = UnwrapStreamReader::new(cipher, key, &wire[..nlen]).expect("reader");
    let decrypted = reader.update(&wire[nlen..]).expect("unwrap update");
    reader.close().expect("unwrap close");
    let mut out: Vec<u8> = Vec::with_capacity(wire.len());
    let mut pos = 0;
    while pos < decrypted.len() {
        let clen = u32::from_le_bytes(decrypted[pos..pos + 4].try_into().unwrap()) as usize;
        pos += 4;
        let ct = &decrypted[pos..pos + clen];
        pos += clen;
        let pt = itb::decrypt(&seeds[0], &seeds[1], &seeds[2], ct).expect("decrypt");
        out.extend_from_slice(&pt);
    }
    out
}

// Streaming benches — Single Ouroboros, AEAD Easy IO-Driven.

fn make_stream_single_aead_easy_io_encrypt(cipher: Cipher) -> BenchCase {
    let key = wrapper::generate_key(cipher).expect("generate_key");
    let payload = common::random_bytes(STREAM_TOTAL_BYTES);
    let run: BenchFn = Box::new(move |iters: u64| {
        let mut enc = build_encryptor_single(Some(MAC_NAME));
        for _ in 0..iters {
            let _ = streaming_easy_aead_encrypt(cipher, &payload, &key, &mut enc);
        }
    });
    BenchCase {
        name: format!(
            "bench_stream_single_aead_easy_io/{}/encrypt",
            cipher_tag(cipher)
        ),
        run,
        payload_bytes: STREAM_TOTAL_BYTES,
    }
}

fn make_stream_single_aead_easy_io_decrypt(cipher: Cipher) -> BenchCase {
    let key = wrapper::generate_key(cipher).expect("generate_key");
    let payload = common::random_bytes(STREAM_TOTAL_BYTES);
    let mut enc = build_encryptor_single(Some(MAC_NAME));
    let pristine_wire = streaming_easy_aead_encrypt(cipher, &payload, &key, &mut enc);
    let run: BenchFn = Box::new(move |iters: u64| {
        for _ in 0..iters {
            let _ = streaming_easy_aead_decrypt(cipher, &pristine_wire, &key, &mut enc);
        }
    });
    BenchCase {
        name: format!(
            "bench_stream_single_aead_easy_io/{}/decrypt",
            cipher_tag(cipher)
        ),
        run,
        payload_bytes: STREAM_TOTAL_BYTES,
    }
}

fn make_stream_single_aead_lowlevel_io_encrypt(cipher: Cipher) -> BenchCase {
    let key = wrapper::generate_key(cipher).expect("generate_key");
    let payload = common::random_bytes(STREAM_TOTAL_BYTES);
    let seeds = build_seeds_single();
    let mac = build_mac();
    let run: BenchFn = Box::new(move |iters: u64| {
        for _ in 0..iters {
            let _ = streaming_lowlevel_aead_encrypt(cipher, &payload, &key, &seeds, &mac);
        }
    });
    BenchCase {
        name: format!(
            "bench_stream_single_aead_lowlevel_io/{}/encrypt",
            cipher_tag(cipher)
        ),
        run,
        payload_bytes: STREAM_TOTAL_BYTES,
    }
}

fn make_stream_single_aead_lowlevel_io_decrypt(cipher: Cipher) -> BenchCase {
    let key = wrapper::generate_key(cipher).expect("generate_key");
    let payload = common::random_bytes(STREAM_TOTAL_BYTES);
    let seeds = build_seeds_single();
    let mac = build_mac();
    let pristine_wire = streaming_lowlevel_aead_encrypt(cipher, &payload, &key, &seeds, &mac);
    let run: BenchFn = Box::new(move |iters: u64| {
        for _ in 0..iters {
            let _ =
                streaming_lowlevel_aead_decrypt(cipher, &pristine_wire, &key, &seeds, &mac);
        }
    });
    BenchCase {
        name: format!(
            "bench_stream_single_aead_lowlevel_io/{}/decrypt",
            cipher_tag(cipher)
        ),
        run,
        payload_bytes: STREAM_TOTAL_BYTES,
    }
}

fn make_stream_single_noaead_easy_userloop_encrypt(cipher: Cipher) -> BenchCase {
    let key = wrapper::generate_key(cipher).expect("generate_key");
    let payload = common::random_bytes(STREAM_TOTAL_BYTES);
    let run: BenchFn = Box::new(move |iters: u64| {
        let mut enc = build_encryptor_single(None);
        for _ in 0..iters {
            let _ = streaming_easy_userloop_encrypt(cipher, &payload, &key, &mut enc);
        }
    });
    BenchCase {
        name: format!(
            "bench_stream_single_noaead_easy_userloop/{}/encrypt",
            cipher_tag(cipher)
        ),
        run,
        payload_bytes: STREAM_TOTAL_BYTES,
    }
}

fn make_stream_single_noaead_easy_userloop_decrypt(cipher: Cipher) -> BenchCase {
    let key = wrapper::generate_key(cipher).expect("generate_key");
    let payload = common::random_bytes(STREAM_TOTAL_BYTES);
    let mut enc = build_encryptor_single(None);
    let pristine_wire = streaming_easy_userloop_encrypt(cipher, &payload, &key, &mut enc);
    let run: BenchFn = Box::new(move |iters: u64| {
        for _ in 0..iters {
            let _ = streaming_easy_userloop_decrypt(cipher, &pristine_wire, &key, &mut enc);
        }
    });
    BenchCase {
        name: format!(
            "bench_stream_single_noaead_easy_userloop/{}/decrypt",
            cipher_tag(cipher)
        ),
        run,
        payload_bytes: STREAM_TOTAL_BYTES,
    }
}

fn make_stream_single_noaead_lowlevel_userloop_encrypt(cipher: Cipher) -> BenchCase {
    let key = wrapper::generate_key(cipher).expect("generate_key");
    let payload = common::random_bytes(STREAM_TOTAL_BYTES);
    let seeds = build_seeds_single();
    let run: BenchFn = Box::new(move |iters: u64| {
        for _ in 0..iters {
            let _ = streaming_lowlevel_userloop_encrypt(cipher, &payload, &key, &seeds);
        }
    });
    BenchCase {
        name: format!(
            "bench_stream_single_noaead_lowlevel_userloop/{}/encrypt",
            cipher_tag(cipher)
        ),
        run,
        payload_bytes: STREAM_TOTAL_BYTES,
    }
}

fn make_stream_single_noaead_lowlevel_userloop_decrypt(cipher: Cipher) -> BenchCase {
    let key = wrapper::generate_key(cipher).expect("generate_key");
    let payload = common::random_bytes(STREAM_TOTAL_BYTES);
    let seeds = build_seeds_single();
    let pristine_wire = streaming_lowlevel_userloop_encrypt(cipher, &payload, &key, &seeds);
    let run: BenchFn = Box::new(move |iters: u64| {
        for _ in 0..iters {
            let _ = streaming_lowlevel_userloop_decrypt(cipher, &pristine_wire, &key, &seeds);
        }
    });
    BenchCase {
        name: format!(
            "bench_stream_single_noaead_lowlevel_userloop/{}/decrypt",
            cipher_tag(cipher)
        ),
        run,
        payload_bytes: STREAM_TOTAL_BYTES,
    }
}

// Streaming Triple variants — same shape with mode=3 / 7-seed paths.

fn make_stream_triple_aead_easy_io_encrypt(cipher: Cipher) -> BenchCase {
    let key = wrapper::generate_key(cipher).expect("generate_key");
    let payload = common::random_bytes(STREAM_TOTAL_BYTES);
    let run: BenchFn = Box::new(move |iters: u64| {
        let mut enc = build_encryptor_triple(Some(MAC_NAME));
        for _ in 0..iters {
            let _ = streaming_easy_aead_encrypt(cipher, &payload, &key, &mut enc);
        }
    });
    BenchCase {
        name: format!(
            "bench_stream_triple_aead_easy_io/{}/encrypt",
            cipher_tag(cipher)
        ),
        run,
        payload_bytes: STREAM_TOTAL_BYTES,
    }
}

fn make_stream_triple_aead_easy_io_decrypt(cipher: Cipher) -> BenchCase {
    let key = wrapper::generate_key(cipher).expect("generate_key");
    let payload = common::random_bytes(STREAM_TOTAL_BYTES);
    let mut enc = build_encryptor_triple(Some(MAC_NAME));
    let pristine_wire = streaming_easy_aead_encrypt(cipher, &payload, &key, &mut enc);
    let run: BenchFn = Box::new(move |iters: u64| {
        for _ in 0..iters {
            let _ = streaming_easy_aead_decrypt(cipher, &pristine_wire, &key, &mut enc);
        }
    });
    BenchCase {
        name: format!(
            "bench_stream_triple_aead_easy_io/{}/decrypt",
            cipher_tag(cipher)
        ),
        run,
        payload_bytes: STREAM_TOTAL_BYTES,
    }
}

fn streaming_lowlevel_aead_triple_encrypt(
    cipher: Cipher,
    plaintext: &[u8],
    key: &[u8],
    seeds: &[Seed],
    mac: &MAC,
) -> Vec<u8> {
    let mut inner: Vec<u8> = Vec::with_capacity(plaintext.len() + 4096);
    itb::encrypt_stream_auth_triple(
        &seeds[0], &seeds[1], &seeds[2], &seeds[3],
        &seeds[4], &seeds[5], &seeds[6], mac,
        Cursor::new(plaintext), &mut inner, STREAM_CHUNK_BYTES,
    )
    .expect("encrypt_stream_auth_triple");
    let mut writer = WrapStreamWriter::new(cipher, key).expect("WrapStreamWriter::new");
    let mut wire = writer.nonce().to_vec();
    wire.extend_from_slice(&writer.update(&inner).expect("wrap update"));
    writer.close().expect("wrap close");
    wire
}

fn streaming_lowlevel_aead_triple_decrypt(
    cipher: Cipher,
    wire: &[u8],
    key: &[u8],
    seeds: &[Seed],
    mac: &MAC,
) -> Vec<u8> {
    let nlen = wrapper::nonce_size(cipher).expect("nonce_size");
    let mut reader = UnwrapStreamReader::new(cipher, key, &wire[..nlen]).expect("reader");
    let inner = reader.update(&wire[nlen..]).expect("unwrap update");
    reader.close().expect("unwrap close");
    let mut out: Vec<u8> = Vec::with_capacity(wire.len());
    itb::decrypt_stream_auth_triple(
        &seeds[0], &seeds[1], &seeds[2], &seeds[3],
        &seeds[4], &seeds[5], &seeds[6], mac,
        Cursor::new(inner), &mut out, STREAM_CHUNK_BYTES,
    )
    .expect("decrypt_stream_auth_triple");
    out
}

fn make_stream_triple_aead_lowlevel_io_encrypt(cipher: Cipher) -> BenchCase {
    let key = wrapper::generate_key(cipher).expect("generate_key");
    let payload = common::random_bytes(STREAM_TOTAL_BYTES);
    let seeds = build_seeds_triple();
    let mac = build_mac();
    let run: BenchFn = Box::new(move |iters: u64| {
        for _ in 0..iters {
            let _ = streaming_lowlevel_aead_triple_encrypt(cipher, &payload, &key, &seeds, &mac);
        }
    });
    BenchCase {
        name: format!(
            "bench_stream_triple_aead_lowlevel_io/{}/encrypt",
            cipher_tag(cipher)
        ),
        run,
        payload_bytes: STREAM_TOTAL_BYTES,
    }
}

fn make_stream_triple_aead_lowlevel_io_decrypt(cipher: Cipher) -> BenchCase {
    let key = wrapper::generate_key(cipher).expect("generate_key");
    let payload = common::random_bytes(STREAM_TOTAL_BYTES);
    let seeds = build_seeds_triple();
    let mac = build_mac();
    let pristine_wire = streaming_lowlevel_aead_triple_encrypt(cipher, &payload, &key, &seeds, &mac);
    let run: BenchFn = Box::new(move |iters: u64| {
        for _ in 0..iters {
            let _ = streaming_lowlevel_aead_triple_decrypt(
                cipher, &pristine_wire, &key, &seeds, &mac,
            );
        }
    });
    BenchCase {
        name: format!(
            "bench_stream_triple_aead_lowlevel_io/{}/decrypt",
            cipher_tag(cipher)
        ),
        run,
        payload_bytes: STREAM_TOTAL_BYTES,
    }
}

fn make_stream_triple_noaead_easy_userloop_encrypt(cipher: Cipher) -> BenchCase {
    let key = wrapper::generate_key(cipher).expect("generate_key");
    let payload = common::random_bytes(STREAM_TOTAL_BYTES);
    let run: BenchFn = Box::new(move |iters: u64| {
        let mut enc = build_encryptor_triple(None);
        for _ in 0..iters {
            let _ = streaming_easy_userloop_encrypt(cipher, &payload, &key, &mut enc);
        }
    });
    BenchCase {
        name: format!(
            "bench_stream_triple_noaead_easy_userloop/{}/encrypt",
            cipher_tag(cipher)
        ),
        run,
        payload_bytes: STREAM_TOTAL_BYTES,
    }
}

fn make_stream_triple_noaead_easy_userloop_decrypt(cipher: Cipher) -> BenchCase {
    let key = wrapper::generate_key(cipher).expect("generate_key");
    let payload = common::random_bytes(STREAM_TOTAL_BYTES);
    let mut enc = build_encryptor_triple(None);
    let pristine_wire = streaming_easy_userloop_encrypt(cipher, &payload, &key, &mut enc);
    let run: BenchFn = Box::new(move |iters: u64| {
        for _ in 0..iters {
            let _ = streaming_easy_userloop_decrypt(cipher, &pristine_wire, &key, &mut enc);
        }
    });
    BenchCase {
        name: format!(
            "bench_stream_triple_noaead_easy_userloop/{}/decrypt",
            cipher_tag(cipher)
        ),
        run,
        payload_bytes: STREAM_TOTAL_BYTES,
    }
}

fn streaming_lowlevel_userloop_triple_encrypt(
    cipher: Cipher,
    plaintext: &[u8],
    key: &[u8],
    seeds: &[Seed],
) -> Vec<u8> {
    let mut writer = WrapStreamWriter::new(cipher, key).expect("WrapStreamWriter::new");
    let mut wire = writer.nonce().to_vec();
    let mut off = 0;
    while off < plaintext.len() {
        let take = std::cmp::min(STREAM_CHUNK_BYTES, plaintext.len() - off);
        let ct = itb::encrypt_triple(
            &seeds[0], &seeds[1], &seeds[2], &seeds[3],
            &seeds[4], &seeds[5], &seeds[6],
            &plaintext[off..off + take],
        )
        .expect("encrypt_triple");
        let len_le = (ct.len() as u32).to_le_bytes();
        wire.extend_from_slice(&writer.update(&len_le).expect("wrap update len"));
        wire.extend_from_slice(&writer.update(&ct).expect("wrap update ct"));
        off += take;
    }
    writer.close().expect("wrap close");
    wire
}

fn streaming_lowlevel_userloop_triple_decrypt(
    cipher: Cipher,
    wire: &[u8],
    key: &[u8],
    seeds: &[Seed],
) -> Vec<u8> {
    let nlen = wrapper::nonce_size(cipher).expect("nonce_size");
    let mut reader = UnwrapStreamReader::new(cipher, key, &wire[..nlen]).expect("reader");
    let decrypted = reader.update(&wire[nlen..]).expect("unwrap update");
    reader.close().expect("unwrap close");
    let mut out: Vec<u8> = Vec::with_capacity(wire.len());
    let mut pos = 0;
    while pos < decrypted.len() {
        let clen = u32::from_le_bytes(decrypted[pos..pos + 4].try_into().unwrap()) as usize;
        pos += 4;
        let ct = &decrypted[pos..pos + clen];
        pos += clen;
        let pt = itb::decrypt_triple(
            &seeds[0], &seeds[1], &seeds[2], &seeds[3],
            &seeds[4], &seeds[5], &seeds[6], ct,
        )
        .expect("decrypt_triple");
        out.extend_from_slice(&pt);
    }
    out
}

fn make_stream_triple_noaead_lowlevel_userloop_encrypt(cipher: Cipher) -> BenchCase {
    let key = wrapper::generate_key(cipher).expect("generate_key");
    let payload = common::random_bytes(STREAM_TOTAL_BYTES);
    let seeds = build_seeds_triple();
    let run: BenchFn = Box::new(move |iters: u64| {
        for _ in 0..iters {
            let _ = streaming_lowlevel_userloop_triple_encrypt(cipher, &payload, &key, &seeds);
        }
    });
    BenchCase {
        name: format!(
            "bench_stream_triple_noaead_lowlevel_userloop/{}/encrypt",
            cipher_tag(cipher)
        ),
        run,
        payload_bytes: STREAM_TOTAL_BYTES,
    }
}

fn make_stream_triple_noaead_lowlevel_userloop_decrypt(cipher: Cipher) -> BenchCase {
    let key = wrapper::generate_key(cipher).expect("generate_key");
    let payload = common::random_bytes(STREAM_TOTAL_BYTES);
    let seeds = build_seeds_triple();
    let pristine_wire = streaming_lowlevel_userloop_triple_encrypt(cipher, &payload, &key, &seeds);
    let run: BenchFn = Box::new(move |iters: u64| {
        for _ in 0..iters {
            let _ = streaming_lowlevel_userloop_triple_decrypt(
                cipher, &pristine_wire, &key, &seeds,
            );
        }
    });
    BenchCase {
        name: format!(
            "bench_stream_triple_noaead_lowlevel_userloop/{}/decrypt",
            cipher_tag(cipher)
        ),
        run,
        payload_bytes: STREAM_TOTAL_BYTES,
    }
}

// --------------------------------------------------------------------
// Case assembly
// --------------------------------------------------------------------

fn build_cases() -> Vec<BenchCase> {
    let mut cases: Vec<BenchCase> = Vec::with_capacity(102);

    // Wrapper Only — 6 cases.
    for c in CIPHERS {
        cases.push(make_wrapper_only_alloc(c));
        cases.push(make_wrapper_only_inplace(c));
    }

    // Message Single — 24 cases (4 modes × 3 ciphers × 2 dirs).
    for c in CIPHERS {
        cases.push(make_msg_single_easy_nomac_encrypt(c));
        cases.push(make_msg_single_easy_nomac_decrypt(c));
        cases.push(make_msg_single_easy_auth_encrypt(c));
        cases.push(make_msg_single_easy_auth_decrypt(c));
        cases.push(make_msg_single_lowlevel_nomac_encrypt(c));
        cases.push(make_msg_single_lowlevel_nomac_decrypt(c));
        cases.push(make_msg_single_lowlevel_auth_encrypt(c));
        cases.push(make_msg_single_lowlevel_auth_decrypt(c));
    }

    // Message Triple — 24 cases.
    for c in CIPHERS {
        cases.push(make_msg_triple_easy_nomac_encrypt(c));
        cases.push(make_msg_triple_easy_nomac_decrypt(c));
        cases.push(make_msg_triple_easy_auth_encrypt(c));
        cases.push(make_msg_triple_easy_auth_decrypt(c));
        cases.push(make_msg_triple_lowlevel_nomac_encrypt(c));
        cases.push(make_msg_triple_lowlevel_nomac_decrypt(c));
        cases.push(make_msg_triple_lowlevel_auth_encrypt(c));
        cases.push(make_msg_triple_lowlevel_auth_decrypt(c));
    }

    // Streaming Single — 24 cases (4 modes × 3 ciphers × 2 dirs).
    for c in CIPHERS {
        cases.push(make_stream_single_aead_easy_io_encrypt(c));
        cases.push(make_stream_single_aead_easy_io_decrypt(c));
        cases.push(make_stream_single_aead_lowlevel_io_encrypt(c));
        cases.push(make_stream_single_aead_lowlevel_io_decrypt(c));
        cases.push(make_stream_single_noaead_easy_userloop_encrypt(c));
        cases.push(make_stream_single_noaead_easy_userloop_decrypt(c));
        cases.push(make_stream_single_noaead_lowlevel_userloop_encrypt(c));
        cases.push(make_stream_single_noaead_lowlevel_userloop_decrypt(c));
    }

    // Streaming Triple — 24 cases.
    for c in CIPHERS {
        cases.push(make_stream_triple_aead_easy_io_encrypt(c));
        cases.push(make_stream_triple_aead_easy_io_decrypt(c));
        cases.push(make_stream_triple_aead_lowlevel_io_encrypt(c));
        cases.push(make_stream_triple_aead_lowlevel_io_decrypt(c));
        cases.push(make_stream_triple_noaead_easy_userloop_encrypt(c));
        cases.push(make_stream_triple_noaead_easy_userloop_decrypt(c));
        cases.push(make_stream_triple_noaead_lowlevel_userloop_encrypt(c));
        cases.push(make_stream_triple_noaead_lowlevel_userloop_decrypt(c));
    }

    cases
}

fn main() {
    let nonce_bits = common::env_nonce_bits(128);
    itb::set_max_workers(0).expect("set_max_workers(0)");
    itb::set_nonce_bits(nonce_bits).expect("set_nonce_bits");

    let cases = build_cases();
    println!(
        "# wrapper benchmarks={} primitive={} key_bits_single={} key_bits_triple={} mac={} nonce_bits={}",
        cases.len(),
        PRIMITIVE,
        KEY_BITS_SINGLE,
        KEY_BITS_TRIPLE,
        MAC_NAME,
        nonce_bits,
    );

    common::run_all(cases);
}
