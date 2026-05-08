//! Round-trip tests across all nonce-size configurations.
//!
//! ITB exposes a runtime-configurable nonce size ([`itb::set_nonce_bits`])
//! that takes one of {128, 256, 512}. The on-the-wire chunk header
//! therefore varies between 20, 36, and 68 bytes; every consumer that
//! walks ciphertext on the byte level (chunk parsers, tampering tests,
//! streaming decoders) must use [`itb::header_size`] rather than a
//! hardcoded constant.
//!
//! This file mirrors `bindings/python/tests/test_nonce_sizes.py` and
//! exhaustively covers the FFI surface under each nonce configuration:
//!   - one-shot encrypt / decrypt (Single + Triple);
//!   - authenticated encrypt / decrypt (Single + Triple), including
//!     tamper rejection at the dynamic header offset;
//!   - parse_chunk_len reporting the right chunk length.
//!
//! Each test snapshots the original nonce setting on entry and restores
//! it on exit so subsequent suites run unaffected. Every test takes the
//! shared [`common::serial_lock`] because [`itb::set_nonce_bits`] is a
//! process-global mutation.

use itb::{MAC, Seed};

#[path = "common/mod.rs"]
mod common;

const NONCE_SIZES: &[i32] = &[128, 256, 512];
const HASHES: &[&str] = &["siphash24", "blake3", "blake2b512"];
const MAC_NAMES: &[&str] = &["kmac256", "hmac-sha256", "hmac-blake3"];
const MAC_KEY: [u8; 32] = [0x73u8; 32];

fn pseudo_plaintext(n: usize) -> Vec<u8> {
    (0..n).map(|i| ((i * 31 + 7) & 0xff) as u8).collect()
}

/// Snapshots the current nonce_bits, sets `n` for the test body, and
/// restores the prior value on exit.
fn with_nonce_bits<F: FnOnce()>(n: i32, body: F) {
    let prev = itb::get_nonce_bits();
    itb::set_nonce_bits(n).unwrap();
    body();
    itb::set_nonce_bits(prev).unwrap();
}

#[test]
fn test_default_is_20() {
    let _g = common::serial_lock();
    let prev = itb::get_nonce_bits();
    itb::set_nonce_bits(128).unwrap();
    assert_eq!(itb::header_size(), 20);
    assert_eq!(itb::get_nonce_bits(), 128);
    itb::set_nonce_bits(prev).unwrap();
}

#[test]
fn test_header_size_dynamic() {
    let _g = common::serial_lock();
    for &n in NONCE_SIZES {
        with_nonce_bits(n, || {
            assert_eq!(itb::header_size(), n / 8 + 4, "nonce={}", n);
        });
    }
}

#[test]
fn test_encrypt_decrypt_across_nonce_sizes() {
    let _g = common::serial_lock();
    let plaintext = pseudo_plaintext(1024);
    for &n in NONCE_SIZES {
        for hash_name in HASHES {
            with_nonce_bits(n, || {
                let ns = Seed::new(hash_name, 1024).unwrap();
                let ds = Seed::new(hash_name, 1024).unwrap();
                let ss = Seed::new(hash_name, 1024).unwrap();
                let ct = itb::encrypt(&ns, &ds, &ss, &plaintext).unwrap();
                let pt = itb::decrypt(&ns, &ds, &ss, &ct).unwrap();
                assert_eq!(pt, plaintext, "nonce={} hash={}", n, hash_name);
                // parse_chunk_len must report the full chunk length.
                let h = itb::header_size() as usize;
                let chunk_len = itb::parse_chunk_len(&ct[..h]).unwrap();
                assert_eq!(chunk_len, ct.len(), "nonce={} hash={}", n, hash_name);
            });
        }
    }
}

#[test]
fn test_triple_encrypt_decrypt_across_nonce_sizes() {
    let _g = common::serial_lock();
    let plaintext = pseudo_plaintext(1024);
    for &n in NONCE_SIZES {
        for hash_name in HASHES {
            with_nonce_bits(n, || {
                let s0 = Seed::new(hash_name, 1024).unwrap();
                let s1 = Seed::new(hash_name, 1024).unwrap();
                let s2 = Seed::new(hash_name, 1024).unwrap();
                let s3 = Seed::new(hash_name, 1024).unwrap();
                let s4 = Seed::new(hash_name, 1024).unwrap();
                let s5 = Seed::new(hash_name, 1024).unwrap();
                let s6 = Seed::new(hash_name, 1024).unwrap();
                let ct = itb::encrypt_triple(
                    &s0, &s1, &s2, &s3, &s4, &s5, &s6, &plaintext,
                )
                .unwrap();
                let pt = itb::decrypt_triple(
                    &s0, &s1, &s2, &s3, &s4, &s5, &s6, &ct,
                )
                .unwrap();
                assert_eq!(pt, plaintext, "nonce={} hash={}", n, hash_name);
            });
        }
    }
}

#[test]
fn test_auth_across_nonce_sizes() {
    let _g = common::serial_lock();
    let plaintext = pseudo_plaintext(1024);
    for &n in NONCE_SIZES {
        for mac_name in MAC_NAMES {
            with_nonce_bits(n, || {
                let mac = MAC::new(mac_name, &MAC_KEY).unwrap();
                let ns = Seed::new("blake3", 1024).unwrap();
                let ds = Seed::new("blake3", 1024).unwrap();
                let ss = Seed::new("blake3", 1024).unwrap();
                let ct = itb::encrypt_auth(&ns, &ds, &ss, &mac, &plaintext).unwrap();
                let pt = itb::decrypt_auth(&ns, &ds, &ss, &mac, &ct).unwrap();
                assert_eq!(pt, plaintext, "nonce={} mac={}", n, mac_name);

                let mut tampered = ct.clone();
                let h = itb::header_size() as usize;
                let upper = std::cmp::min(h + 256, tampered.len());
                for b in &mut tampered[h..upper] {
                    *b ^= 0x01;
                }
                let err = itb::decrypt_auth(&ns, &ds, &ss, &mac, &tampered).unwrap_err();
                assert_eq!(err.code(), itb::STATUS_MAC_FAILURE);
            });
        }
    }
}

#[test]
fn test_triple_auth_across_nonce_sizes() {
    let _g = common::serial_lock();
    let plaintext = pseudo_plaintext(1024);
    for &n in NONCE_SIZES {
        for mac_name in MAC_NAMES {
            with_nonce_bits(n, || {
                let mac = MAC::new(mac_name, &MAC_KEY).unwrap();
                let s0 = Seed::new("blake3", 1024).unwrap();
                let s1 = Seed::new("blake3", 1024).unwrap();
                let s2 = Seed::new("blake3", 1024).unwrap();
                let s3 = Seed::new("blake3", 1024).unwrap();
                let s4 = Seed::new("blake3", 1024).unwrap();
                let s5 = Seed::new("blake3", 1024).unwrap();
                let s6 = Seed::new("blake3", 1024).unwrap();
                let ct = itb::encrypt_auth_triple(
                    &s0, &s1, &s2, &s3, &s4, &s5, &s6, &mac, &plaintext,
                )
                .unwrap();
                let pt = itb::decrypt_auth_triple(
                    &s0, &s1, &s2, &s3, &s4, &s5, &s6, &mac, &ct,
                )
                .unwrap();
                assert_eq!(pt, plaintext, "nonce={} mac={}", n, mac_name);

                let mut tampered = ct.clone();
                let h = itb::header_size() as usize;
                let upper = std::cmp::min(h + 256, tampered.len());
                for b in &mut tampered[h..upper] {
                    *b ^= 0x01;
                }
                let err = itb::decrypt_auth_triple(
                    &s0, &s1, &s2, &s3, &s4, &s5, &s6, &mac, &tampered,
                )
                .unwrap_err();
                assert_eq!(err.code(), itb::STATUS_MAC_FAILURE);
            });
        }
    }
}
