//! AES-CMAC-focused Rust binding coverage.
//!
//! W128 counterpart to `test_chacha20.rs` / `test_blake3.rs`: the same
//! coverage shape (nonce-size sweep, single and triple roundtrip,
//! single and triple auth with tamper rejection, persistence sweep,
//! plaintext-size sweep) applied to aescmac. AES-CMAC ships at a
//! single width (128 — the AES block size) so this file iterates the
//! single primitive across the same axes `test_chacha20.rs` covers.
//!
//! Mirrors `bindings/python/tests/test_aescmac.py` one-to-one. Each
//! Python `TestCase.test_*` becomes a single `#[test] fn` here; the
//! per-class subTest loops are inlined since cargo's test harness has
//! no equivalent of unittest subTest.
//!
//! Every test mutates the process-global `set_nonce_bits`, so each one
//! holds [`common::serial_lock`] for its entire duration.

#[path = "common/mod.rs"]
mod common;

use itb::{Seed, MAC};

// (hash, ITB_seed_width) — AES-CMAC ships only at -128 (the AES block
// size). The width feeds into Seed::from_components key validation
// later in this file.
const AESCMAC_HASHES: &[(&str, i32)] = &[("aescmac", 128)];

// Hash-key length (bytes) per primitive — locks in the FFI-surfaced
// contract that AES-CMAC carries a 16-byte AES-128 key.
fn expected_key_len(name: &str) -> usize {
    match name {
        "aescmac" => 16,
        _ => panic!("unknown hash {name}"),
    }
}

const NONCE_SIZES: &[i32] = &[128, 256, 512];

const MAC_NAMES: &[&str] = &["kmac256", "hmac-sha256", "hmac-blake3"];

/// Generates a pseudo-random byte buffer of length `n`. Each call
/// mixes a static counter with a fresh `Instant::now` reading so the
/// returned bytes differ between calls within one test run, while
/// staying dependency-free.
fn token_bytes(n: usize) -> Vec<u8> {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::Instant;
    static CTR: AtomicU64 = AtomicU64::new(0xDEADBEEF_CAFEBABE);
    let c = CTR.fetch_add(0x9E37_79B9_7F4A_7C15, Ordering::Relaxed);
    let t = Instant::now().elapsed().as_nanos() as u64;
    let mut state = c ^ t.rotate_left(17);
    let mut out = Vec::with_capacity(n);
    for _ in 0..n {
        state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        out.push((state >> 33) as u8);
    }
    out
}

fn restore_nonce_bits(orig: i32) {
    let _ = itb::set_nonce_bits(orig);
}

#[test]
fn roundtrip_across_nonce_sizes() {
    let _g = common::serial_lock();
    let orig = itb::get_nonce_bits();
    let plaintext = token_bytes(1024);
    for &n in NONCE_SIZES {
        for &(hash_name, _) in AESCMAC_HASHES {
            itb::set_nonce_bits(n).unwrap();
            let s0 = Seed::new(hash_name, 1024).unwrap();
            let s1 = Seed::new(hash_name, 1024).unwrap();
            let s2 = Seed::new(hash_name, 1024).unwrap();
            let ct = itb::encrypt(&s0, &s1, &s2, &plaintext).unwrap();
            let pt = itb::decrypt(&s0, &s1, &s2, &ct).unwrap();
            assert_eq!(pt.as_slice(), plaintext.as_slice());
            let h = itb::header_size() as usize;
            let chunk_len = itb::parse_chunk_len(&ct[..h]).unwrap();
            assert_eq!(chunk_len, ct.len());
        }
    }
    restore_nonce_bits(orig);
}

#[test]
fn triple_roundtrip_across_nonce_sizes() {
    let _g = common::serial_lock();
    let orig = itb::get_nonce_bits();
    let plaintext = token_bytes(1024);
    for &n in NONCE_SIZES {
        for &(hash_name, _) in AESCMAC_HASHES {
            itb::set_nonce_bits(n).unwrap();
            let mut seeds: Vec<Seed> = Vec::new();
            for _ in 0..7 {
                seeds.push(Seed::new(hash_name, 1024).unwrap());
            }
            let ct = itb::encrypt_triple(
                &seeds[0], &seeds[1], &seeds[2], &seeds[3],
                &seeds[4], &seeds[5], &seeds[6], &plaintext,
            )
            .unwrap();
            let pt = itb::decrypt_triple(
                &seeds[0], &seeds[1], &seeds[2], &seeds[3],
                &seeds[4], &seeds[5], &seeds[6], &ct,
            )
            .unwrap();
            assert_eq!(pt.as_slice(), plaintext.as_slice());
        }
    }
    restore_nonce_bits(orig);
}

#[test]
fn auth_across_nonce_sizes() {
    let _g = common::serial_lock();
    let orig = itb::get_nonce_bits();
    let plaintext = token_bytes(1024);
    for &n in NONCE_SIZES {
        for &mac_name in MAC_NAMES {
            for &(hash_name, _) in AESCMAC_HASHES {
                itb::set_nonce_bits(n).unwrap();
                let key = token_bytes(32);
                let mac = MAC::new(mac_name, &key).unwrap();
                let s0 = Seed::new(hash_name, 1024).unwrap();
                let s1 = Seed::new(hash_name, 1024).unwrap();
                let s2 = Seed::new(hash_name, 1024).unwrap();
                let ct = itb::encrypt_auth(&s0, &s1, &s2, &mac, &plaintext).unwrap();
                let pt = itb::decrypt_auth(&s0, &s1, &s2, &mac, &ct).unwrap();
                assert_eq!(pt.as_slice(), plaintext.as_slice());

                // Tamper at the dynamic header offset.
                let mut tampered = ct.clone();
                let h = itb::header_size() as usize;
                let end = std::cmp::min(h + 256, tampered.len());
                for b in &mut tampered[h..end] {
                    *b ^= 0x01;
                }
                let err = itb::decrypt_auth(&s0, &s1, &s2, &mac, &tampered).unwrap_err();
                assert_eq!(err.code(), itb::STATUS_MAC_FAILURE);
            }
        }
    }
    restore_nonce_bits(orig);
}

#[test]
fn triple_auth_across_nonce_sizes() {
    let _g = common::serial_lock();
    let orig = itb::get_nonce_bits();
    let plaintext = token_bytes(1024);
    for &n in NONCE_SIZES {
        for &mac_name in MAC_NAMES {
            for &(hash_name, _) in AESCMAC_HASHES {
                itb::set_nonce_bits(n).unwrap();
                let key = token_bytes(32);
                let mac = MAC::new(mac_name, &key).unwrap();
                let mut seeds: Vec<Seed> = Vec::new();
                for _ in 0..7 {
                    seeds.push(Seed::new(hash_name, 1024).unwrap());
                }
                let ct = itb::encrypt_auth_triple(
                    &seeds[0], &seeds[1], &seeds[2], &seeds[3],
                    &seeds[4], &seeds[5], &seeds[6], &mac, &plaintext,
                )
                .unwrap();
                let pt = itb::decrypt_auth_triple(
                    &seeds[0], &seeds[1], &seeds[2], &seeds[3],
                    &seeds[4], &seeds[5], &seeds[6], &mac, &ct,
                )
                .unwrap();
                assert_eq!(pt.as_slice(), plaintext.as_slice());

                let mut tampered = ct.clone();
                let h = itb::header_size() as usize;
                let end = std::cmp::min(h + 256, tampered.len());
                for b in &mut tampered[h..end] {
                    *b ^= 0x01;
                }
                let err = itb::decrypt_auth_triple(
                    &seeds[0], &seeds[1], &seeds[2], &seeds[3],
                    &seeds[4], &seeds[5], &seeds[6], &mac, &tampered,
                )
                .unwrap_err();
                assert_eq!(err.code(), itb::STATUS_MAC_FAILURE);
            }
        }
    }
    restore_nonce_bits(orig);
}

#[test]
fn persistence_across_nonce_sizes() {
    let _g = common::serial_lock();
    let orig = itb::get_nonce_bits();
    let mut plaintext = b"persistence payload ".to_vec();
    plaintext.extend_from_slice(&token_bytes(1024));

    for &(hash_name, width) in AESCMAC_HASHES {
        let valid_key_bits: Vec<i32> = [512i32, 1024, 2048]
            .iter()
            .copied()
            .filter(|k| k % width == 0)
            .collect();
        for &key_bits in &valid_key_bits {
            for &n in NONCE_SIZES {
                itb::set_nonce_bits(n).unwrap();

                // Day 1 — random seeds.
                let ns = Seed::new(hash_name, key_bits).unwrap();
                let ds = Seed::new(hash_name, key_bits).unwrap();
                let ss = Seed::new(hash_name, key_bits).unwrap();

                let ns_comps = ns.components().unwrap();
                let ns_key = ns.hash_key().unwrap();
                let ds_comps = ds.components().unwrap();
                let ds_key = ds.hash_key().unwrap();
                let ss_comps = ss.components().unwrap();
                let ss_key = ss.hash_key().unwrap();

                assert_eq!(ns_key.len(), expected_key_len(hash_name));
                assert_eq!(ns_comps.len() as i32 * 64, key_bits);

                let ciphertext = itb::encrypt(&ns, &ds, &ss, &plaintext).unwrap();
                drop(ns);
                drop(ds);
                drop(ss);

                // Day 2 — restore from saved material.
                let ns2 = Seed::from_components(hash_name, &ns_comps, &ns_key).unwrap();
                let ds2 = Seed::from_components(hash_name, &ds_comps, &ds_key).unwrap();
                let ss2 = Seed::from_components(hash_name, &ss_comps, &ss_key).unwrap();
                let decrypted = itb::decrypt(&ns2, &ds2, &ss2, &ciphertext).unwrap();
                assert_eq!(decrypted.as_slice(), plaintext.as_slice());
            }
        }
    }
    restore_nonce_bits(orig);
}

#[test]
fn roundtrip_sizes() {
    let _g = common::serial_lock();
    let orig = itb::get_nonce_bits();
    for &(hash_name, _) in AESCMAC_HASHES {
        for &n in NONCE_SIZES {
            for &sz in &[1usize, 17, 4096, 65536, 1 << 20] {
                itb::set_nonce_bits(n).unwrap();
                let plaintext = token_bytes(sz);
                let ns = Seed::new(hash_name, 1024).unwrap();
                let ds = Seed::new(hash_name, 1024).unwrap();
                let ss = Seed::new(hash_name, 1024).unwrap();
                let ct = itb::encrypt(&ns, &ds, &ss, &plaintext).unwrap();
                let pt = itb::decrypt(&ns, &ds, &ss, &ct).unwrap();
                assert_eq!(pt.as_slice(), plaintext.as_slice());
            }
        }
    }
    restore_nonce_bits(orig);
}
