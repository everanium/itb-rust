//! Round-trip tests across every per-instance nonce-size
//! configuration — Rust mirror of
//! `bindings/python/tests/easy/test_nonce_sizes.py`.
//!
//! The Encryptor surface exposes nonce_bits as a per-instance setter
//! ([`Encryptor::set_nonce_bits`]) rather than a process-wide config —
//! each encryptor's [`Encryptor::header_size`] and
//! [`Encryptor::parse_chunk_len`] track its own nonce_bits state
//! without touching the global [`itb::set_nonce_bits`] /
//! [`itb::get_nonce_bits`] accessors. None of the tests in this file
//! mutate process-global state.

#[path = "common/mod.rs"]
#[allow(dead_code)]
mod common;

use itb::Encryptor;

const NONCE_SIZES: &[i32] = &[128, 256, 512];
const HASHES: &[&str] = &["siphash24", "blake3", "blake2b512"];
const MACS: &[&str] = &["kmac256", "hmac-sha256", "hmac-blake3"];

fn token_bytes(n: usize) -> Vec<u8> {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::Instant;
    static CTR: AtomicU64 = AtomicU64::new(0xA5A5A5A5_5A5A5A5A);
    let c = CTR.fetch_add(0x9E37_79B9_7F4A_7C15, Ordering::Relaxed);
    let t = Instant::now().elapsed().as_nanos() as u64;
    let mut state = c ^ t.rotate_left(11);
    let mut out = Vec::with_capacity(n);
    for _ in 0..n {
        state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        out.push((state >> 33) as u8);
    }
    out
}

#[test]
fn header_size_default_is_20() {
    let enc = Encryptor::new(Some("blake3"), Some(1024), Some("kmac256"), 1).unwrap();
    assert_eq!(enc.header_size().unwrap(), 20);
    assert_eq!(enc.nonce_bits().unwrap(), 128);
}

#[test]
fn header_size_dynamic() {
    for &n in NONCE_SIZES {
        let enc = Encryptor::new(Some("blake3"), Some(1024), Some("kmac256"), 1).unwrap();
        enc.set_nonce_bits(n).unwrap();
        assert_eq!(enc.nonce_bits().unwrap(), n);
        assert_eq!(enc.header_size().unwrap(), n / 8 + 4);
    }
}

#[test]
fn encrypt_decrypt_across_nonce_sizes_single() {
    let plaintext = token_bytes(1024);
    for &n in NONCE_SIZES {
        for &hash_name in HASHES {
            let mut enc = Encryptor::new(Some(hash_name), Some(1024), Some("kmac256"), 1)
                .unwrap();
            enc.set_nonce_bits(n).unwrap();
            let ct = enc.encrypt(&plaintext).unwrap();
            let pt = enc.decrypt(&ct).unwrap();
            assert_eq!(pt.as_slice(), plaintext.as_slice());
            let h = enc.header_size().unwrap() as usize;
            let parsed = enc.parse_chunk_len(&ct[..h]).unwrap();
            assert_eq!(parsed, ct.len());
        }
    }
}

#[test]
fn encrypt_decrypt_across_nonce_sizes_triple() {
    let plaintext = token_bytes(1024);
    for &n in NONCE_SIZES {
        for &hash_name in HASHES {
            let mut enc = Encryptor::new(Some(hash_name), Some(1024), Some("kmac256"), 3)
                .unwrap();
            enc.set_nonce_bits(n).unwrap();
            let ct = enc.encrypt(&plaintext).unwrap();
            let pt = enc.decrypt(&ct).unwrap();
            assert_eq!(pt.as_slice(), plaintext.as_slice());
            let h = enc.header_size().unwrap() as usize;
            let parsed = enc.parse_chunk_len(&ct[..h]).unwrap();
            assert_eq!(parsed, ct.len());
        }
    }
}

#[test]
fn auth_across_nonce_sizes_single() {
    let plaintext = token_bytes(1024);
    for &n in NONCE_SIZES {
        for &mac_name in MACS {
            let mut enc =
                Encryptor::new(Some("blake3"), Some(1024), Some(mac_name), 1).unwrap();
            enc.set_nonce_bits(n).unwrap();
            let ct = enc.encrypt_auth(&plaintext).unwrap();
            let pt = enc.decrypt_auth(&ct).unwrap();
            assert_eq!(pt.as_slice(), plaintext.as_slice());
            let mut tampered = ct.clone();
            let h = enc.header_size().unwrap() as usize;
            let end = std::cmp::min(h + 256, tampered.len());
            for b in &mut tampered[h..end] {
                *b ^= 0x01;
            }
            let err = enc.decrypt_auth(&tampered).unwrap_err();
            assert_eq!(err.code(), itb::STATUS_MAC_FAILURE);
        }
    }
}

#[test]
fn auth_across_nonce_sizes_triple() {
    let plaintext = token_bytes(1024);
    for &n in NONCE_SIZES {
        for &mac_name in MACS {
            let mut enc =
                Encryptor::new(Some("blake3"), Some(1024), Some(mac_name), 3).unwrap();
            enc.set_nonce_bits(n).unwrap();
            let ct = enc.encrypt_auth(&plaintext).unwrap();
            let pt = enc.decrypt_auth(&ct).unwrap();
            assert_eq!(pt.as_slice(), plaintext.as_slice());
            let mut tampered = ct.clone();
            let h = enc.header_size().unwrap() as usize;
            let end = std::cmp::min(h + 256, tampered.len());
            for b in &mut tampered[h..end] {
                *b ^= 0x01;
            }
            let err = enc.decrypt_auth(&tampered).unwrap_err();
            assert_eq!(err.code(), itb::STATUS_MAC_FAILURE);
        }
    }
}

#[test]
fn two_encryptors_independent_nonce_bits() {
    let plaintext = b"isolation test";
    let mut a = Encryptor::new(Some("blake3"), Some(1024), Some("kmac256"), 1).unwrap();
    let mut b = Encryptor::new(Some("blake3"), Some(1024), Some("kmac256"), 1).unwrap();
    a.set_nonce_bits(512).unwrap();
    assert_eq!(a.nonce_bits().unwrap(), 512);
    assert_eq!(a.header_size().unwrap(), 68);
    assert_eq!(b.nonce_bits().unwrap(), 128);
    assert_eq!(b.header_size().unwrap(), 20);
    let ct_a = a.encrypt(plaintext).unwrap();
    let pt_a = a.decrypt(&ct_a).unwrap();
    assert_eq!(pt_a.as_slice(), plaintext);
    let ct_b = b.encrypt(plaintext).unwrap();
    let pt_b = b.decrypt(&ct_b).unwrap();
    assert_eq!(pt_b.as_slice(), plaintext);
}
