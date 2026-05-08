//! End-to-end Encryptor tests for authenticated encryption — Rust
//! mirror of `bindings/python/tests/easy/test_auth.py`.
//!
//! Same matrix (3 MACs × 3 hash widths × {Single, Triple} round trip
//! plus tamper rejection) applied to the high-level [`itb::Encryptor`]
//! surface. Cross-MAC structural rejection rides through the
//! `Encryptor::export` / `Encryptor::import_state` path, where a
//! receiver constructed with the wrong MAC primitive surfaces
//! `STATUS_EASY_MISMATCH` with `last_mismatch_field() == "mac"`.
//! Same-primitive different-key MAC failure verifies that two
//! independently constructed encryptors with their own random MAC
//! material collide on `STATUS_MAC_FAILURE` rather than a corrupted
//! plaintext.

#[path = "common/mod.rs"]
#[allow(dead_code)]
mod common;

use itb::Encryptor;

const CANONICAL_MACS: &[&str] = &["kmac256", "hmac-sha256", "hmac-blake3"];
const HASH_BY_WIDTH: &[&str] = &["siphash24", "blake3", "blake2b512"];

fn token_bytes(n: usize) -> Vec<u8> {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::Instant;
    static CTR: AtomicU64 = AtomicU64::new(0xCAFEBABE_DEADBEEF);
    let c = CTR.fetch_add(0x9E37_79B9_7F4A_7C15, Ordering::Relaxed);
    let t = Instant::now().elapsed().as_nanos() as u64;
    let mut state = c ^ t.rotate_left(23);
    let mut out = Vec::with_capacity(n);
    for _ in 0..n {
        state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        out.push((state >> 33) as u8);
    }
    out
}

#[test]
fn all_macs_all_widths_single() {
    let plaintext = token_bytes(4096);
    for &mac_name in CANONICAL_MACS {
        for &hash_name in HASH_BY_WIDTH {
            let mut enc = Encryptor::new(Some(hash_name), Some(1024), Some(mac_name), 1)
                .expect("encryptor construction");
            let ct = enc.encrypt_auth(&plaintext).unwrap();
            let pt = enc.decrypt_auth(&ct).unwrap();
            assert_eq!(pt.as_slice(), plaintext.as_slice());

            // Tamper: flip 256 bytes past the dynamic header.
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
fn all_macs_all_widths_triple() {
    let plaintext = token_bytes(4096);
    for &mac_name in CANONICAL_MACS {
        for &hash_name in HASH_BY_WIDTH {
            let mut enc = Encryptor::new(Some(hash_name), Some(1024), Some(mac_name), 3)
                .expect("encryptor construction");
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
fn cross_mac_rejection_different_primitive() {
    // Sender uses kmac256; receiver uses hmac-sha256 — Import must
    // reject on field=mac.
    let src = Encryptor::new(Some("blake3"), Some(1024), Some("kmac256"), 1).unwrap();
    let blob = src.export().unwrap();
    drop(src);

    let dst = Encryptor::new(Some("blake3"), Some(1024), Some("hmac-sha256"), 1).unwrap();
    let err = dst.import_state(&blob).unwrap_err();
    assert_eq!(err.code(), itb::STATUS_EASY_MISMATCH);
    assert_eq!(itb::last_mismatch_field(), "mac");
}

#[test]
fn same_primitive_different_key_mac_failure() {
    let plaintext = b"authenticated payload";
    let mut enc1 =
        Encryptor::new(Some("blake3"), Some(1024), Some("hmac-sha256"), 1).unwrap();
    let mut enc2 =
        Encryptor::new(Some("blake3"), Some(1024), Some("hmac-sha256"), 1).unwrap();
    // Day 1: encrypt with enc1's seeds and MAC key.
    let _blob1 = enc1.export().unwrap();
    let ct = enc1.encrypt_auth(plaintext).unwrap();
    // Day 2: enc2 has its own (different) seed/MAC keys.
    let err = enc2.decrypt_auth(&ct).unwrap_err();
    assert_eq!(err.code(), itb::STATUS_MAC_FAILURE);
    // Silence unused-mut warning on enc1 if the test ever stops using
    // encrypt_auth; the binding contract requires `&mut self` on
    // every cipher call so the variable must remain mut.
    let _ = &mut enc1;
}
