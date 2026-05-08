//! SipHash-2-4-focused Encryptor coverage.
//!
//! Symmetric counterpart to `bindings/python/tests/test_siphash24.py`
//! applied to the high-level [`itb::Encryptor`] surface. SipHash
//! ships only at -128 and is the unique primitive with no fixed PRF
//! key — [`Encryptor::has_prf_keys`] is `false`,
//! [`Encryptor::prf_key`] surfaces `STATUS_BAD_INPUT`. The persistence
//! path therefore exports / imports without prf_keys carried in the
//! JSON blob; the seed components alone reconstruct the SipHash keying
//! material.
//!
//! `Encryptor::set_nonce_bits` is per-instance and does not touch
//! process-global state, so these tests do not need the
//! [`common::serial_lock`].

#[path = "common/mod.rs"]
#[allow(dead_code)]
mod common;

use itb::Encryptor;

const SIPHASH_HASHES: &[(&str, i32)] = &[("siphash24", 128)];

const NONCE_SIZES: &[i32] = &[128, 256, 512];

const MAC_NAMES: &[&str] = &["kmac256", "hmac-sha256", "hmac-blake3"];

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

fn key_bits_for(width: i32) -> Vec<i32> {
    [512i32, 1024, 2048]
        .iter()
        .copied()
        .filter(|k| k % width == 0)
        .collect()
}

#[test]
fn no_prf_keys() {
    // SipHash is the lone primitive with has_prf_keys == false; the
    // PRF key getter rejects indexed access with STATUS_BAD_INPUT.
    let enc = Encryptor::new(Some("siphash24"), Some(1024), Some("kmac256"), 1).unwrap();
    assert!(!enc.has_prf_keys().unwrap());
    let err = enc.prf_key(0).unwrap_err();
    assert_eq!(err.code(), itb::STATUS_BAD_INPUT);
}

#[test]
fn roundtrip_across_nonce_sizes() {
    let plaintext = token_bytes(1024);
    for &n in NONCE_SIZES {
        for &(hash_name, _) in SIPHASH_HASHES {
            let mut enc =
                Encryptor::new(Some(hash_name), Some(1024), Some("kmac256"), 1).unwrap();
            enc.set_nonce_bits(n).unwrap();
            let ct = enc.encrypt(&plaintext).unwrap();
            let pt = enc.decrypt(&ct).unwrap();
            assert_eq!(pt.as_slice(), plaintext.as_slice());
        }
    }
}

#[test]
fn triple_roundtrip_across_nonce_sizes() {
    let plaintext = token_bytes(1024);
    for &n in NONCE_SIZES {
        for &(hash_name, _) in SIPHASH_HASHES {
            let mut enc =
                Encryptor::new(Some(hash_name), Some(1024), Some("kmac256"), 3).unwrap();
            enc.set_nonce_bits(n).unwrap();
            let ct = enc.encrypt(&plaintext).unwrap();
            let pt = enc.decrypt(&ct).unwrap();
            assert_eq!(pt.as_slice(), plaintext.as_slice());
        }
    }
}

#[test]
fn auth_across_nonce_sizes() {
    let plaintext = token_bytes(1024);
    for &n in NONCE_SIZES {
        for &mac_name in MAC_NAMES {
            for &(hash_name, _) in SIPHASH_HASHES {
                let mut enc =
                    Encryptor::new(Some(hash_name), Some(1024), Some(mac_name), 1).unwrap();
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
}

#[test]
fn triple_auth_across_nonce_sizes() {
    let plaintext = token_bytes(1024);
    for &n in NONCE_SIZES {
        for &mac_name in MAC_NAMES {
            for &(hash_name, _) in SIPHASH_HASHES {
                let mut enc =
                    Encryptor::new(Some(hash_name), Some(1024), Some(mac_name), 3).unwrap();
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
}

#[test]
fn persistence_across_nonce_sizes() {
    // Persistence sweep without prf_keys: SipHash's seed components
    // alone reconstruct the keying material. The exported blob omits
    // prf_keys, and Import on a fresh encryptor restores the seeds
    // without consulting them.
    let mut plaintext = b"persistence payload ".to_vec();
    plaintext.extend_from_slice(&token_bytes(1024));

    for &(hash_name, width) in SIPHASH_HASHES {
        for &key_bits in &key_bits_for(width) {
            for &n in NONCE_SIZES {
                let mut src =
                    Encryptor::new(Some(hash_name), Some(key_bits), Some("kmac256"), 1)
                        .unwrap();
                src.set_nonce_bits(n).unwrap();
                assert!(!src.has_prf_keys().unwrap());
                assert_eq!(
                    src.seed_components(0).unwrap().len() as i32 * 64,
                    key_bits,
                );
                let blob = src.export().unwrap();
                let ct = src.encrypt(&plaintext).unwrap();
                src.free().unwrap();

                let mut dst =
                    Encryptor::new(Some(hash_name), Some(key_bits), Some("kmac256"), 1)
                        .unwrap();
                dst.set_nonce_bits(n).unwrap();
                dst.import_state(&blob).unwrap();
                let pt = dst.decrypt(&ct).unwrap();
                assert_eq!(pt.as_slice(), plaintext.as_slice());
                dst.free().unwrap();
            }
        }
    }
}

#[test]
fn roundtrip_sizes() {
    for &(hash_name, _) in SIPHASH_HASHES {
        for &n in NONCE_SIZES {
            for &sz in &[1usize, 17, 4096, 65536, 1 << 20] {
                let plaintext = token_bytes(sz);
                let mut enc =
                    Encryptor::new(Some(hash_name), Some(1024), Some("kmac256"), 1).unwrap();
                enc.set_nonce_bits(n).unwrap();
                let ct = enc.encrypt(&plaintext).unwrap();
                let pt = enc.decrypt(&ct).unwrap();
                assert_eq!(pt.as_slice(), plaintext.as_slice());
            }
        }
    }
}
