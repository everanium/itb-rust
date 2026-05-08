//! End-to-end Rust binding tests for the high-level
//! [`itb::Encryptor`] surface — Rust mirror of
//! `bindings/python/tests/easy/test_roundtrip.py`.
//!
//! Lifecycle tests (close / drop / handle invalidation), structural
//! validation (bad primitive / MAC / key_bits / mode), full-matrix
//! round-trips for both Single and Triple Ouroboros, and per-instance
//! configuration setters that mutate only the local Config copy
//! without touching libitb's process-global state.

#[path = "common/mod.rs"]
#[allow(dead_code)]
mod common;

use itb::Encryptor;

const CANONICAL_HASHES: &[(&str, i32)] = &[
    ("areion256", 256),
    ("areion512", 512),
    ("siphash24", 128),
    ("aescmac", 128),
    ("blake2b256", 256),
    ("blake2b512", 512),
    ("blake2s", 256),
    ("blake3", 256),
    ("chacha20", 256),
];

fn key_bits_for(width: i32) -> Vec<i32> {
    [512i32, 1024, 2048].iter().copied().filter(|k| k % width == 0).collect()
}

fn token_bytes(n: usize) -> Vec<u8> {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::Instant;
    static CTR: AtomicU64 = AtomicU64::new(0xF00DCAFE_BAADF00D);
    let c = CTR.fetch_add(0x9E37_79B9_7F4A_7C15, Ordering::Relaxed);
    let t = Instant::now().elapsed().as_nanos() as u64;
    let mut state = c ^ t.rotate_left(7);
    let mut out = Vec::with_capacity(n);
    for _ in 0..n {
        state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        out.push((state >> 33) as u8);
    }
    out
}

// ─── Lifecycle ─────────────────────────────────────────────────────

#[test]
fn new_and_free() {
    let enc = Encryptor::new(Some("blake3"), Some(1024), Some("kmac256"), 1).unwrap();
    assert_ne!(enc.handle(), 0);
    assert_eq!(enc.primitive().unwrap(), "blake3");
    assert_eq!(enc.key_bits().unwrap(), 1024);
    assert_eq!(enc.mode().unwrap(), 1);
    assert_eq!(enc.mac_name().unwrap(), "kmac256");
    enc.free().unwrap();
}

#[test]
fn drop_releases_handle() {
    // Rust analogue of Python's context-manager test — `Drop` runs
    // automatic `ITB_Easy_Free` when the encryptor leaves scope.
    {
        let enc = Encryptor::new(Some("areion256"), Some(1024), Some("kmac256"), 1)
            .unwrap();
        assert_ne!(enc.handle(), 0);
    } // drop here; libitb-side handle released
}

#[test]
fn double_free_idempotent() {
    let mut enc = Encryptor::new(Some("blake3"), Some(1024), Some("kmac256"), 1).unwrap();
    enc.close().unwrap();
    // free() is consuming; close-then-free mirrors Python's
    // free()-twice-no-raise contract (the second free is via Drop).
    enc.free().unwrap();
}

#[test]
fn close_then_method_raises() {
    let mut enc = Encryptor::new(Some("blake3"), Some(1024), Some("kmac256"), 1).unwrap();
    enc.close().unwrap();
    let err = enc.encrypt(b"after close").unwrap_err();
    assert_eq!(err.code(), itb::STATUS_EASY_CLOSED);
}

#[test]
fn defaults() {
    // None primitive / None keyBits / None mac select package
    // defaults: areion512 / 1024 / hmac-blake3 (the latter via the
    // binding-side override that maps `mac=None` to the
    // lightest-overhead MAC available in the Easy Mode surface).
    let enc = Encryptor::new(None, None, None, 1).unwrap();
    assert_eq!(enc.primitive().unwrap(), "areion512");
    assert_eq!(enc.key_bits().unwrap(), 1024);
    assert_eq!(enc.mode().unwrap(), 1);
    assert_eq!(enc.mac_name().unwrap(), "hmac-blake3");
}

#[test]
fn bad_primitive() {
    assert!(
        Encryptor::new(Some("nonsense-hash"), Some(1024), Some("kmac256"), 1).is_err()
    );
}

#[test]
fn bad_mac() {
    assert!(
        Encryptor::new(Some("blake3"), Some(1024), Some("nonsense-mac"), 1).is_err()
    );
}

#[test]
fn bad_key_bits() {
    for bits in [256, 511, 999, 2049] {
        assert!(
            Encryptor::new(Some("blake3"), Some(bits), Some("kmac256"), 1).is_err(),
            "key_bits={bits} must be rejected",
        );
    }
}

#[test]
fn bad_mode() {
    match Encryptor::new(Some("blake3"), Some(1024), Some("kmac256"), 2) {
        Ok(_) => panic!("expected mode=2 to be rejected"),
        Err(e) => assert_eq!(e.code(), itb::STATUS_BAD_INPUT),
    }
}

// ─── Roundtrip Single ──────────────────────────────────────────────

#[test]
fn all_hashes_all_widths_single() {
    let plaintext = token_bytes(4096);
    for &(name, width) in CANONICAL_HASHES {
        for &key_bits in &key_bits_for(width) {
            let mut enc = Encryptor::new(Some(name), Some(key_bits), Some("kmac256"), 1)
                .unwrap();
            let ct = enc.encrypt(&plaintext).unwrap();
            assert!(ct.len() > plaintext.len());
            let pt = enc.decrypt(&ct).unwrap();
            assert_eq!(pt.as_slice(), plaintext.as_slice());
        }
    }
}

#[test]
fn all_hashes_all_widths_single_auth() {
    let plaintext = token_bytes(4096);
    for &(name, width) in CANONICAL_HASHES {
        for &key_bits in &key_bits_for(width) {
            let mut enc = Encryptor::new(Some(name), Some(key_bits), Some("kmac256"), 1)
                .unwrap();
            let ct = enc.encrypt_auth(&plaintext).unwrap();
            let pt = enc.decrypt_auth(&ct).unwrap();
            assert_eq!(pt.as_slice(), plaintext.as_slice());
        }
    }
}

#[test]
fn slice_input_roundtrip() {
    // Rust analogue of the Python bytearray + memoryview tests:
    // `&[u8]` is the canonical input shape and any slice reference is
    // accepted.
    let mut enc = Encryptor::new(Some("blake3"), Some(1024), Some("kmac256"), 1).unwrap();
    let payload: Vec<u8> = b"hello bytearray".to_vec();
    let ct = enc.encrypt(&payload[..]).unwrap();
    let pt = enc.decrypt(&ct[..]).unwrap();
    assert_eq!(pt.as_slice(), payload.as_slice());
}

// ─── Roundtrip Triple ──────────────────────────────────────────────

#[test]
fn all_hashes_all_widths_triple() {
    let plaintext = token_bytes(4096);
    for &(name, width) in CANONICAL_HASHES {
        for &key_bits in &key_bits_for(width) {
            let mut enc = Encryptor::new(Some(name), Some(key_bits), Some("kmac256"), 3)
                .unwrap();
            let ct = enc.encrypt(&plaintext).unwrap();
            assert!(ct.len() > plaintext.len());
            let pt = enc.decrypt(&ct).unwrap();
            assert_eq!(pt.as_slice(), plaintext.as_slice());
        }
    }
}

#[test]
fn all_hashes_all_widths_triple_auth() {
    let plaintext = token_bytes(4096);
    for &(name, width) in CANONICAL_HASHES {
        for &key_bits in &key_bits_for(width) {
            let mut enc = Encryptor::new(Some(name), Some(key_bits), Some("kmac256"), 3)
                .unwrap();
            let ct = enc.encrypt_auth(&plaintext).unwrap();
            let pt = enc.decrypt_auth(&ct).unwrap();
            assert_eq!(pt.as_slice(), plaintext.as_slice());
        }
    }
}

#[test]
fn seed_count_reflects_mode() {
    let enc1 = Encryptor::new(Some("blake3"), Some(1024), Some("kmac256"), 1).unwrap();
    assert_eq!(enc1.seed_count().unwrap(), 3);
    let enc3 = Encryptor::new(Some("blake3"), Some(1024), Some("kmac256"), 3).unwrap();
    assert_eq!(enc3.seed_count().unwrap(), 7);
}

// ─── Per-instance configuration ───────────────────────────────────

#[test]
fn set_bit_soup() {
    let mut enc = Encryptor::new(Some("blake3"), Some(1024), Some("kmac256"), 1).unwrap();
    enc.set_bit_soup(1).unwrap();
    let ct = enc.encrypt(b"bit-soup payload").unwrap();
    let pt = enc.decrypt(&ct).unwrap();
    assert_eq!(pt.as_slice(), b"bit-soup payload");
}

#[test]
fn set_lock_soup_couples_bit_soup() {
    let mut enc = Encryptor::new(Some("blake3"), Some(1024), Some("kmac256"), 1).unwrap();
    enc.set_lock_soup(1).unwrap();
    let ct = enc.encrypt(b"lock-soup payload").unwrap();
    let pt = enc.decrypt(&ct).unwrap();
    assert_eq!(pt.as_slice(), b"lock-soup payload");
}

#[test]
fn set_lock_seed_grows_seed_count() {
    let mut enc = Encryptor::new(Some("blake3"), Some(1024), Some("kmac256"), 1).unwrap();
    assert_eq!(enc.seed_count().unwrap(), 3);
    enc.set_lock_seed(1).unwrap();
    assert_eq!(enc.seed_count().unwrap(), 4);
    let ct = enc.encrypt(b"lockseed payload").unwrap();
    let pt = enc.decrypt(&ct).unwrap();
    assert_eq!(pt.as_slice(), b"lockseed payload");
}

#[test]
fn set_lock_seed_after_encrypt_rejected() {
    let mut enc = Encryptor::new(Some("blake3"), Some(1024), Some("kmac256"), 1).unwrap();
    let _ = enc.encrypt(b"first").unwrap();
    let err = enc.set_lock_seed(1).unwrap_err();
    assert_eq!(err.code(), itb::STATUS_EASY_LOCKSEED_AFTER_ENCRYPT);
}

#[test]
fn set_nonce_bits_validation() {
    let enc = Encryptor::new(Some("blake3"), Some(1024), Some("kmac256"), 1).unwrap();
    for &valid in &[128, 256, 512] {
        enc.set_nonce_bits(valid).unwrap();
    }
    for &bad in &[0, 1, 192, 1024] {
        let err = enc.set_nonce_bits(bad).unwrap_err();
        assert_eq!(err.code(), itb::STATUS_BAD_INPUT, "bad={bad}");
    }
}

#[test]
fn set_barrier_fill_validation() {
    let enc = Encryptor::new(Some("blake3"), Some(1024), Some("kmac256"), 1).unwrap();
    for &valid in &[1, 2, 4, 8, 16, 32] {
        enc.set_barrier_fill(valid).unwrap();
    }
    for &bad in &[0, 3, 5, 7, 64] {
        let err = enc.set_barrier_fill(bad).unwrap_err();
        assert_eq!(err.code(), itb::STATUS_BAD_INPUT, "bad={bad}");
    }
}

#[test]
fn set_chunk_size_accepted() {
    let enc = Encryptor::new(Some("blake3"), Some(1024), Some("kmac256"), 1).unwrap();
    enc.set_chunk_size(1024).unwrap();
    enc.set_chunk_size(0).unwrap();
}

#[test]
fn two_encryptors_isolated() {
    // Setting LockSoup on one encryptor must not bleed into another;
    // per-instance Config snapshots are independent.
    let mut a = Encryptor::new(Some("blake3"), Some(1024), Some("kmac256"), 1).unwrap();
    let mut b = Encryptor::new(Some("blake3"), Some(1024), Some("kmac256"), 1).unwrap();
    a.set_lock_soup(1).unwrap();
    let ct_a = a.encrypt(b"a").unwrap();
    assert_eq!(a.decrypt(&ct_a).unwrap().as_slice(), b"a");
    let ct_b = b.encrypt(b"b").unwrap();
    assert_eq!(b.decrypt(&ct_b).unwrap().as_slice(), b"b");
}
