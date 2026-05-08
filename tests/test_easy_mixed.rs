//! Mixed-mode Encryptor (per-slot PRF primitive selection) tests —
//! Rust mirror of `bindings/python/tests/easy/test_mixed.py`.
//!
//! Round-trip on Single + Triple under [`Encryptor::mixed_single`] /
//! [`Encryptor::mixed_triple`]; optional dedicated lockSeed under its
//! own primitive; state-blob Export / Import; mixed-width rejection
//! through the cgo boundary; per-slot introspection accessors
//! ([`Encryptor::primitive_at`], [`Encryptor::is_mixed`]).

#[path = "common/mod.rs"]
#[allow(dead_code)]
mod common;

use itb::Encryptor;

fn token_bytes(n: usize) -> Vec<u8> {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::Instant;
    static CTR: AtomicU64 = AtomicU64::new(0xFEEDFACE_DEC0DED0);
    let c = CTR.fetch_add(0x9E37_79B9_7F4A_7C15, Ordering::Relaxed);
    let t = Instant::now().elapsed().as_nanos() as u64;
    let mut state = c ^ t.rotate_left(29);
    let mut out = Vec::with_capacity(n);
    for _ in 0..n {
        state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        out.push((state >> 33) as u8);
    }
    out
}

// ─── TestMixedSingle ──────────────────────────────────────────────

#[test]
fn mixed_single_basic_roundtrip() {
    let mut enc = Encryptor::mixed_single(
        "blake3",
        "blake2s",
        "areion256",
        None,
        1024,
        "kmac256",
    )
    .unwrap();
    assert!(enc.is_mixed().unwrap());
    assert_eq!(enc.primitive().unwrap(), "mixed");
    assert_eq!(enc.primitive_at(0).unwrap(), "blake3");
    assert_eq!(enc.primitive_at(1).unwrap(), "blake2s");
    assert_eq!(enc.primitive_at(2).unwrap(), "areion256");

    let plaintext = b"rs mixed Single roundtrip payload";
    let ct = enc.encrypt(plaintext).unwrap();
    let pt = enc.decrypt(&ct).unwrap();
    assert_eq!(pt.as_slice(), plaintext);
}

#[test]
fn mixed_single_with_dedicated_lockseed() {
    let mut enc = Encryptor::mixed_single(
        "blake3",
        "blake2s",
        "blake3",
        Some("areion256"),
        1024,
        "kmac256",
    )
    .unwrap();
    assert_eq!(enc.primitive_at(3).unwrap(), "areion256");
    let plaintext = b"rs mixed Single + dedicated lockSeed payload";
    let ct = enc.encrypt_auth(plaintext).unwrap();
    let pt = enc.decrypt_auth(&ct).unwrap();
    assert_eq!(pt.as_slice(), plaintext);
}

#[test]
fn mixed_single_aescmac_siphash_128bit() {
    // SipHash-2-4 in one slot + AES-CMAC in others — 128-bit width
    // with mixed key shapes (siphash24 carries no fixed key bytes,
    // aescmac carries 16). Exercises the per-slot empty / non-empty
    // PRF-key validation in Export / Import.
    let mut enc = Encryptor::mixed_single(
        "aescmac",
        "siphash24",
        "aescmac",
        None,
        512,
        "hmac-sha256",
    )
    .unwrap();
    let plaintext = b"rs mixed 128-bit aescmac+siphash24 mix";
    let ct = enc.encrypt(plaintext).unwrap();
    let pt = enc.decrypt(&ct).unwrap();
    assert_eq!(pt.as_slice(), plaintext);
}

// ─── TestMixedTriple ──────────────────────────────────────────────

#[test]
fn mixed_triple_basic_roundtrip() {
    let mut enc = Encryptor::mixed_triple(
        "areion256",
        "blake3",
        "blake2s",
        "chacha20",
        "blake2b256",
        "blake3",
        "blake2s",
        None,
        1024,
        "kmac256",
    )
    .unwrap();
    let wants = [
        "areion256", "blake3", "blake2s", "chacha20",
        "blake2b256", "blake3", "blake2s",
    ];
    for (i, w) in wants.iter().enumerate() {
        assert_eq!(enc.primitive_at(i as i32).unwrap().as_str(), *w);
    }
    let plaintext = b"rs mixed Triple roundtrip payload";
    let ct = enc.encrypt(plaintext).unwrap();
    let pt = enc.decrypt(&ct).unwrap();
    assert_eq!(pt.as_slice(), plaintext);
}

#[test]
fn mixed_triple_with_dedicated_lockseed() {
    let mut enc = Encryptor::mixed_triple(
        "blake3",
        "blake2s",
        "blake3",
        "blake2s",
        "blake3",
        "blake2s",
        "blake3",
        Some("areion256"),
        1024,
        "kmac256",
    )
    .unwrap();
    assert_eq!(enc.primitive_at(7).unwrap(), "areion256");
    let plaintext = b"rs mixed Triple + lockSeed payload".repeat(16);
    let ct = enc.encrypt_auth(&plaintext).unwrap();
    let pt = enc.decrypt_auth(&ct).unwrap();
    assert_eq!(pt.as_slice(), plaintext.as_slice());
}

// ─── TestMixedExportImport ────────────────────────────────────────

#[test]
fn mixed_single_export_import() {
    let mut sender = Encryptor::mixed_single(
        "blake3",
        "blake2s",
        "areion256",
        None,
        1024,
        "kmac256",
    )
    .unwrap();
    let plaintext = token_bytes(2048);
    let ct = sender.encrypt_auth(&plaintext).unwrap();
    let blob = sender.export().unwrap();
    assert!(!blob.is_empty());
    drop(sender);

    let mut receiver = Encryptor::mixed_single(
        "blake3",
        "blake2s",
        "areion256",
        None,
        1024,
        "kmac256",
    )
    .unwrap();
    receiver.import_state(&blob).unwrap();
    let pt = receiver.decrypt_auth(&ct).unwrap();
    assert_eq!(pt.as_slice(), plaintext.as_slice());
}

#[test]
fn mixed_triple_export_import_with_lockseed() {
    let plaintext = b"rs mixed Triple + lockSeed Export/Import".repeat(16);
    let mut sender = Encryptor::mixed_triple(
        "areion256",
        "blake3",
        "blake2s",
        "chacha20",
        "blake2b256",
        "blake3",
        "blake2s",
        Some("areion256"),
        1024,
        "kmac256",
    )
    .unwrap();
    let ct = sender.encrypt_auth(&plaintext).unwrap();
    let blob = sender.export().unwrap();
    drop(sender);

    let mut receiver = Encryptor::mixed_triple(
        "areion256",
        "blake3",
        "blake2s",
        "chacha20",
        "blake2b256",
        "blake3",
        "blake2s",
        Some("areion256"),
        1024,
        "kmac256",
    )
    .unwrap();
    receiver.import_state(&blob).unwrap();
    let pt = receiver.decrypt_auth(&ct).unwrap();
    assert_eq!(pt.as_slice(), plaintext.as_slice());
}

#[test]
fn mixed_shape_mismatch() {
    // Mixed blob landing on a single-primitive receiver must be
    // rejected as a primitive mismatch.
    let mixed_sender = Encryptor::mixed_single(
        "blake3",
        "blake2s",
        "blake3",
        None,
        1024,
        "kmac256",
    )
    .unwrap();
    let mixed_blob = mixed_sender.export().unwrap();
    drop(mixed_sender);

    let single_recv =
        Encryptor::new(Some("blake3"), Some(1024), Some("kmac256"), 1).unwrap();
    assert!(single_recv.import_state(&mixed_blob).is_err());
}

// ─── TestMixedRejection ───────────────────────────────────────────

#[test]
fn reject_mixed_width() {
    // Mixing a 256-bit primitive with a 512-bit primitive surfaces as
    // an error (panic-to-Status path on the Go side).
    let result = Encryptor::mixed_single(
        "blake3",     // 256-bit
        "areion512",  // 512-bit ← width mismatch
        "blake3",
        None,
        1024,
        "kmac256",
    );
    assert!(result.is_err());
}

#[test]
fn reject_unknown_primitive() {
    let result = Encryptor::mixed_single(
        "no-such-primitive",
        "blake3",
        "blake3",
        None,
        1024,
        "kmac256",
    );
    assert!(result.is_err());
}

// ─── TestMixedNonMixed ────────────────────────────────────────────

#[test]
fn default_constructor_is_not_mixed() {
    let enc = Encryptor::new(Some("blake3"), Some(1024), Some("kmac256"), 1).unwrap();
    assert!(!enc.is_mixed().unwrap());
    for i in 0..3 {
        assert_eq!(enc.primitive_at(i).unwrap(), "blake3");
    }
}
