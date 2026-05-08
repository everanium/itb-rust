//! Cross-process persistence round-trip tests for the ITB Rust binding.
//!
//! Mirrors `bindings/python/tests/test_persistence.py`. Exercises the
//! [`itb::Seed::components`] / [`itb::Seed::hash_key`] /
//! [`itb::Seed::from_components`] surface across every primitive in the
//! registry × the three ITB key-bit widths (512 / 1024 / 2048) that are
//! valid for each native hash width.
//!
//! Without both `components` and `hash_key` captured at encrypt-side
//! and re-supplied at decrypt-side, the seed state cannot be
//! reconstructed and the ciphertext is unreadable.

use itb::Seed;

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

/// Maps a primitive name to its expected fixed hash-key length in
/// bytes. SipHash-2-4 has no internal fixed key (its keying material
/// is the seed components themselves), so the expected length is 0.
fn expected_hash_key_len(name: &str) -> usize {
    match name {
        "areion256" => 32,
        "areion512" => 64,
        "siphash24" => 0,
        "aescmac" => 16,
        "blake2b256" => 32,
        "blake2b512" => 64,
        "blake2s" => 32,
        "blake3" => 32,
        "chacha20" => 32,
        _ => panic!("unexpected primitive {}", name),
    }
}

/// The three ITB key-bit widths (512, 1024, 2048) that are valid for a
/// given native hash width — a width is valid when key_bits is a
/// multiple of width.
fn key_bits_for(width: i32) -> Vec<i32> {
    [512, 1024, 2048]
        .into_iter()
        .filter(|k| k % width == 0)
        .collect()
}

fn build_plaintext() -> Vec<u8> {
    let mut p = b"any binary data, including 0x00 bytes -- ".to_vec();
    p.extend((0u32..256).map(|i| i as u8));
    p
}

#[test]
fn test_roundtrip_all_hashes() {
    let plaintext = build_plaintext();

    for (name, width) in CANONICAL_HASHES {
        for key_bits in key_bits_for(*width) {
            // Day 1 — random seeds.
            let ns = Seed::new(name, key_bits).unwrap();
            let ds = Seed::new(name, key_bits).unwrap();
            let ss = Seed::new(name, key_bits).unwrap();
            let ns_comps = ns.components().unwrap();
            let ds_comps = ds.components().unwrap();
            let ss_comps = ss.components().unwrap();
            let ns_key = ns.hash_key().unwrap();
            let ds_key = ds.hash_key().unwrap();
            let ss_key = ss.hash_key().unwrap();

            assert_eq!(
                ns_comps.len() * 64,
                key_bits as usize,
                "components count mismatch hash={} bits={}",
                name,
                key_bits,
            );
            assert_eq!(
                ns_key.len(),
                expected_hash_key_len(name),
                "hash_key length mismatch hash={}",
                name,
            );

            let ciphertext = itb::encrypt(&ns, &ds, &ss, &plaintext).unwrap();
            drop(ns);
            drop(ds);
            drop(ss);

            // Day 2 — restore from saved material.
            let ns2 = Seed::from_components(name, &ns_comps, &ns_key).unwrap();
            let ds2 = Seed::from_components(name, &ds_comps, &ds_key).unwrap();
            let ss2 = Seed::from_components(name, &ss_comps, &ss_key).unwrap();
            let decrypted = itb::decrypt(&ns2, &ds2, &ss2, &ciphertext).unwrap();
            assert_eq!(decrypted, plaintext, "hash={} bits={}", name, key_bits);

            // Restored seeds report the same components + key.
            assert_eq!(ns2.components().unwrap(), ns_comps);
            assert_eq!(ns2.hash_key().unwrap(), ns_key);
        }
    }
}

#[test]
fn test_random_key_path() {
    // 512-bit zero components — sufficient for non-SipHash primitives.
    let components: Vec<u64> = vec![0u64; 8];
    for (name, _) in CANONICAL_HASHES {
        let seed = Seed::from_components(name, &components, &[]).unwrap();
        let key = seed.hash_key().unwrap();
        if *name == "siphash24" {
            assert_eq!(key.len(), 0, "siphash24 must report empty key");
        } else {
            assert_eq!(
                key.len(),
                expected_hash_key_len(name),
                "primitive={}", name,
            );
        }
    }
}

#[test]
fn test_explicit_key_preserved() {
    // BLAKE3 has a 32-byte symmetric key.
    let explicit: Vec<u8> = (0u8..32).collect();
    let components: Vec<u64> = vec![0xCAFEBABE_DEADBEEF; 8];
    let seed = Seed::from_components("blake3", &components, &explicit).unwrap();
    assert_eq!(seed.hash_key().unwrap(), explicit);
}

#[test]
fn test_bad_key_size() {
    // A non-empty hash_key whose length does not match the primitive's
    // expected length must surface a clean ITBError (no panic across
    // the FFI). Seven bytes is wrong for blake3 (expects 32).
    let components: Vec<u64> = vec![0u64; 16];
    let bad_key = [0u8; 7];
    let result = Seed::from_components("blake3", &components, &bad_key);
    assert!(result.is_err(), "expected from_components to reject 7-byte key for blake3");
}

#[test]
fn test_siphash_rejects_hash_key() {
    // SipHash-2-4 takes no internal fixed key; passing one must be
    // rejected (not silently ignored).
    let components: Vec<u64> = vec![0u64; 8];
    let nonempty = [0u8; 16];
    let result = Seed::from_components("siphash24", &components, &nonempty);
    assert!(
        result.is_err(),
        "siphash24 must reject a non-empty hash_key argument",
    );
}
