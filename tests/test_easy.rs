//! Phase-4 smoke: confirm the high-level Encryptor surface
//! round-trips plaintext under Single + Triple Ouroboros, authenticates
//! on tampered ciphertext, and survives the `export` /
//! `import_state` cycle on a fresh encryptor.
//!
//! Lock-soup-related coverage (set_lock_soup, set_lock_seed,
//! attach_lock_seed) lives in the Phase-5 suite where the global
//! `set_lock_soup` knob can be serialised under a shared mutex without
//! racing against parallel-runner peers.

use itb::{peek_config, Encryptor};

const PLAINTEXT: &[u8] = b"Lorem ipsum dolor sit amet, consectetur adipiscing elit.";

#[test]
fn single_roundtrip_blake3_kmac256() {
    let mut enc = Encryptor::new(Some("blake3"), Some(1024), Some("kmac256"), 1).unwrap();
    let ct = enc.encrypt(PLAINTEXT).unwrap();
    assert_ne!(ct.as_slice(), PLAINTEXT);
    let pt = enc.decrypt(&ct).unwrap();
    assert_eq!(pt.as_slice(), PLAINTEXT);

    // Verify the read-only field accessors on the constructed
    // encryptor reflect the constructor arguments.
    assert_eq!(enc.primitive().unwrap(), "blake3");
    assert_eq!(enc.key_bits().unwrap(), 1024);
    assert_eq!(enc.mode().unwrap(), 1);
    assert_eq!(enc.mac_name().unwrap(), "kmac256");
    assert!(!enc.is_mixed().unwrap());
    assert_eq!(enc.seed_count().unwrap(), 3);
}

#[test]
fn triple_roundtrip_areion512_kmac256() {
    let mut enc =
        Encryptor::new(Some("areion512"), Some(2048), Some("kmac256"), 3).unwrap();
    let ct = enc.encrypt(PLAINTEXT).unwrap();
    let pt = enc.decrypt(&ct).unwrap();
    assert_eq!(pt.as_slice(), PLAINTEXT);

    assert_eq!(enc.primitive().unwrap(), "areion512");
    assert_eq!(enc.mode().unwrap(), 3);
    assert_eq!(enc.seed_count().unwrap(), 7);
}

#[test]
fn auth_roundtrip_single() {
    let mut enc = Encryptor::new(Some("blake3"), Some(1024), Some("kmac256"), 1).unwrap();
    let ct = enc.encrypt_auth(PLAINTEXT).unwrap();
    let pt = enc.decrypt_auth(&ct).unwrap();
    assert_eq!(pt.as_slice(), PLAINTEXT);
}

#[test]
fn auth_decrypt_tampered_fails_with_mac_failure() {
    let mut enc = Encryptor::new(Some("blake3"), Some(1024), Some("kmac256"), 1).unwrap();
    let mut ct = enc.encrypt_auth(PLAINTEXT).unwrap();
    // Flip 256 bytes immediately after the chunk header; this region
    // sits inside the structured payload and is reliably MAC-covered
    // regardless of container-layout details, matching the tamper
    // convention used by the rest of the suite.
    let h = enc.header_size().unwrap() as usize;
    let end = std::cmp::min(h + 256, ct.len());
    for b in &mut ct[h..end] {
        *b ^= 0x01;
    }
    let err = enc.decrypt_auth(&ct).unwrap_err();
    assert_eq!(err.code(), itb::STATUS_MAC_FAILURE);
}

#[test]
fn export_import_roundtrip() {
    let mut enc = Encryptor::new(Some("blake3"), Some(1024), Some("kmac256"), 1).unwrap();
    let ct = enc.encrypt_auth(PLAINTEXT).unwrap();
    let blob = enc.export().unwrap();
    assert!(!blob.is_empty());

    // Peek-config the saved blob and reconstruct a fresh encryptor
    // bound to the same dimensions.
    let (primitive, key_bits, mode, mac_name) = peek_config(&blob).unwrap();
    assert_eq!(primitive, "blake3");
    assert_eq!(key_bits, 1024);
    assert_eq!(mode, 1);
    assert_eq!(mac_name, "kmac256");

    let mut dec = Encryptor::new(Some(&primitive), Some(key_bits), Some(&mac_name), mode)
        .unwrap();
    dec.import_state(&blob).unwrap();
    let pt = dec.decrypt_auth(&ct).unwrap();
    assert_eq!(pt.as_slice(), PLAINTEXT);
}

#[test]
fn peek_config_returns_correct_tuple() {
    let enc =
        Encryptor::new(Some("areion512"), Some(2048), Some("hmac-blake3"), 3).unwrap();
    let blob = enc.export().unwrap();
    let (primitive, key_bits, mode, mac_name) = peek_config(&blob).unwrap();
    assert_eq!(primitive, "areion512");
    assert_eq!(key_bits, 2048);
    assert_eq!(mode, 3);
    assert_eq!(mac_name, "hmac-blake3");
}

#[test]
fn mixed_single_three_same_width_primitives() {
    // Three 256-bit primitives — areion256, blake3, blake2s — share
    // the same native hash width, so mixed_single accepts them as a
    // valid noise / data / start trio at key_bits=1024 (a multiple
    // of 256).
    let mut enc =
        Encryptor::mixed_single("areion256", "blake3", "blake2s", None, 1024, "kmac256")
            .unwrap();
    assert!(enc.is_mixed().unwrap());
    assert_eq!(enc.primitive_at(0).unwrap(), "areion256");
    assert_eq!(enc.primitive_at(1).unwrap(), "blake3");
    assert_eq!(enc.primitive_at(2).unwrap(), "blake2s");

    let ct = enc.encrypt_auth(PLAINTEXT).unwrap();
    let pt = enc.decrypt_auth(&ct).unwrap();
    assert_eq!(pt.as_slice(), PLAINTEXT);
}

#[test]
fn invalid_mode_rejected() {
    match Encryptor::new(Some("blake3"), Some(1024), Some("kmac256"), 2) {
        Ok(_) => panic!("expected mode=2 to be rejected"),
        Err(e) => assert_eq!(e.code(), itb::STATUS_BAD_INPUT),
    }
}

#[test]
fn close_is_idempotent() {
    let mut enc = Encryptor::new(Some("blake3"), Some(1024), Some("kmac256"), 1).unwrap();
    enc.close().unwrap();
    enc.close().unwrap();
}

#[test]
fn header_size_matches_nonce_bits() {
    let enc = Encryptor::new(Some("blake3"), Some(1024), Some("kmac256"), 1).unwrap();
    let nb = enc.nonce_bits().unwrap();
    let hs = enc.header_size().unwrap();
    // header = nonce(N) + width(2) + height(2)
    assert_eq!(hs, nb / 8 + 4);
}

#[test]
fn parse_chunk_len_matches_chunk_length() {
    let mut enc = Encryptor::new(Some("blake3"), Some(1024), Some("kmac256"), 1).unwrap();
    let ct = enc.encrypt(PLAINTEXT).unwrap();
    let hs = enc.header_size().unwrap() as usize;
    let parsed = enc.parse_chunk_len(&ct[..hs]).unwrap();
    assert_eq!(parsed, ct.len());
}
