//! Cross-process persistence round-trip tests for the high-level
//! [`itb::Encryptor`] surface — Rust mirror of
//! `bindings/python/tests/easy/test_persistence.py`.
//!
//! The [`Encryptor::export`] / [`Encryptor::import_state`] /
//! [`itb::peek_config`] triplet is the persistence surface required
//! for any deployment where encrypt and decrypt run in different
//! processes (network, storage, backup, microservices). Without the
//! JSON-encoded blob captured at encrypt-side and re-supplied at
//! decrypt-side, the encryptor state cannot be reconstructed and the
//! ciphertext is unreadable.

#[path = "common/mod.rs"]
#[allow(dead_code)]
mod common;

use itb::{peek_config, Encryptor};
use std::sync::Mutex;

// Serialises the four import_mismatch_* tests that read
// `itb::last_mismatch_field()` against each other. The accessor
// reads a process-wide errno-style buffer shared across all
// threads in the address space; cargo's default test threading
// races the four tests against each other within this binary,
// overwriting the recorded field name between the failing
// import_state call and the assert_eq. Other tests in this file
// do not trigger STATUS_EASY_MISMATCH, so a lock shared only
// across these four is sufficient — no need to gate the rest.
static MISMATCH_FIELD_LOCK: Mutex<()> = Mutex::new(());

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

fn expected_prf_key_len(name: &str) -> usize {
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
        _ => panic!("unknown hash {name}"),
    }
}

fn key_bits_for(width: i32) -> Vec<i32> {
    [512i32, 1024, 2048].iter().copied().filter(|k| k % width == 0).collect()
}

fn canonical_plaintext_single() -> Vec<u8> {
    let mut v: Vec<u8> = b"any binary data, including 0x00 bytes -- ".to_vec();
    v.extend((0u16..256).map(|i| i as u8));
    v
}

fn canonical_plaintext_triple() -> Vec<u8> {
    let mut v: Vec<u8> = b"triple-mode persistence payload ".to_vec();
    v.extend((0u8..64).collect::<Vec<u8>>());
    v
}

// ─── TestPersistenceRoundtrip ──────────────────────────────────────

#[test]
fn roundtrip_all_hashes_single() {
    let plaintext = canonical_plaintext_single();
    for &(name, width) in CANONICAL_HASHES {
        for &key_bits in &key_bits_for(width) {
            // Day 1 — random encryptor.
            let mut src =
                Encryptor::new(Some(name), Some(key_bits), Some("kmac256"), 1).unwrap();
            let blob = src.export().unwrap();
            let ct = src.encrypt_auth(&plaintext).unwrap();
            src.free().unwrap();

            // Day 2 — restore from saved blob.
            let mut dst =
                Encryptor::new(Some(name), Some(key_bits), Some("kmac256"), 1).unwrap();
            dst.import_state(&blob).unwrap();
            let pt = dst.decrypt_auth(&ct).unwrap();
            assert_eq!(pt.as_slice(), plaintext.as_slice());
            dst.free().unwrap();
        }
    }
}

#[test]
fn roundtrip_all_hashes_triple() {
    let plaintext = canonical_plaintext_triple();
    for &(name, width) in CANONICAL_HASHES {
        for &key_bits in &key_bits_for(width) {
            let mut src =
                Encryptor::new(Some(name), Some(key_bits), Some("kmac256"), 3).unwrap();
            let blob = src.export().unwrap();
            let ct = src.encrypt_auth(&plaintext).unwrap();
            src.free().unwrap();

            let mut dst =
                Encryptor::new(Some(name), Some(key_bits), Some("kmac256"), 3).unwrap();
            dst.import_state(&blob).unwrap();
            let pt = dst.decrypt_auth(&ct).unwrap();
            assert_eq!(pt.as_slice(), plaintext.as_slice());
            dst.free().unwrap();
        }
    }
}

#[test]
fn roundtrip_with_lock_seed() {
    // Activating LockSeed grows the encryptor to 4 (Single) or 8
    // (Triple) seed slots; the exported blob carries the dedicated
    // lockSeed material via the `lock_seed:true` field, and
    // [`Encryptor::import_state`] on a fresh encryptor restores the
    // seed slot AND auto-couples LockSoup + BitSoup overlays.
    let mut plaintext: Vec<u8> = b"lockseed payload ".to_vec();
    plaintext.extend(0u8..32);

    for (mode, expected_count) in [(1, 4), (3, 8)] {
        let mut src =
            Encryptor::new(Some("blake3"), Some(1024), Some("kmac256"), mode).unwrap();
        src.set_lock_seed(1).unwrap();
        assert_eq!(src.seed_count().unwrap(), expected_count);
        let blob = src.export().unwrap();
        let ct = src.encrypt_auth(&plaintext).unwrap();
        src.free().unwrap();

        let mut dst =
            Encryptor::new(Some("blake3"), Some(1024), Some("kmac256"), mode).unwrap();
        assert_eq!(dst.seed_count().unwrap(), expected_count - 1);
        dst.import_state(&blob).unwrap();
        assert_eq!(dst.seed_count().unwrap(), expected_count);
        let pt = dst.decrypt_auth(&ct).unwrap();
        assert_eq!(pt.as_slice(), plaintext.as_slice());
        dst.free().unwrap();
    }
}

#[test]
fn roundtrip_with_full_config() {
    // Per-instance configuration knobs (NonceBits, BarrierFill,
    // BitSoup, LockSoup) round-trip through the state blob along
    // with the seed material — no manual mirror set_*() calls
    // required on the receiver. The blob carries the fields that
    // the sender explicitly set; the receiver's import_state restores
    // them transparently.
    let mut plaintext: Vec<u8> = b"full-config persistence ".to_vec();
    plaintext.extend(0u8..64);

    let mut src = Encryptor::new(Some("blake3"), Some(1024), Some("kmac256"), 1).unwrap();
    src.set_nonce_bits(512).unwrap();
    src.set_barrier_fill(4).unwrap();
    src.set_bit_soup(1).unwrap();
    src.set_lock_soup(1).unwrap();
    let blob = src.export().unwrap();
    let ct = src.encrypt_auth(&plaintext).unwrap();
    src.free().unwrap();

    // Receiver — fresh encryptor without any mirror set_*() calls.
    let mut dst = Encryptor::new(Some("blake3"), Some(1024), Some("kmac256"), 1).unwrap();
    assert_eq!(dst.nonce_bits().unwrap(), 128); // default before Import
    dst.import_state(&blob).unwrap();
    assert_eq!(dst.nonce_bits().unwrap(), 512); // restored from blob
    assert_eq!(dst.header_size().unwrap(), 68); // follows nonce_bits

    let pt = dst.decrypt_auth(&ct).unwrap();
    assert_eq!(pt.as_slice(), plaintext.as_slice());
    dst.free().unwrap();
}

#[test]
fn roundtrip_barrier_fill_receiver_priority() {
    // BarrierFill is asymmetric — the receiver does not need the
    // same margin as the sender. When the receiver explicitly
    // installs a non-default BarrierFill before Import, that choice
    // takes priority over the blob's barrier_fill.
    let plaintext = b"barrier-fill priority";

    let mut src = Encryptor::new(Some("blake3"), Some(1024), Some("kmac256"), 1).unwrap();
    src.set_barrier_fill(4).unwrap();
    let blob = src.export().unwrap();
    let ct = src.encrypt_auth(plaintext).unwrap();
    src.free().unwrap();

    // Receiver pre-sets BarrierFill=8; Import must NOT downgrade it
    // to the blob's 4.
    let mut dst = Encryptor::new(Some("blake3"), Some(1024), Some("kmac256"), 1).unwrap();
    dst.set_barrier_fill(8).unwrap();
    dst.import_state(&blob).unwrap();
    let pt = dst.decrypt_auth(&ct).unwrap();
    assert_eq!(pt.as_slice(), plaintext);
    dst.free().unwrap();

    // A receiver that did NOT pre-set BarrierFill picks up the blob
    // value transparently.
    let mut dst2 =
        Encryptor::new(Some("blake3"), Some(1024), Some("kmac256"), 1).unwrap();
    dst2.import_state(&blob).unwrap();
    let pt2 = dst2.decrypt_auth(&ct).unwrap();
    assert_eq!(pt2.as_slice(), plaintext);
    dst2.free().unwrap();
}

// ─── TestPeekConfig ────────────────────────────────────────────────

#[test]
fn peek_recovers_metadata() {
    for &(primitive, width) in CANONICAL_HASHES {
        for &key_bits in &key_bits_for(width) {
            for mode in [1, 3] {
                for mac in ["kmac256", "hmac-sha256", "hmac-blake3"] {
                    let enc = Encryptor::new(
                        Some(primitive),
                        Some(key_bits),
                        Some(mac),
                        mode,
                    )
                    .unwrap();
                    let blob = enc.export().unwrap();
                    drop(enc);
                    let (p2, kb2, mode2, mac2) = peek_config(&blob).unwrap();
                    assert_eq!(p2, primitive);
                    assert_eq!(kb2, key_bits);
                    assert_eq!(mode2, mode);
                    assert_eq!(mac2, mac);
                }
            }
        }
    }
}

#[test]
fn peek_malformed_blob() {
    for blob in [
        b"not json".as_slice(),
        b"".as_slice(),
        b"{}".as_slice(),
        b"{\"v\":1}".as_slice(),
    ] {
        let err = peek_config(blob).unwrap_err();
        assert_eq!(err.code(), itb::STATUS_EASY_MALFORMED, "blob={blob:?}");
    }
}

#[test]
fn peek_too_new_version() {
    // Hand-craft a blob with v=99; PeekConfig must reject rather
    // than silently parsing. The peek path conflates "too-new
    // version" with the broader malformed-shape bucket and surfaces
    // STATUS_EASY_MALFORMED for either; the dedicated
    // STATUS_EASY_VERSION_TOO_NEW is reserved for the Import path
    // (covered by `import_too_new_version` in this file).
    let blob = b"{\"v\":99,\"kind\":\"itb-easy\"}";
    let err = peek_config(blob).unwrap_err();
    assert_eq!(err.code(), itb::STATUS_EASY_MALFORMED);
}

// ─── TestImportMismatch ────────────────────────────────────────────

fn make_baseline_blob() -> Vec<u8> {
    let src = Encryptor::new(Some("blake3"), Some(1024), Some("kmac256"), 1).unwrap();
    src.export().unwrap()
}

#[test]
fn import_mismatch_primitive() {
    let _guard = MISMATCH_FIELD_LOCK.lock().unwrap();
    let blob = make_baseline_blob();
    let dst = Encryptor::new(Some("blake2s"), Some(1024), Some("kmac256"), 1).unwrap();
    let err = dst.import_state(&blob).unwrap_err();
    assert_eq!(err.code(), itb::STATUS_EASY_MISMATCH);
    assert_eq!(itb::last_mismatch_field(), "primitive");
}

#[test]
fn import_mismatch_key_bits() {
    let _guard = MISMATCH_FIELD_LOCK.lock().unwrap();
    let blob = make_baseline_blob();
    let dst = Encryptor::new(Some("blake3"), Some(2048), Some("kmac256"), 1).unwrap();
    let err = dst.import_state(&blob).unwrap_err();
    assert_eq!(err.code(), itb::STATUS_EASY_MISMATCH);
    assert_eq!(itb::last_mismatch_field(), "key_bits");
}

#[test]
fn import_mismatch_mode() {
    let _guard = MISMATCH_FIELD_LOCK.lock().unwrap();
    let blob = make_baseline_blob();
    let dst = Encryptor::new(Some("blake3"), Some(1024), Some("kmac256"), 3).unwrap();
    let err = dst.import_state(&blob).unwrap_err();
    assert_eq!(err.code(), itb::STATUS_EASY_MISMATCH);
    assert_eq!(itb::last_mismatch_field(), "mode");
}

#[test]
fn import_mismatch_mac() {
    let _guard = MISMATCH_FIELD_LOCK.lock().unwrap();
    let blob = make_baseline_blob();
    let dst = Encryptor::new(Some("blake3"), Some(1024), Some("hmac-sha256"), 1).unwrap();
    let err = dst.import_state(&blob).unwrap_err();
    assert_eq!(err.code(), itb::STATUS_EASY_MISMATCH);
    assert_eq!(itb::last_mismatch_field(), "mac");
}

// ─── TestImportMalformed ───────────────────────────────────────────

#[test]
fn import_malformed_json() {
    let enc = Encryptor::new(Some("blake3"), Some(1024), Some("kmac256"), 1).unwrap();
    let err = enc.import_state(b"this is not json").unwrap_err();
    assert_eq!(err.code(), itb::STATUS_EASY_MALFORMED);
}

#[test]
fn import_too_new_version() {
    let enc = Encryptor::new(Some("blake3"), Some(1024), Some("kmac256"), 1).unwrap();
    let blob = b"{\"v\":99,\"kind\":\"itb-easy\"}";
    let err = enc.import_state(blob).unwrap_err();
    assert_eq!(err.code(), itb::STATUS_EASY_VERSION_TOO_NEW);
}

#[test]
fn import_wrong_kind() {
    let enc = Encryptor::new(Some("blake3"), Some(1024), Some("kmac256"), 1).unwrap();
    let blob = b"{\"v\":1,\"kind\":\"not-itb-easy\"}";
    let err = enc.import_state(blob).unwrap_err();
    assert_eq!(err.code(), itb::STATUS_EASY_MALFORMED);
}

// ─── TestMaterialGetters ───────────────────────────────────────────

#[test]
fn prf_key_lengths_per_primitive() {
    for &(name, width) in CANONICAL_HASHES {
        for &key_bits in &key_bits_for(width) {
            let enc =
                Encryptor::new(Some(name), Some(key_bits), Some("kmac256"), 1).unwrap();
            if name == "siphash24" {
                assert!(!enc.has_prf_keys().unwrap());
                assert!(enc.prf_key(0).is_err());
            } else {
                assert!(enc.has_prf_keys().unwrap());
                let count = enc.seed_count().unwrap();
                for slot in 0..count {
                    let key = enc.prf_key(slot).unwrap();
                    assert_eq!(
                        key.len(),
                        expected_prf_key_len(name),
                        "name={name} slot={slot}",
                    );
                }
            }
        }
    }
}

#[test]
fn seed_components_lengths_per_key_bits() {
    for &(name, width) in CANONICAL_HASHES {
        for &key_bits in &key_bits_for(width) {
            let enc =
                Encryptor::new(Some(name), Some(key_bits), Some("kmac256"), 1).unwrap();
            let count = enc.seed_count().unwrap();
            for slot in 0..count {
                let comps = enc.seed_components(slot).unwrap();
                assert_eq!(comps.len() as i32 * 64, key_bits);
            }
        }
    }
}

#[test]
fn mac_key_present() {
    for mac in ["kmac256", "hmac-sha256", "hmac-blake3"] {
        let enc = Encryptor::new(Some("blake3"), Some(1024), Some(mac), 1).unwrap();
        assert!(!enc.mac_key().unwrap().is_empty());
    }
}

#[test]
fn seed_components_out_of_range() {
    let enc = Encryptor::new(Some("blake3"), Some(1024), Some("kmac256"), 1).unwrap();
    assert_eq!(enc.seed_count().unwrap(), 3);
    let err = enc.seed_components(3).unwrap_err();
    assert_eq!(err.code(), itb::STATUS_BAD_INPUT);
    let err = enc.seed_components(-1).unwrap_err();
    assert_eq!(err.code(), itb::STATUS_BAD_INPUT);
}
