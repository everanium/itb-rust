//! Phase-3 smoke: confirm Seed, MAC, and the low-level encrypt /
//! decrypt entry points round-trip plaintext correctly. Covers
//! Single, Triple, and Authenticated variants.

use itb::{Seed, MAC};

const PLAINTEXT: &[u8] = b"Lorem ipsum dolor sit amet, consectetur adipiscing elit.";

#[test]
fn single_roundtrip_blake3() {
    let n = Seed::new("blake3", 1024).unwrap();
    let d = Seed::new("blake3", 1024).unwrap();
    let s = Seed::new("blake3", 1024).unwrap();
    let ct = itb::encrypt(&n, &d, &s, PLAINTEXT).unwrap();
    assert_ne!(ct.as_slice(), PLAINTEXT);
    let pt = itb::decrypt(&n, &d, &s, &ct).unwrap();
    assert_eq!(pt.as_slice(), PLAINTEXT);
}

#[test]
fn triple_roundtrip_blake3() {
    let n = Seed::new("blake3", 1024).unwrap();
    let d1 = Seed::new("blake3", 1024).unwrap();
    let d2 = Seed::new("blake3", 1024).unwrap();
    let d3 = Seed::new("blake3", 1024).unwrap();
    let s1 = Seed::new("blake3", 1024).unwrap();
    let s2 = Seed::new("blake3", 1024).unwrap();
    let s3 = Seed::new("blake3", 1024).unwrap();
    let ct = itb::encrypt_triple(&n, &d1, &d2, &d3, &s1, &s2, &s3, PLAINTEXT).unwrap();
    let pt = itb::decrypt_triple(&n, &d1, &d2, &d3, &s1, &s2, &s3, &ct).unwrap();
    assert_eq!(pt.as_slice(), PLAINTEXT);
}

#[test]
fn auth_roundtrip_hmac_sha256() {
    let n = Seed::new("blake3", 1024).unwrap();
    let d = Seed::new("blake3", 1024).unwrap();
    let s = Seed::new("blake3", 1024).unwrap();
    let mac = MAC::new("hmac-sha256", &[0x42u8; 32]).unwrap();
    let ct = itb::encrypt_auth(&n, &d, &s, &mac, PLAINTEXT).unwrap();
    let pt = itb::decrypt_auth(&n, &d, &s, &mac, &ct).unwrap();
    assert_eq!(pt.as_slice(), PLAINTEXT);
}

#[test]
fn auth_triple_roundtrip_kmac256() {
    let n = Seed::new("blake3", 1024).unwrap();
    let d1 = Seed::new("blake3", 1024).unwrap();
    let d2 = Seed::new("blake3", 1024).unwrap();
    let d3 = Seed::new("blake3", 1024).unwrap();
    let s1 = Seed::new("blake3", 1024).unwrap();
    let s2 = Seed::new("blake3", 1024).unwrap();
    let s3 = Seed::new("blake3", 1024).unwrap();
    let mac = MAC::new("kmac256", &[0x21u8; 32]).unwrap();
    let ct = itb::encrypt_auth_triple(&n, &d1, &d2, &d3, &s1, &s2, &s3, &mac, PLAINTEXT).unwrap();
    let pt = itb::decrypt_auth_triple(&n, &d1, &d2, &d3, &s1, &s2, &s3, &mac, &ct).unwrap();
    assert_eq!(pt.as_slice(), PLAINTEXT);
}

#[test]
fn seed_components_roundtrip() {
    let s = Seed::new("blake3", 1024).unwrap();
    let comps = s.components().unwrap();
    let key = s.hash_key().unwrap();
    let s2 = Seed::from_components("blake3", &comps, &key).unwrap();
    // The two seeds must produce identical components / key.
    assert_eq!(s.components().unwrap(), s2.components().unwrap());
    assert_eq!(s.hash_key().unwrap(), s2.hash_key().unwrap());
}

#[test]
fn auth_decrypt_tampered_fails_with_mac_failure() {
    let n = Seed::new("blake3", 1024).unwrap();
    let d = Seed::new("blake3", 1024).unwrap();
    let s = Seed::new("blake3", 1024).unwrap();
    let mac = MAC::new("hmac-sha256", &[0u8; 32]).unwrap();
    let mut ct = itb::encrypt_auth(&n, &d, &s, &mac, PLAINTEXT).unwrap();
    // Flip the last byte to tamper with the MAC tag.
    let last = ct.len() - 1;
    ct[last] ^= 0xff;
    let err = itb::decrypt_auth(&n, &d, &s, &mac, &ct).unwrap_err();
    assert_eq!(err.code(), itb::STATUS_MAC_FAILURE);
}

#[test]
fn seed_drop_does_not_panic() {
    // Construct + drop in a tight loop; the Drop impl must not double-free.
    for _ in 0..32 {
        let _ = Seed::new("blake3", 512).unwrap();
    }
}

// Note: a test for `Seed::attach_lock_seed` lives in the Phase-5 suite,
// where the global `set_lock_soup` knob is serialised via a shared
// Mutex so it does not race with other roundtrip tests under cargo's
// parallel test runner.

// --------------------------------------------------------------------
// Phase-5 extension — full Python-parity coverage. Tests below mirror
// the remaining method names from `bindings/python/tests/test_roundtrip.py`.
// --------------------------------------------------------------------

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

#[test]
fn test_version() {
    let v = itb::version().unwrap();
    assert!(!v.is_empty());
    // Must look like a SemVer-ish prefix "<digits>.<digits>.<digits>".
    let mut iter = v.split('.');
    let a = iter.next().unwrap_or("");
    let b = iter.next().unwrap_or("");
    let c = iter.next().unwrap_or("");
    assert!(a.chars().all(|ch| ch.is_ascii_digit()), "major: {}", v);
    assert!(b.chars().all(|ch| ch.is_ascii_digit()), "minor: {}", v);
    assert!(
        c.chars().take_while(|ch| ch.is_ascii_digit()).count() > 0,
        "patch: {}",
        v,
    );
}

#[test]
fn test_list_hashes() {
    let got = itb::list_hashes().unwrap();
    let expected: Vec<(String, i32)> = CANONICAL_HASHES
        .iter()
        .map(|(n, w)| (n.to_string(), *w))
        .collect();
    assert_eq!(got, expected);
}

#[test]
fn test_constants() {
    assert_eq!(itb::max_key_bits(), 2048);
    assert_eq!(itb::channels(), 8);
}

#[test]
fn test_new_and_free() {
    let s = Seed::new("blake3", 1024).unwrap();
    assert_ne!(s.handle(), 0);
    assert_eq!(s.hash_name(), "blake3");
    assert_eq!(s.width().unwrap(), 256);
    s.free().unwrap();
}

#[test]
fn test_bad_hash() {
    let result = Seed::new("nonsense-hash", 1024);
    let err = match result {
        Ok(_) => panic!("expected Seed::new to fail on bad hash name"),
        Err(e) => e,
    };
    assert_eq!(err.code(), itb::STATUS_BAD_HASH);
}

#[test]
fn test_bad_key_bits() {
    for bits in [0, 256, 511, 2049] {
        let result = Seed::new("blake3", bits);
        let err = match result {
            Ok(_) => panic!("expected Seed::new to fail on key_bits={}", bits),
            Err(e) => e,
        };
        assert_eq!(err.code(), itb::STATUS_BAD_KEY_BITS, "bits={}", bits);
    }
}

#[test]
fn test_all_hashes_all_widths_single() {
    let plaintext = pseudo_payload(4096);
    for (name, _) in CANONICAL_HASHES {
        for key_bits in [512, 1024, 2048] {
            let ns = Seed::new(name, key_bits).unwrap();
            let ds = Seed::new(name, key_bits).unwrap();
            let ss = Seed::new(name, key_bits).unwrap();
            let ct = itb::encrypt(&ns, &ds, &ss, &plaintext).unwrap();
            assert!(ct.len() > plaintext.len(), "ciphertext must be longer than plaintext");
            let pt = itb::decrypt(&ns, &ds, &ss, &ct).unwrap();
            assert_eq!(pt, plaintext, "hash={} bits={}", name, key_bits);
        }
    }
}

#[test]
fn test_seed_width_mismatch() {
    let ns = Seed::new("siphash24", 1024).unwrap(); // width 128
    let ds = Seed::new("blake3", 1024).unwrap(); // width 256
    let ss = Seed::new("blake3", 1024).unwrap(); // width 256
    let err = itb::encrypt(&ns, &ds, &ss, b"hello").unwrap_err();
    assert_eq!(err.code(), itb::STATUS_SEED_WIDTH_MIX);
}

#[test]
fn test_all_hashes_all_widths_triple() {
    let plaintext = pseudo_payload(4096);
    for (name, _) in CANONICAL_HASHES {
        for key_bits in [512, 1024, 2048] {
            let s0 = Seed::new(name, key_bits).unwrap();
            let s1 = Seed::new(name, key_bits).unwrap();
            let s2 = Seed::new(name, key_bits).unwrap();
            let s3 = Seed::new(name, key_bits).unwrap();
            let s4 = Seed::new(name, key_bits).unwrap();
            let s5 = Seed::new(name, key_bits).unwrap();
            let s6 = Seed::new(name, key_bits).unwrap();
            let ct = itb::encrypt_triple(
                &s0, &s1, &s2, &s3, &s4, &s5, &s6, &plaintext,
            )
            .unwrap();
            assert!(ct.len() > plaintext.len());
            let pt = itb::decrypt_triple(
                &s0, &s1, &s2, &s3, &s4, &s5, &s6, &ct,
            )
            .unwrap();
            assert_eq!(pt, plaintext, "hash={} bits={}", name, key_bits);
        }
    }
}

#[test]
fn test_triple_seed_width_mismatch() {
    // One width-128 seed mixed with six width-256 seeds.
    let odd = Seed::new("siphash24", 1024).unwrap();
    let r1 = Seed::new("blake3", 1024).unwrap();
    let r2 = Seed::new("blake3", 1024).unwrap();
    let r3 = Seed::new("blake3", 1024).unwrap();
    let r4 = Seed::new("blake3", 1024).unwrap();
    let r5 = Seed::new("blake3", 1024).unwrap();
    let r6 = Seed::new("blake3", 1024).unwrap();
    let err = itb::encrypt_triple(&odd, &r1, &r2, &r3, &r4, &r5, &r6, b"hello").unwrap_err();
    assert_eq!(err.code(), itb::STATUS_SEED_WIDTH_MIX);
}

// Note: the Python TestConfig tests (`test_bit_soup_roundtrip`,
// `test_lock_soup_roundtrip`, `test_max_workers_roundtrip`,
// `test_nonce_bits_validation`, `test_barrier_fill_validation`) mutate
// the libitb process-global atomics (BitSoup / LockSoup / MaxWorkers /
// NonceBits / BarrierFill). The cargo test runner dispatches every
// `#[test]` fn in this binary on a parallel thread pool, and the
// existing pre-Phase-5 tests in this file (`single_roundtrip_blake3`
// etc.) read those globals indirectly via `encrypt` / `decrypt`. A
// parallel writer mutating, say, NonceBits in the middle of an
// encrypt's two-phase probe-then-write idiom races the writer's value
// into the second-phase buffer-size mismatch. The global-state
// mutation tests therefore live in dedicated lock-only test binaries
// (`test_nonce_sizes.rs`, `test_attach_lock_seed.rs`) where every
// `#[test]` holds `common::serial_lock()` and the existing roundtrip
// tests in this file remain race-free.

fn pseudo_payload(n: usize) -> Vec<u8> {
    (0..n).map(|i| ((i * 17 + 5) & 0xff) as u8).collect()
}
