//! End-to-end Rust binding tests for Authenticated Encryption.
//!
//! Mirrors `bindings/python/tests/test_auth.py`: the same matrix of
//! 3 MACs × 3 hash widths × {Single, Triple} round-trip plus tamper
//! rejection at the dynamic header offset and cross-MAC rejection.

use itb::{MAC, Seed};

const CANONICAL_MACS: &[(&str, i32, i32, i32)] = &[
    ("kmac256", 32, 32, 16),
    ("hmac-sha256", 32, 32, 16),
    ("hmac-blake3", 32, 32, 32),
];

// (hash, native width) representatives one per ITB key-width axis.
const HASH_BY_WIDTH: &[(&str, i32)] = &[
    ("siphash24", 128),
    ("blake3", 256),
    ("blake2b512", 512),
];

const KEY_BYTES: [u8; 32] = [0x42u8; 32];

#[test]
fn test_list_macs() {
    let got = itb::list_macs().unwrap();
    let expected: Vec<(String, i32, i32, i32)> = CANONICAL_MACS
        .iter()
        .map(|(n, ks, ts, mk)| (n.to_string(), *ks, *ts, *mk))
        .collect();
    assert_eq!(got, expected);
}

#[test]
fn test_create_and_free() {
    for (name, _, _, _) in CANONICAL_MACS {
        let m = MAC::new(name, &KEY_BYTES).unwrap();
        assert_ne!(m.handle(), 0);
        assert_eq!(m.name(), *name);
        m.free().unwrap();
    }
}

#[test]
fn test_mac_drop_release() {
    // Equivalent of the Python context-manager test: the Drop impl
    // must release the handle when the value goes out of scope.
    let h: usize;
    {
        let m = MAC::new("hmac-sha256", &KEY_BYTES).unwrap();
        h = m.handle();
        assert_ne!(h, 0);
    }
    // No explicit assertion possible after drop (handle is gone), but
    // a use-after-free in libitb would surface as a test crash here.
}

#[test]
fn test_bad_name() {
    let err = match MAC::new("nonsense-mac", &KEY_BYTES) {
        Ok(_) => panic!("expected MAC::new to fail on nonsense name"),
        Err(e) => e,
    };
    assert_eq!(err.code(), itb::STATUS_BAD_MAC);
}

#[test]
fn test_short_key() {
    for (name, _, _, min_key) in CANONICAL_MACS {
        let short = vec![0x11u8; (*min_key as usize) - 1];
        let err = match MAC::new(name, &short) {
            Ok(_) => panic!("expected MAC::new to fail on short key for {}", name),
            Err(e) => e,
        };
        assert_eq!(err.code(), itb::STATUS_BAD_INPUT, "mac={}", name);
    }
}

fn pseudo_plaintext(n: usize) -> Vec<u8> {
    (0..n).map(|i| (i & 0xff) as u8).collect()
}

#[test]
fn test_auth_roundtrip_all_macs_all_widths() {
    let plaintext = pseudo_plaintext(4096);
    for (mac_name, _, _, _) in CANONICAL_MACS {
        for (hash_name, _) in HASH_BY_WIDTH {
            let mac = MAC::new(mac_name, &KEY_BYTES).unwrap();
            let n = Seed::new(hash_name, 1024).unwrap();
            let d = Seed::new(hash_name, 1024).unwrap();
            let s = Seed::new(hash_name, 1024).unwrap();
            let ct = itb::encrypt_auth(&n, &d, &s, &mac, &plaintext).unwrap();
            let pt = itb::decrypt_auth(&n, &d, &s, &mac, &ct).unwrap();
            assert_eq!(pt, plaintext, "mac={} hash={}", mac_name, hash_name);

            // Tamper at the dynamic header offset.
            let mut tampered = ct.clone();
            let h = itb::header_size() as usize;
            let upper = std::cmp::min(h + 256, tampered.len());
            for b in &mut tampered[h..upper] {
                *b ^= 0x01;
            }
            let err = itb::decrypt_auth(&n, &d, &s, &mac, &tampered).unwrap_err();
            assert_eq!(err.code(), itb::STATUS_MAC_FAILURE);
        }
    }
}

#[test]
fn test_auth_triple_roundtrip_all_macs_all_widths() {
    let plaintext = pseudo_plaintext(4096);
    for (mac_name, _, _, _) in CANONICAL_MACS {
        for (hash_name, _) in HASH_BY_WIDTH {
            let mac = MAC::new(mac_name, &KEY_BYTES).unwrap();
            let n = Seed::new(hash_name, 1024).unwrap();
            let d1 = Seed::new(hash_name, 1024).unwrap();
            let d2 = Seed::new(hash_name, 1024).unwrap();
            let d3 = Seed::new(hash_name, 1024).unwrap();
            let s1 = Seed::new(hash_name, 1024).unwrap();
            let s2 = Seed::new(hash_name, 1024).unwrap();
            let s3 = Seed::new(hash_name, 1024).unwrap();
            let ct = itb::encrypt_auth_triple(
                &n, &d1, &d2, &d3, &s1, &s2, &s3, &mac, &plaintext,
            )
            .unwrap();
            let pt = itb::decrypt_auth_triple(
                &n, &d1, &d2, &d3, &s1, &s2, &s3, &mac, &ct,
            )
            .unwrap();
            assert_eq!(pt, plaintext, "mac={} hash={}", mac_name, hash_name);

            let mut tampered = ct.clone();
            let h = itb::header_size() as usize;
            let upper = std::cmp::min(h + 256, tampered.len());
            for b in &mut tampered[h..upper] {
                *b ^= 0x01;
            }
            let err = itb::decrypt_auth_triple(
                &n, &d1, &d2, &d3, &s1, &s2, &s3, &mac, &tampered,
            )
            .unwrap_err();
            assert_eq!(err.code(), itb::STATUS_MAC_FAILURE);
        }
    }
}

#[test]
fn test_cross_mac_different_primitive() {
    let n = Seed::new("blake3", 1024).unwrap();
    let d = Seed::new("blake3", 1024).unwrap();
    let s = Seed::new("blake3", 1024).unwrap();
    let enc_mac = MAC::new("kmac256", &KEY_BYTES).unwrap();
    let dec_mac = MAC::new("hmac-sha256", &KEY_BYTES).unwrap();
    let ct = itb::encrypt_auth(&n, &d, &s, &enc_mac, b"authenticated payload").unwrap();
    let err = itb::decrypt_auth(&n, &d, &s, &dec_mac, &ct).unwrap_err();
    assert_eq!(err.code(), itb::STATUS_MAC_FAILURE);
}

#[test]
fn test_cross_mac_same_primitive_different_key() {
    let n = Seed::new("blake3", 1024).unwrap();
    let d = Seed::new("blake3", 1024).unwrap();
    let s = Seed::new("blake3", 1024).unwrap();
    let key_a = [0x01u8; 32];
    let key_b = [0x02u8; 32];
    let enc_mac = MAC::new("hmac-sha256", &key_a).unwrap();
    let dec_mac = MAC::new("hmac-sha256", &key_b).unwrap();
    let ct = itb::encrypt_auth(&n, &d, &s, &enc_mac, b"authenticated payload").unwrap();
    let err = itb::decrypt_auth(&n, &d, &s, &dec_mac, &ct).unwrap_err();
    assert_eq!(err.code(), itb::STATUS_MAC_FAILURE);
}
