//! Phase-4 smoke: confirm Blob256 round-trips Single-Ouroboros
//! material plus a MAC key + name through export / import.

use itb::{Blob256, SLOT_D, SLOT_N, SLOT_S};

#[test]
fn blob256_single_export_import_roundtrip() {
    // Sender: stage hash keys + components into a fresh Blob256.
    let sender = Blob256::new().unwrap();

    let key_n: Vec<u8> = (0..32u8).map(|i| 0xa0 ^ i).collect();
    let key_d: Vec<u8> = (0..32u8).map(|i| 0xb0 ^ i).collect();
    let key_s: Vec<u8> = (0..32u8).map(|i| 0xc0 ^ i).collect();
    let comps_n: Vec<u64> = (0..16u64).map(|i| 0x1000 + i).collect();
    let comps_d: Vec<u64> = (0..16u64).map(|i| 0x2000 + i).collect();
    let comps_s: Vec<u64> = (0..16u64).map(|i| 0x3000 + i).collect();
    let mac_key: Vec<u8> = (0..32u8).map(|i| 0xd0 ^ i).collect();

    sender.set_key(SLOT_N, &key_n).unwrap();
    sender.set_components(SLOT_N, &comps_n).unwrap();
    sender.set_key(SLOT_D, &key_d).unwrap();
    sender.set_components(SLOT_D, &comps_d).unwrap();
    sender.set_key(SLOT_S, &key_s).unwrap();
    sender.set_components(SLOT_S, &comps_s).unwrap();
    sender.set_mac_key(Some(&mac_key)).unwrap();
    sender.set_mac_name(Some("kmac256")).unwrap();

    let blob_bytes = sender.export(false, true).unwrap();
    assert!(!blob_bytes.is_empty());

    // Receiver: a fresh Blob256 imports the bytes and the slot
    // contents must match the originals.
    let receiver = Blob256::new().unwrap();
    receiver.import_blob(&blob_bytes).unwrap();

    assert_eq!(receiver.width().unwrap(), 256);
    assert_eq!(receiver.mode().unwrap(), 1);

    assert_eq!(receiver.get_key(SLOT_N).unwrap(), key_n);
    assert_eq!(receiver.get_key(SLOT_D).unwrap(), key_d);
    assert_eq!(receiver.get_key(SLOT_S).unwrap(), key_s);
    assert_eq!(receiver.get_components(SLOT_N).unwrap(), comps_n);
    assert_eq!(receiver.get_components(SLOT_D).unwrap(), comps_d);
    assert_eq!(receiver.get_components(SLOT_S).unwrap(), comps_s);
    assert_eq!(receiver.get_mac_key().unwrap(), mac_key);
    assert_eq!(receiver.get_mac_name().unwrap(), "kmac256");
}

#[test]
fn blob256_freshly_constructed_has_unset_mode() {
    let b = Blob256::new().unwrap();
    assert_eq!(b.width().unwrap(), 256);
    assert_eq!(b.mode().unwrap(), 0);
}

#[test]
fn blob_slot_from_name_round_trip() {
    assert_eq!(itb::slot_from_name("n"), Some(SLOT_N));
    assert_eq!(itb::slot_from_name("D"), Some(SLOT_D));
    assert_eq!(itb::slot_from_name("S3"), Some(itb::SLOT_S3));
    assert_eq!(itb::slot_from_name("nope"), None);
}

#[test]
fn blob_drop_does_not_panic() {
    for _ in 0..16 {
        let _ = Blob256::new().unwrap();
    }
}

// --------------------------------------------------------------------
// Phase-5 extension — full Python-parity coverage. Mirrors the
// remaining test classes / methods from
// `bindings/python/tests/test_blob.py`.
// --------------------------------------------------------------------

#[path = "common/mod.rs"]
mod common;

use itb::{Blob128, Blob512, MAC, Seed, SLOT_D1, SLOT_D2, SLOT_D3, SLOT_L,
          SLOT_S1, SLOT_S2, SLOT_S3};

/// Snapshots the four globals on entry, sets non-default values for
/// the test body, restores on exit. Mirrors `_with_globals` from
/// `test_blob.py`.
fn with_globals<F: FnOnce()>(body: F) {
    let prev_nonce = itb::get_nonce_bits();
    let prev_barrier = itb::get_barrier_fill();
    let prev_bs = itb::get_bit_soup();
    let prev_ls = itb::get_lock_soup();
    itb::set_nonce_bits(512).unwrap();
    itb::set_barrier_fill(4).unwrap();
    itb::set_bit_soup(1).unwrap();
    itb::set_lock_soup(1).unwrap();
    body();
    itb::set_nonce_bits(prev_nonce).unwrap();
    itb::set_barrier_fill(prev_barrier).unwrap();
    itb::set_bit_soup(prev_bs).unwrap();
    itb::set_lock_soup(prev_ls).unwrap();
}

/// Forces all four globals to their defaults so an Import-applied
/// snapshot can be detected via post-Import reads.
fn reset_globals() {
    itb::set_nonce_bits(128).unwrap();
    itb::set_barrier_fill(1).unwrap();
    itb::set_bit_soup(0).unwrap();
    itb::set_lock_soup(0).unwrap();
}

fn assert_globals_restored(nonce: i32, barrier: i32, bit_soup: i32, lock_soup: i32) {
    assert_eq!(itb::get_nonce_bits(), nonce, "NonceBits not restored");
    assert_eq!(itb::get_barrier_fill(), barrier, "BarrierFill not restored");
    assert_eq!(itb::get_bit_soup(), bit_soup, "BitSoup not restored");
    assert_eq!(itb::get_lock_soup(), lock_soup, "LockSoup not restored");
}

#[test]
fn test_construct_each_width() {
    let b1 = Blob128::new().unwrap();
    assert_eq!(b1.width().unwrap(), 128);
    assert_eq!(b1.mode().unwrap(), 0);
    assert_ne!(b1.handle(), 0);

    let b2 = Blob256::new().unwrap();
    assert_eq!(b2.width().unwrap(), 256);
    assert_eq!(b2.mode().unwrap(), 0);
    assert_ne!(b2.handle(), 0);

    let b3 = Blob512::new().unwrap();
    assert_eq!(b3.width().unwrap(), 512);
    assert_eq!(b3.mode().unwrap(), 0);
    assert_ne!(b3.handle(), 0);
}

#[test]
fn test_blob512_single_full_matrix() {
    let _g = common::serial_lock();
    let plaintext = b"rs blob512 single round-trip payload";
    for with_ls in [false, true] {
        for with_mac in [false, true] {
            with_globals(|| {
                blob512_single_one(plaintext, with_ls, with_mac);
            });
        }
    }
}

fn blob512_single_one(plaintext: &[u8], with_ls: bool, with_mac: bool) {
    let primitive = "areion512";
    let key_bits = 2048;
    let ns = Seed::new(primitive, key_bits).unwrap();
    let ds = Seed::new(primitive, key_bits).unwrap();
    let ss = Seed::new(primitive, key_bits).unwrap();

    let ls = if with_ls {
        let l = Seed::new(primitive, key_bits).unwrap();
        ns.attach_lock_seed(&l).unwrap();
        Some(l)
    } else {
        None
    };

    let mac_key: Vec<u8> = (0..32u8).map(|i| 0x55 ^ i).collect();
    let mac = if with_mac {
        Some(MAC::new("kmac256", &mac_key).unwrap())
    } else {
        None
    };

    let ct = if let Some(m) = &mac {
        itb::encrypt_auth(&ns, &ds, &ss, m, plaintext).unwrap()
    } else {
        itb::encrypt(&ns, &ds, &ss, plaintext).unwrap()
    };

    let src = Blob512::new().unwrap();
    src.set_key(SLOT_N, &ns.hash_key().unwrap()).unwrap();
    src.set_key(SLOT_D, &ds.hash_key().unwrap()).unwrap();
    src.set_key(SLOT_S, &ss.hash_key().unwrap()).unwrap();
    src.set_components(SLOT_N, &ns.components().unwrap()).unwrap();
    src.set_components(SLOT_D, &ds.components().unwrap()).unwrap();
    src.set_components(SLOT_S, &ss.components().unwrap()).unwrap();
    if let Some(l) = &ls {
        src.set_key(SLOT_L, &l.hash_key().unwrap()).unwrap();
        src.set_components(SLOT_L, &l.components().unwrap()).unwrap();
    }
    if with_mac {
        src.set_mac_key(Some(&mac_key)).unwrap();
        src.set_mac_name(Some("kmac256")).unwrap();
    }
    let blob = src.export(with_ls, with_mac).unwrap();

    reset_globals();
    let dst = Blob512::new().unwrap();
    dst.import_blob(&blob).unwrap();
    assert_eq!(dst.mode().unwrap(), 1);
    assert_globals_restored(512, 4, 1, 1);

    let ns2 = Seed::from_components(
        primitive,
        &dst.get_components(SLOT_N).unwrap(),
        &dst.get_key(SLOT_N).unwrap(),
    )
    .unwrap();
    let ds2 = Seed::from_components(
        primitive,
        &dst.get_components(SLOT_D).unwrap(),
        &dst.get_key(SLOT_D).unwrap(),
    )
    .unwrap();
    let ss2 = Seed::from_components(
        primitive,
        &dst.get_components(SLOT_S).unwrap(),
        &dst.get_key(SLOT_S).unwrap(),
    )
    .unwrap();
    let ls2 = if with_ls {
        let l = Seed::from_components(
            primitive,
            &dst.get_components(SLOT_L).unwrap(),
            &dst.get_key(SLOT_L).unwrap(),
        )
        .unwrap();
        ns2.attach_lock_seed(&l).unwrap();
        Some(l)
    } else {
        None
    };

    let mac2 = if with_mac {
        assert_eq!(dst.get_mac_name().unwrap(), "kmac256");
        assert_eq!(dst.get_mac_key().unwrap(), mac_key);
        Some(MAC::new("kmac256", &dst.get_mac_key().unwrap()).unwrap())
    } else {
        None
    };

    let pt = if let Some(m) = &mac2 {
        itb::decrypt_auth(&ns2, &ds2, &ss2, m, &ct).unwrap()
    } else {
        itb::decrypt(&ns2, &ds2, &ss2, &ct).unwrap()
    };
    assert_eq!(pt.as_slice(), plaintext);

    drop(ls2); // keep ls2 alive until after decrypt above
    drop(ls);
}

#[test]
fn test_blob512_triple_full_matrix() {
    let _g = common::serial_lock();
    let plaintext = b"rs blob512 triple round-trip payload";
    for with_ls in [false, true] {
        for with_mac in [false, true] {
            with_globals(|| {
                blob512_triple_one(plaintext, with_ls, with_mac);
            });
        }
    }
}

fn blob512_triple_one(plaintext: &[u8], with_ls: bool, with_mac: bool) {
    let primitive = "areion512";
    let key_bits = 2048;
    let ns = Seed::new(primitive, key_bits).unwrap();
    let ds1 = Seed::new(primitive, key_bits).unwrap();
    let ds2 = Seed::new(primitive, key_bits).unwrap();
    let ds3 = Seed::new(primitive, key_bits).unwrap();
    let ss1 = Seed::new(primitive, key_bits).unwrap();
    let ss2 = Seed::new(primitive, key_bits).unwrap();
    let ss3 = Seed::new(primitive, key_bits).unwrap();

    let ls = if with_ls {
        let l = Seed::new(primitive, key_bits).unwrap();
        ns.attach_lock_seed(&l).unwrap();
        Some(l)
    } else {
        None
    };

    let mac_key: Vec<u8> = (0..32u8).map(|i| 0x37 ^ i).collect();
    let mac = if with_mac {
        Some(MAC::new("kmac256", &mac_key).unwrap())
    } else {
        None
    };

    let ct = if let Some(m) = &mac {
        itb::encrypt_auth_triple(&ns, &ds1, &ds2, &ds3, &ss1, &ss2, &ss3, m, plaintext).unwrap()
    } else {
        itb::encrypt_triple(&ns, &ds1, &ds2, &ds3, &ss1, &ss2, &ss3, plaintext).unwrap()
    };

    let src = Blob512::new().unwrap();
    let pairs: [(i32, &Seed); 7] = [
        (SLOT_N, &ns),
        (SLOT_D1, &ds1),
        (SLOT_D2, &ds2),
        (SLOT_D3, &ds3),
        (SLOT_S1, &ss1),
        (SLOT_S2, &ss2),
        (SLOT_S3, &ss3),
    ];
    for (slot, seed) in pairs.iter() {
        src.set_key(*slot, &seed.hash_key().unwrap()).unwrap();
        src.set_components(*slot, &seed.components().unwrap()).unwrap();
    }
    if let Some(l) = &ls {
        src.set_key(SLOT_L, &l.hash_key().unwrap()).unwrap();
        src.set_components(SLOT_L, &l.components().unwrap()).unwrap();
    }
    if with_mac {
        src.set_mac_key(Some(&mac_key)).unwrap();
        src.set_mac_name(Some("kmac256")).unwrap();
    }
    let blob = src.export3(with_ls, with_mac).unwrap();

    reset_globals();
    let dst = Blob512::new().unwrap();
    dst.import_triple(&blob).unwrap();
    assert_eq!(dst.mode().unwrap(), 3);
    assert_globals_restored(512, 4, 1, 1);

    let rebuild = |slot: i32| -> Seed {
        Seed::from_components(
            primitive,
            &dst.get_components(slot).unwrap(),
            &dst.get_key(slot).unwrap(),
        )
        .unwrap()
    };
    let ns2 = rebuild(SLOT_N);
    let ds1_2 = rebuild(SLOT_D1);
    let ds2_2 = rebuild(SLOT_D2);
    let ds3_2 = rebuild(SLOT_D3);
    let ss1_2 = rebuild(SLOT_S1);
    let ss2_2 = rebuild(SLOT_S2);
    let ss3_2 = rebuild(SLOT_S3);
    let ls2 = if with_ls {
        let l = rebuild(SLOT_L);
        ns2.attach_lock_seed(&l).unwrap();
        Some(l)
    } else {
        None
    };

    let mac2 = if with_mac {
        Some(MAC::new("kmac256", &dst.get_mac_key().unwrap()).unwrap())
    } else {
        None
    };

    let pt = if let Some(m) = &mac2 {
        itb::decrypt_auth_triple(&ns2, &ds1_2, &ds2_2, &ds3_2, &ss1_2, &ss2_2, &ss3_2, m, &ct)
            .unwrap()
    } else {
        itb::decrypt_triple(&ns2, &ds1_2, &ds2_2, &ds3_2, &ss1_2, &ss2_2, &ss3_2, &ct).unwrap()
    };
    assert_eq!(pt.as_slice(), plaintext);

    drop(ls2);
    drop(ls);
}

#[test]
fn test_blob256_single() {
    let _g = common::serial_lock();
    with_globals(|| {
        let plaintext = b"rs blob256 single round-trip";
        let ns = Seed::new("blake3", 1024).unwrap();
        let ds = Seed::new("blake3", 1024).unwrap();
        let ss = Seed::new("blake3", 1024).unwrap();
        let ct = itb::encrypt(&ns, &ds, &ss, plaintext).unwrap();

        let src = Blob256::new().unwrap();
        for (slot, seed) in [(SLOT_N, &ns), (SLOT_D, &ds), (SLOT_S, &ss)] {
            src.set_key(slot, &seed.hash_key().unwrap()).unwrap();
            src.set_components(slot, &seed.components().unwrap()).unwrap();
        }
        let blob = src.export(false, false).unwrap();

        reset_globals();
        let dst = Blob256::new().unwrap();
        dst.import_blob(&blob).unwrap();
        assert_eq!(dst.mode().unwrap(), 1);
        let ns2 = Seed::from_components(
            "blake3",
            &dst.get_components(SLOT_N).unwrap(),
            &dst.get_key(SLOT_N).unwrap(),
        )
        .unwrap();
        let ds2 = Seed::from_components(
            "blake3",
            &dst.get_components(SLOT_D).unwrap(),
            &dst.get_key(SLOT_D).unwrap(),
        )
        .unwrap();
        let ss2 = Seed::from_components(
            "blake3",
            &dst.get_components(SLOT_S).unwrap(),
            &dst.get_key(SLOT_S).unwrap(),
        )
        .unwrap();
        let pt = itb::decrypt(&ns2, &ds2, &ss2, &ct).unwrap();
        assert_eq!(pt.as_slice(), plaintext);
    });
}

#[test]
fn test_blob256_triple() {
    let _g = common::serial_lock();
    with_globals(|| {
        let plaintext = b"rs blob256 triple round-trip";
        let s0 = Seed::new("blake3", 1024).unwrap();
        let s1 = Seed::new("blake3", 1024).unwrap();
        let s2 = Seed::new("blake3", 1024).unwrap();
        let s3 = Seed::new("blake3", 1024).unwrap();
        let s4 = Seed::new("blake3", 1024).unwrap();
        let s5 = Seed::new("blake3", 1024).unwrap();
        let s6 = Seed::new("blake3", 1024).unwrap();
        let ct = itb::encrypt_triple(&s0, &s1, &s2, &s3, &s4, &s5, &s6, plaintext).unwrap();

        let slots: [(i32, &Seed); 7] = [
            (SLOT_N, &s0),
            (SLOT_D1, &s1),
            (SLOT_D2, &s2),
            (SLOT_D3, &s3),
            (SLOT_S1, &s4),
            (SLOT_S2, &s5),
            (SLOT_S3, &s6),
        ];
        let src = Blob256::new().unwrap();
        for (slot, seed) in slots.iter() {
            src.set_key(*slot, &seed.hash_key().unwrap()).unwrap();
            src.set_components(*slot, &seed.components().unwrap()).unwrap();
        }
        let blob = src.export3(false, false).unwrap();

        reset_globals();
        let dst = Blob256::new().unwrap();
        dst.import_triple(&blob).unwrap();
        assert_eq!(dst.mode().unwrap(), 3);
        let rebuild = |slot: i32| -> Seed {
            Seed::from_components(
                "blake3",
                &dst.get_components(slot).unwrap(),
                &dst.get_key(slot).unwrap(),
            )
            .unwrap()
        };
        let ns2 = rebuild(SLOT_N);
        let d1 = rebuild(SLOT_D1);
        let d2 = rebuild(SLOT_D2);
        let d3 = rebuild(SLOT_D3);
        let st1 = rebuild(SLOT_S1);
        let st2 = rebuild(SLOT_S2);
        let st3 = rebuild(SLOT_S3);
        let pt = itb::decrypt_triple(&ns2, &d1, &d2, &d3, &st1, &st2, &st3, &ct).unwrap();
        assert_eq!(pt.as_slice(), plaintext);
    });
}

#[test]
fn test_blob128_siphash_single() {
    let _g = common::serial_lock();
    with_globals(|| {
        let plaintext = b"rs blob128 siphash round-trip";
        let ns = Seed::new("siphash24", 512).unwrap();
        let ds = Seed::new("siphash24", 512).unwrap();
        let ss = Seed::new("siphash24", 512).unwrap();
        let ct = itb::encrypt(&ns, &ds, &ss, plaintext).unwrap();

        let src = Blob128::new().unwrap();
        for (slot, seed) in [(SLOT_N, &ns), (SLOT_D, &ds), (SLOT_S, &ss)] {
            src.set_key(slot, &seed.hash_key().unwrap()).unwrap(); // empty
            src.set_components(slot, &seed.components().unwrap()).unwrap();
        }
        let blob = src.export(false, false).unwrap();

        reset_globals();
        let dst = Blob128::new().unwrap();
        dst.import_blob(&blob).unwrap();
        let ns2 = Seed::from_components(
            "siphash24",
            &dst.get_components(SLOT_N).unwrap(),
            &[],
        )
        .unwrap();
        let ds2 = Seed::from_components(
            "siphash24",
            &dst.get_components(SLOT_D).unwrap(),
            &[],
        )
        .unwrap();
        let ss2 = Seed::from_components(
            "siphash24",
            &dst.get_components(SLOT_S).unwrap(),
            &[],
        )
        .unwrap();
        let pt = itb::decrypt(&ns2, &ds2, &ss2, &ct).unwrap();
        assert_eq!(pt.as_slice(), plaintext);
    });
}

#[test]
fn test_blob128_aescmac_single() {
    let _g = common::serial_lock();
    with_globals(|| {
        let plaintext = b"rs blob128 aescmac round-trip";
        let ns = Seed::new("aescmac", 512).unwrap();
        let ds = Seed::new("aescmac", 512).unwrap();
        let ss = Seed::new("aescmac", 512).unwrap();
        let ct = itb::encrypt(&ns, &ds, &ss, plaintext).unwrap();

        let src = Blob128::new().unwrap();
        for (slot, seed) in [(SLOT_N, &ns), (SLOT_D, &ds), (SLOT_S, &ss)] {
            src.set_key(slot, &seed.hash_key().unwrap()).unwrap();
            src.set_components(slot, &seed.components().unwrap()).unwrap();
        }
        let blob = src.export(false, false).unwrap();

        reset_globals();
        let dst = Blob128::new().unwrap();
        dst.import_blob(&blob).unwrap();
        let ns2 = Seed::from_components(
            "aescmac",
            &dst.get_components(SLOT_N).unwrap(),
            &dst.get_key(SLOT_N).unwrap(),
        )
        .unwrap();
        let ds2 = Seed::from_components(
            "aescmac",
            &dst.get_components(SLOT_D).unwrap(),
            &dst.get_key(SLOT_D).unwrap(),
        )
        .unwrap();
        let ss2 = Seed::from_components(
            "aescmac",
            &dst.get_components(SLOT_S).unwrap(),
            &dst.get_key(SLOT_S).unwrap(),
        )
        .unwrap();
        let pt = itb::decrypt(&ns2, &ds2, &ss2, &ct).unwrap();
        assert_eq!(pt.as_slice(), plaintext);
    });
}

#[test]
fn test_string_and_int_slots_equivalent() {
    let b = Blob512::new().unwrap();
    let key: Vec<u8> = (0..64u8).map(|i| 0x9c ^ i).collect();
    let comps: Vec<u64> = vec![0xDEADBEEF_CAFEBABE; 8];
    // Set via string-resolved slot.
    let slot_n = itb::slot_from_name("n").unwrap();
    b.set_key(slot_n, &key).unwrap();
    b.set_components(slot_n, &comps).unwrap();
    // Read via integer SLOT_N (= 0). Must match.
    assert_eq!(b.get_key(SLOT_N).unwrap(), key);
    assert_eq!(b.get_components(SLOT_N).unwrap(), comps);
}

#[test]
fn test_invalid_slot_name() {
    // slot_from_name("nope") returns None — the equivalent of a
    // ValueError on the Python side (the string-to-int resolution
    // happens at the wrapper layer, not in libitb).
    assert!(itb::slot_from_name("nope").is_none());
}

#[test]
fn test_mode_mismatch() {
    let _g = common::serial_lock();
    with_globals(|| {
        let ns = Seed::new("areion512", 1024).unwrap();
        let ds = Seed::new("areion512", 1024).unwrap();
        let ss = Seed::new("areion512", 1024).unwrap();
        let src = Blob512::new().unwrap();
        for (slot, seed) in [(SLOT_N, &ns), (SLOT_D, &ds), (SLOT_S, &ss)] {
            src.set_key(slot, &seed.hash_key().unwrap()).unwrap();
            src.set_components(slot, &seed.components().unwrap()).unwrap();
        }
        let blob = src.export(false, false).unwrap();

        let dst = Blob512::new().unwrap();
        let err = dst.import_triple(&blob).unwrap_err();
        assert_eq!(err.code(), itb::STATUS_BLOB_MODE_MISMATCH);
    });
}

#[test]
fn test_malformed() {
    let b = Blob512::new().unwrap();
    let err = b.import_blob(b"{not json").unwrap_err();
    assert_eq!(err.code(), itb::STATUS_BLOB_MALFORMED);
}

#[test]
fn test_version_too_new() {
    // Hand-built JSON with v=99 (above any version this build
    // supports). Shape mirrors the Python test exactly.
    let zeros_64: String = "00".repeat(64);
    let zeros_8: String = (0..8).map(|_| "\"0\"").collect::<Vec<_>>().join(",");
    let doc = format!(
        "{{\"v\":99,\"mode\":1,\"key_bits\":512,\
         \"key_n\":\"{zk}\",\"key_d\":\"{zk}\",\"key_s\":\"{zk}\",\
         \"ns\":[{c}],\"ds\":[{c}],\"ss\":[{c}],\
         \"globals\":{{\"nonce_bits\":128,\"barrier_fill\":1,\"bit_soup\":0,\"lock_soup\":0}}}}",
        zk = zeros_64,
        c = zeros_8,
    );
    let b = Blob512::new().unwrap();
    let err = b.import_blob(doc.as_bytes()).unwrap_err();
    assert_eq!(err.code(), itb::STATUS_BLOB_VERSION_TOO_NEW);
}
