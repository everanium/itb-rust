//! Integration tests for the low-level [`itb::Seed::attach_lock_seed`]
//! mutator. The dedicated lockSeed routes the bit-permutation derivation
//! through its own state instead of the noiseSeed: the per-chunk PRF
//! closure captures BOTH the lockSeed's components AND its hash function,
//! so the lockSeed primitive may legitimately differ from the noiseSeed
//! primitive within the same native hash width — keying-material isolation
//! plus algorithm diversity for defence-in-depth on the bit-permutation
//! channel, without changing the public encrypt / decrypt signatures.
//!
//! The bit-permutation overlay must be engaged via [`itb::set_bit_soup`]
//! or [`itb::set_lock_soup`] before any encrypt call — without the
//! overlay, the dedicated lockSeed has no observable effect on the wire
//! output, and the Go-side build-PRF guard surfaces as `ITBError`. These
//! tests exercise both the round-trip path with overlay engaged and the
//! attach-time misuse rejections (self-attach, post-encrypt switching,
//! width mismatch).

use itb::Seed;

#[path = "common/mod.rs"]
mod common;

/// Engages set_lock_soup(1) for the duration of the test body, then
/// restores the prior values. The set_lock_soup setter auto-couples
/// BitSoup=1 inside libitb, so both flags are restored on exit.
fn with_lock_soup_on<F: FnOnce()>(body: F) {
    let prev_bs = itb::get_bit_soup();
    let prev_ls = itb::get_lock_soup();
    itb::set_lock_soup(1).unwrap();
    body();
    itb::set_bit_soup(prev_bs).unwrap();
    itb::set_lock_soup(prev_ls).unwrap();
}

#[test]
fn test_roundtrip() {
    let _g = common::serial_lock();
    let plaintext = b"attach_lock_seed roundtrip payload";
    with_lock_soup_on(|| {
        let ns = Seed::new("blake3", 1024).unwrap();
        let ds = Seed::new("blake3", 1024).unwrap();
        let ss = Seed::new("blake3", 1024).unwrap();
        let ls = Seed::new("blake3", 1024).unwrap();
        ns.attach_lock_seed(&ls).unwrap();
        let ct = itb::encrypt(&ns, &ds, &ss, plaintext).unwrap();
        let pt = itb::decrypt(&ns, &ds, &ss, &ct).unwrap();
        assert_eq!(pt.as_slice(), plaintext);
    });
}

#[test]
fn test_persistence() {
    let _g = common::serial_lock();
    let plaintext = b"cross-process attach lockseed roundtrip";
    with_lock_soup_on(|| {
        // Day 1 — sender.
        let ns = Seed::new("blake3", 1024).unwrap();
        let ds = Seed::new("blake3", 1024).unwrap();
        let ss = Seed::new("blake3", 1024).unwrap();
        let ls = Seed::new("blake3", 1024).unwrap();
        ns.attach_lock_seed(&ls).unwrap();

        let ns_comps = ns.components().unwrap();
        let ds_comps = ds.components().unwrap();
        let ss_comps = ss.components().unwrap();
        let ls_comps = ls.components().unwrap();
        let ns_key = ns.hash_key().unwrap();
        let ds_key = ds.hash_key().unwrap();
        let ss_key = ss.hash_key().unwrap();
        let ls_key = ls.hash_key().unwrap();

        let ct = itb::encrypt(&ns, &ds, &ss, plaintext).unwrap();

        drop(ns);
        drop(ds);
        drop(ss);
        drop(ls);

        // Day 2 — receiver.
        let ns2 = Seed::from_components("blake3", &ns_comps, &ns_key).unwrap();
        let ds2 = Seed::from_components("blake3", &ds_comps, &ds_key).unwrap();
        let ss2 = Seed::from_components("blake3", &ss_comps, &ss_key).unwrap();
        let ls2 = Seed::from_components("blake3", &ls_comps, &ls_key).unwrap();

        ns2.attach_lock_seed(&ls2).unwrap();
        let pt = itb::decrypt(&ns2, &ds2, &ss2, &ct).unwrap();
        assert_eq!(pt.as_slice(), plaintext);
    });
}

#[test]
fn test_self_attach_rejected() {
    let _g = common::serial_lock();
    let ns = Seed::new("blake3", 1024).unwrap();
    let err = ns.attach_lock_seed(&ns).unwrap_err();
    assert_eq!(err.code(), itb::STATUS_BAD_INPUT);
}

#[test]
fn test_width_mismatch_rejected() {
    let _g = common::serial_lock();
    let ns_256 = Seed::new("blake3", 1024).unwrap(); // width 256
    let ls_128 = Seed::new("siphash24", 1024).unwrap(); // width 128
    let err = ns_256.attach_lock_seed(&ls_128).unwrap_err();
    assert_eq!(err.code(), itb::STATUS_SEED_WIDTH_MIX);
}

#[test]
fn test_post_encrypt_attach_rejected() {
    let _g = common::serial_lock();
    with_lock_soup_on(|| {
        let ns = Seed::new("blake3", 1024).unwrap();
        let ds = Seed::new("blake3", 1024).unwrap();
        let ss = Seed::new("blake3", 1024).unwrap();
        let ls = Seed::new("blake3", 1024).unwrap();
        ns.attach_lock_seed(&ls).unwrap();
        // Encrypt once — locks future attach_lock_seed calls.
        itb::encrypt(&ns, &ds, &ss, b"pre-switch").unwrap();
        let ls2 = Seed::new("blake3", 1024).unwrap();
        let err = ns.attach_lock_seed(&ls2).unwrap_err();
        assert_eq!(err.code(), itb::STATUS_BAD_INPUT);
    });
}

#[test]
fn test_overlay_off_panics_on_encrypt() {
    let _g = common::serial_lock();
    let prev_bs = itb::get_bit_soup();
    let prev_ls = itb::get_lock_soup();
    itb::set_bit_soup(0).unwrap();
    itb::set_lock_soup(0).unwrap();
    let ns = Seed::new("blake3", 1024).unwrap();
    let ds = Seed::new("blake3", 1024).unwrap();
    let ss = Seed::new("blake3", 1024).unwrap();
    let ls = Seed::new("blake3", 1024).unwrap();
    ns.attach_lock_seed(&ls).unwrap();
    let result = itb::encrypt(&ns, &ds, &ss, b"overlay off - should panic");
    assert!(result.is_err(), "encrypt with attached lockSeed but overlay off must surface ITBError");
    itb::set_bit_soup(prev_bs).unwrap();
    itb::set_lock_soup(prev_ls).unwrap();
}
