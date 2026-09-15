//! Error-mapping surface: opaque-string relay, closed Pipeline,
//! unknown profile, duplicate profile registration (with an 8-entry
//! `hashes` constellation).

use itb3::{ItbStatus, OptsBuilder, Pipeline, Profile, lookup, register};

#[test]
fn unknown_profile_is_distinct_status_with_diagnostic() {
    let err = Pipeline::init("no-such-profile", &OptsBuilder::new()).unwrap_err();
    assert_eq!(err.status(), Some(ItbStatus::UnknownProfile));
    assert!(!err.to_string().is_empty());
    let err = lookup("no-such-profile").unwrap_err();
    assert_eq!(err.status(), Some(ItbStatus::UnknownProfile));
}

#[test]
fn unknown_opts_key_is_bad_input() {
    // Typoed key (lowercase s) — Go rejects unknown keys.
    let opts = OptsBuilder::new().with_raw("chunksize", "4096");
    let err = Pipeline::init("singlemsg-triple-mac-v1", &opts).unwrap_err();
    assert_eq!(err.status(), Some(ItbStatus::BadInput));
}

#[test]
fn negative_max_workers_in_opts_is_clamped() {
    let opts = OptsBuilder::new().with_max_workers(-1);
    let p = Pipeline::init("singlemsg-triple-mac-v1", &opts).unwrap();
    let wire = p.encrypt_message(b"clamped").unwrap();
    assert_eq!(p.decrypt_message(&wire).unwrap(), b"clamped");
}

#[test]
fn closed_pipeline_reports_triple_closed() {
    let mut p = Pipeline::init("singlemsg-triple-mac-v1", &OptsBuilder::new()).unwrap();
    p.close().unwrap();
    p.close().unwrap(); // idempotent
    let err = p.encrypt_message(b"payload").unwrap_err();
    assert_eq!(err.status(), Some(ItbStatus::TripleClosed));
    let err = p.save().unwrap_err();
    assert_eq!(err.status(), Some(ItbStatus::TripleClosed));
    let err = p.max_workers(2).unwrap_err();
    assert_eq!(err.status(), Some(ItbStatus::TripleClosed));
}

#[test]
fn register_mixed_then_duplicate() {
    // 8-entry width-256 hashes constellation, layers off.
    let profile = Profile {
        mode: "singlemsg-nomac".into(),
        width: 256,
        mixed_hashes: [
            "blake3", "blake2s", "areion256", "blake2b256", "chacha20", "blake3", "blake2s",
            "areion256",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect(),
        key_bits: 1024,
        ..Profile::default()
    };
    register("rust-binding-test-mixed", &profile).unwrap();

    // The registered profile round-trips and reads back.
    let sender = Pipeline::init("rust-binding-test-mixed", &OptsBuilder::new()).unwrap();
    let receiver = Pipeline::load(&sender.save().unwrap(), None).unwrap();
    let wire = sender.encrypt_message(b"custom profile").unwrap();
    assert_eq!(receiver.decrypt_message(&wire).unwrap(), b"custom profile");
    let back = lookup("rust-binding-test-mixed").unwrap();
    assert_eq!(back.name, "rust-binding-test-mixed");
    assert_eq!(back.mixed_hashes, profile.mixed_hashes);

    // Duplicate name is a distinct status.
    let err = register("rust-binding-test-mixed", &profile).unwrap_err();
    assert_eq!(err.status(), Some(ItbStatus::ProfileExists));
}

#[test]
fn register_rejects_name_mismatch_inside_record() {
    let mut profile = lookup("singlemsg-triple-nomac-v1").unwrap();
    profile.name = "some-other-name".into();
    let err = register("rust-binding-test-mismatch", &profile).unwrap_err();
    assert_eq!(err.status(), Some(ItbStatus::BadInput));
}

#[test]
fn opaque_primitive_name_relay() {
    // An unknown inner-hash name is relayed to Go and rejected there —
    // the binding performs no name validation of its own.
    let opts = OptsBuilder::new().with_inner_hash("no-such-hash");
    let err = Pipeline::init("singlemsg-triple-mac-v1", &opts).unwrap_err();
    assert!(err.status().is_some());
    assert_ne!(err.status(), Some(ItbStatus::Ok));
}

#[test]
fn per_call_inner_hashes_override_round_trips() {
    // The single-primitive width-512 base profile takes an 8-slot
    // per-call MixedHashes override (Go-side Opts.MixedHashes, wired
    // through the innerHashes= opts key). The blob carries the
    // resolved constellation, so the receiver needs no override.
    let mix = [
        "areion512", "blake2b512", "areion512", "blake2b512",
        "areion512", "blake2b512", "areion512", "blake2b512",
    ];
    let sender_opts = OptsBuilder::new().with_inner_hashes(&mix);
    let sender = Pipeline::init("singlemsg-triple-mac-v1", &sender_opts).unwrap();
    let receiver = Pipeline::load(&sender.save().unwrap(), None).unwrap();
    let plain = b"per-call inner-hashes override round-trip payload";
    let wire = sender.encrypt_message(plain).unwrap();
    assert_eq!(receiver.decrypt_message(&wire).unwrap(), plain);
    let prof = itb3::inspect(&sender.save().unwrap()).unwrap();
    assert_eq!(prof.mixed_hashes, mix);
}
