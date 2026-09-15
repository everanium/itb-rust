//! Persistence surface: save / save_f / load / load_f round trips,
//! inspect, lookup / profiles, max_workers.

use itb3::{ItbStatus, OptsBuilder, Pipeline, Profile, inspect, lookup, profiles};

fn temp_path(tag: &str) -> std::path::PathBuf {
    let mut p = std::env::temp_dir();
    p.push(format!("itb-rust-{tag}-{}.blob", std::process::id()));
    p
}

#[test]
fn save_then_load_round_trip() {
    let sender = Pipeline::init("singlemsg-triple-mac-v1", &OptsBuilder::new()).unwrap();
    let blob = sender.save().unwrap();
    assert_eq!(sender.save().unwrap(), blob, "save is stable");
    let receiver = Pipeline::load(&blob, None).unwrap();
    let wire = sender.encrypt_message(b"in-memory").unwrap();
    assert_eq!(receiver.decrypt_message(&wire).unwrap(), b"in-memory");
    assert_eq!(receiver.save().unwrap(), blob, "load retains the blob bytes");
}

#[test]
fn save_f_then_load_f_round_trip() {
    let path = temp_path("persist");
    let sender = Pipeline::init("streaming-aead-triple-mac-v1", &OptsBuilder::new()).unwrap();
    sender.save_f(&path).unwrap();
    assert_eq!(std::fs::read(&path).unwrap(), sender.save().unwrap());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }
    let receiver = Pipeline::load_f(&path, None).unwrap();
    let wire = sender.encrypt_stream_one_shot(b"on-disk").unwrap();
    assert_eq!(receiver.decrypt_stream_one_shot(&wire).unwrap(), b"on-disk");
    std::fs::remove_file(&path).unwrap();
}

#[test]
fn load_f_missing_file_is_bad_input() {
    let err = Pipeline::load_f(temp_path("missing"), None).unwrap_err();
    assert_eq!(err.status(), Some(ItbStatus::BadInput));
}

#[test]
fn load_with_master_overrides() {
    let sender = Pipeline::init("singlemsg-triple-mac-v1", &OptsBuilder::new()).unwrap();
    let blob = sender.save().unwrap();
    let perm = [0x31u8; 32];
    let wrap = [0x32u8; 32];
    let receiver = Pipeline::load(&blob, Some((&perm, &wrap))).unwrap();
    let rotated = receiver.save().unwrap();
    assert_ne!(rotated, blob, "master overrides rotate the blob");
    // The override pair on the receiver equals a rekey on the sender.
    let mut sender = sender;
    sender.rekey(&perm, &wrap).unwrap();
    let wire = sender.encrypt_message(b"overrides").unwrap();
    assert_eq!(receiver.decrypt_message(&wire).unwrap(), b"overrides");
}

#[test]
fn inspect_reads_the_embedded_profile() {
    let sender = Pipeline::init("singlemsg-triple-mac-v1", &OptsBuilder::new()).unwrap();
    let prof = inspect(&sender.save().unwrap()).unwrap();
    assert_eq!(prof.name, "singlemsg-triple-mac-v1");
    assert_eq!(prof.mode, "singlemsg-mac");
    assert_eq!(prof.width, 512);
    assert_eq!(prof.inner_hash, "areion512");
    assert_eq!(prof.mac_name, "hmac-blake3");
    assert!(prof.wrapper && prof.parallax);
    // The recipe fields match the registry entry; the two
    // inspection-only fields separate the two records.
    let registry = lookup("singlemsg-triple-mac-v1").unwrap();
    assert_eq!(
        Profile {
            nonce_bits: None,
            barrier_fill: None,
            ..prof.clone()
        },
        registry,
        "inspect matches lookup on the recipe fields"
    );
    let err = inspect(b"not a blob").unwrap_err();
    assert_eq!(err.status(), Some(ItbStatus::BadInput));
}

#[test]
fn inspect_carries_the_runtime_globals_lookup_does_not() {
    // Defaults: the blob records the compile-in nonce width and
    // barrier fill margin, and inspect surfaces both.
    let sender = Pipeline::init("singlemsg-triple-mac-v1", &OptsBuilder::new()).unwrap();
    let prof = inspect(&sender.save().unwrap()).unwrap();
    assert_eq!(prof.nonce_bits, Some(512));
    assert_eq!(prof.barrier_fill, Some(1));

    // Per-Pipeline overrides travel through the blob into inspect.
    let tuned = Pipeline::init(
        "singlemsg-triple-mac-v1",
        &OptsBuilder::new().with_nonce_bits(256).with_barrier_fill(4),
    )
    .unwrap();
    let tuned_prof = inspect(&tuned.save().unwrap()).unwrap();
    assert_eq!(tuned_prof.nonce_bits, Some(256));
    assert_eq!(tuned_prof.barrier_fill, Some(4));

    // The registry entry is the recipe alone — neither field is part
    // of it, so both read as absent rather than as zero.
    let registry = lookup("singlemsg-triple-mac-v1").unwrap();
    assert_eq!(registry.nonce_bits, None);
    assert_eq!(registry.barrier_fill, None);

    // A lookup record still serialises without the two keys, so it
    // remains a valid register payload; an inspected one carries them.
    assert!(!registry.to_json().contains("nonce_bits"));
    assert!(!registry.to_json().contains("barrier_fill"));
    assert!(tuned_prof.to_json().contains("\"nonce_bits\":256"));
    assert!(tuned_prof.to_json().contains("\"barrier_fill\":4"));
}

#[test]
fn profiles_lists_the_shipped_catalogue() {
    let names = profiles().unwrap();
    assert!(names.iter().any(|n| n == "singlemsg-triple-mac-v1"));
    let mut sorted = names.clone();
    sorted.sort();
    assert_eq!(names, sorted);
    for n in &names {
        assert_eq!(lookup(n).unwrap().name, *n);
    }
}

#[test]
fn max_workers_clamps_and_round_trips() {
    let sender = Pipeline::init("singlemsg-triple-mac-v1", &OptsBuilder::new()).unwrap();
    sender.max_workers(2).unwrap();
    sender.max_workers(-1).unwrap();
    sender.max_workers(100_000).unwrap();
    let receiver = Pipeline::load(&sender.save().unwrap(), None).unwrap();
    receiver.max_workers(1).unwrap();
    let wire = sender.encrypt_message(b"workers").unwrap();
    assert_eq!(receiver.decrypt_message(&wire).unwrap(), b"workers");
}
