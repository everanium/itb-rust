//! Init → save → Load → EncryptMessage → DecryptMessage round trip.

use itb3::{ItbError, ItbStatus, OptsBuilder, Pipeline};

#[test]
fn smoke_round_trip() {
    let opts = OptsBuilder::new();
    let sender = Pipeline::init("singlemsg-triple-mac-v1", &opts).unwrap();
    let blob = sender.save().unwrap();
    assert!(!blob.is_empty());

    let receiver = Pipeline::load(&blob, None).unwrap();

    let plain = b"smoke round-trip payload".to_vec();
    let wire = sender.encrypt_message(&plain).unwrap();
    assert_ne!(wire, plain);

    let back = receiver.decrypt_message(&wire).unwrap();
    assert_eq!(back, plain);
}

#[test]
fn init_keys_round_trip_and_errors() {
    let opts = OptsBuilder::new();
    let masters: Vec<[u8; 32]> = (1u8..=8).map(|i| [0x11u8.wrapping_mul(i); 32]).collect();
    let p1 = Pipeline::init_keys("singlemsg-triple-mac-v1", &opts, &masters).unwrap();
    let p2 = Pipeline::init_keys("singlemsg-triple-mac-v1", &opts, &masters).unwrap();
    assert_eq!(p1.save().unwrap(), p2.save().unwrap());

    let plain = b"init_keys determinism payload";
    let wire = p1.encrypt_message(plain).unwrap();
    assert_eq!(p2.decrypt_message(&wire).unwrap(), plain);

    let mut dup = masters.clone();
    dup[1] = dup[0];
    match Pipeline::init_keys("singlemsg-triple-mac-v1", &opts, &dup) {
        Err(ItbError::Status { status, .. }) => assert_eq!(status, ItbStatus::BadInput),
        other => panic!("expected BadInput on duplicate keys, got {other:?}"),
    }

    let mut short: Vec<Vec<u8>> = masters.iter().map(|m| m.to_vec()).collect();
    short[0] = vec![1, 2, 3, 4, 5, 6, 7, 8];
    match Pipeline::init_keys("singlemsg-triple-mac-v1", &opts, &short) {
        Err(ItbError::Status { status, .. }) => assert_eq!(status, ItbStatus::BadInput),
        other => panic!("expected BadInput on short key, got {other:?}"),
    }
}
