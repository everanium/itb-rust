//! Init → save → Load → EncryptMessage → DecryptMessage round trip.

use itb3::{OptsBuilder, Pipeline};

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
