//! Init → Rekey → Load receiver with the rotated blob → round trip.

use itb3::{OptsBuilder, Pipeline};

#[test]
fn rekey_round_trip() {
    let opts = OptsBuilder::new();
    let mut sender = Pipeline::init("singlemsg-triple-mac-v1", &opts).unwrap();
    let blob_before = sender.save().unwrap();

    let perm = [0x11u8; 32];
    let wrap = [0x22u8; 32];
    let rotated = sender.rekey(&perm, &wrap).unwrap();
    assert_ne!(rotated, blob_before, "rekey must refresh the blob");
    assert_eq!(sender.save().unwrap(), rotated, "save reports the rotated blob");

    let receiver = Pipeline::load(&rotated, None).unwrap();
    let plain = b"post-rekey payload".to_vec();
    let wire = sender.encrypt_message(&plain).unwrap();
    assert_eq!(receiver.decrypt_message(&wire).unwrap(), plain);
}
