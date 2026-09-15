//! Dropping an encrypt session mid-flight cleans up and leaves the
//! Pipeline usable.

use itb3::{OptsBuilder, Pipeline};

#[test]
fn drop_mid_flight_then_reuse_pipeline() {
    let opts = OptsBuilder::new();
    let sender = Pipeline::init("streaming-aead-triple-mac-v1", &opts).unwrap();

    {
        let mut sess = sender.encrypt_stream().unwrap();
        sess.write(&vec![0xA5u8; 100_000]).unwrap();
        // Dropped here without end() — Drop cancels and frees the
        // session; the test passing (process not hanging) is the
        // assertion.
    }

    // The Pipeline stays usable after the cancelled session.
    let receiver =
        Pipeline::load(&sender.save().unwrap(), None).unwrap();
    let wire = sender.encrypt_message(b"after cancel").unwrap();
    assert_eq!(receiver.decrypt_message(&wire).unwrap(), b"after cancel");
}
