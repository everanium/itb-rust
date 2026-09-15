//! Round trip through the stream pumps on a Streaming AEAD profile.

use std::io::Cursor;

use itb3::{OptsBuilder, Pipeline};

#[test]
fn pump_round_trip_1mib() {
    let opts = OptsBuilder::new();
    let sender = Pipeline::init("streaming-aead-triple-mac-v1", &opts).unwrap();
    let receiver =
        Pipeline::load(&sender.save().unwrap(), None).unwrap();

    let plain: Vec<u8> = (0..(1 << 20)).map(|i| (i % 251) as u8).collect();

    let mut wire = Vec::new();
    sender
        .encrypt_stream_pump(Cursor::new(&plain), &mut wire)
        .unwrap();
    assert!(!wire.is_empty());

    let mut back = Vec::new();
    receiver
        .decrypt_stream_pump(Cursor::new(&wire), &mut back)
        .unwrap();
    assert_eq!(back, plain);
}

#[test]
fn pump_matches_one_shot() {
    let opts = OptsBuilder::new();
    let sender = Pipeline::init("streaming-aead-triple-mac-v1", &opts).unwrap();
    let receiver =
        Pipeline::load(&sender.save().unwrap(), None).unwrap();

    let plain: Vec<u8> = (0..65_536).map(|i| (i % 199) as u8).collect();
    let wire = sender.encrypt_stream_one_shot(&plain).unwrap();

    let mut back = Vec::new();
    receiver
        .decrypt_stream_pump(Cursor::new(&wire), &mut back)
        .unwrap();
    assert_eq!(back, plain);

    let back2 = receiver.decrypt_stream_one_shot(&wire).unwrap();
    assert_eq!(back2, plain);
}
