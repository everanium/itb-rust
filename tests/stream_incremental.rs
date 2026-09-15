//! Explicit write / end / read round trip with pathological batch
//! sizes (17-byte feed, 23-byte drain) across multiple chunks.

use itb3::{OptsBuilder, Pipeline};

#[test]
fn incremental_tiny_batches() {
    // Small chunk size so the 64 KiB payload spans many chunks.
    let opts = OptsBuilder::new().with_chunk_size(4096);
    let sender = Pipeline::init("streaming-aead-triple-mac-v1", &opts).unwrap();
    let receiver =
        Pipeline::load(&sender.save().unwrap(), None).unwrap();

    let plain: Vec<u8> = (0..65_536).map(|i| (i % 241) as u8).collect();

    // Encrypt: 17-byte writes, then end + 23-byte drains.
    let mut wire = Vec::new();
    {
        let mut sess = sender.encrypt_stream().unwrap();
        for piece in plain.chunks(17) {
            sess.write(piece).unwrap();
        }
        sess.end().unwrap();
        let mut buf = [0u8; 23];
        loop {
            let (n, fin) = sess.read(&mut buf).unwrap();
            wire.extend_from_slice(&buf[..n]);
            if fin {
                break;
            }
        }
    }
    assert!(!wire.is_empty());

    // Decrypt with the same pathological batch sizes.
    let mut back = Vec::new();
    {
        let mut sess = receiver.decrypt_stream().unwrap();
        for piece in wire.chunks(17) {
            sess.write(piece).unwrap();
        }
        sess.end().unwrap();
        let mut buf = [0u8; 23];
        loop {
            let (n, fin) = sess.read(&mut buf).unwrap();
            back.extend_from_slice(&buf[..n]);
            if fin {
                break;
            }
        }
    }
    assert_eq!(back, plain);
}
