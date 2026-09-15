//! Minimal sender / receiver round trip over the Triple Pipeline.
//!
//! Run with `cargo run --example round_trip --release` (after
//! `./build.sh`).

use itb3::{OptsBuilder, Pipeline, set_gc_percent, set_memory_limit};

fn main() -> Result<(), itb3::ItbError> {
    // Cap the Go runtime's heap so a workload that scales up does
    // not grow scratch heaps between GC cycles.
    let _ = set_memory_limit(4 << 30);
    let _ = set_gc_percent(100);

    let opts = OptsBuilder::new();

    // Sender: fresh session against a shipped profile; the saved blob
    // is the session bundle the receiver needs.
    let sender = Pipeline::init("singlemsg-triple-mac-v1", &opts)?;

    // Receiver: reconstructed from the blob.
    let receiver = Pipeline::load(&sender.save()?, None)?;

    let plaintext = b"any text or binary data - including 0x00 bytes";
    let wire = sender.encrypt_message(plaintext)?;
    let recovered = receiver.decrypt_message(&wire)?;

    assert_eq!(recovered, plaintext);
    println!(
        "ok: {} plaintext bytes, {} wire bytes",
        plaintext.len(),
        wire.len()
    );
    Ok(())
}
