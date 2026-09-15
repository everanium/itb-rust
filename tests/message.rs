//! Single Message round trip across every shipped cipher profile at
//! small (4 KiB) and medium (256 KiB) payloads. The blob-only profile
//! has no cipher surface and is exercised in errors.rs instead.

use itb3::{OptsBuilder, Pipeline};

/// Deterministic non-trivial payload (xorshift fill).
fn payload(n: usize, seed: u64) -> Vec<u8> {
    let mut x = seed | 1;
    (0..n)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x as u8
        })
        .collect()
}

#[test]
fn message_round_trip_every_profile() {
    let profiles = [
        "streaming-aead-triple-mac-v1",
        "streaming-noaead-triple-v1",
        "singlemsg-triple-mac-v1",
        "singlemsg-triple-nomac-v1",
        "streaming-aead-triple-mac-mixed-v1",
        "streaming-noaead-triple-mixed-v1",
        "singlemsg-triple-mac-mixed-v1",
        "singlemsg-triple-nomac-mixed-v1",
    ];
    let opts = OptsBuilder::new();
    for profile in profiles {
        let sender =
            Pipeline::init(profile, &opts).unwrap_or_else(|e| panic!("init {profile}: {e}"));
        let receiver = Pipeline::load(&sender.save().unwrap(), None)
            .unwrap_or_else(|e| panic!("load {profile}: {e}"));
        for size in [4 * 1024, 256 * 1024] {
            let plain = payload(size, size as u64);
            let wire = sender
                .encrypt_message(&plain)
                .unwrap_or_else(|e| panic!("encrypt {profile} @{size}: {e}"));
            let back = receiver
                .decrypt_message(&wire)
                .unwrap_or_else(|e| panic!("decrypt {profile} @{size}: {e}"));
            assert_eq!(back, plain, "{profile} @{size}");
        }
    }
}
