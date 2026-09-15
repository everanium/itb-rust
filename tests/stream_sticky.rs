//! A decrypt session fed a tampered wire fails with a sticky MAC
//! failure. Uses a position probe rather than a single bit flip
//! because the over-sized container carries CSPRNG residue in the
//! non-payload area — a flip that lands inside the residue is
//! architecturally inert (residue is not payload) and the session
//! finishes clean. Probing 32 evenly-spaced positions makes the
//! all-residue probability negligible; the first position that
//! surfaces an error must give ITB_STATUS_MAC_FAILURE and remain
//! sticky on subsequent reads.

use itb3::{ItbStatus, OptsBuilder, Pipeline};

#[test]
fn tampered_wire_sticky_failure() {
    let opts = OptsBuilder::new();
    let sender = Pipeline::init("streaming-aead-triple-mac-v1", &opts).unwrap();
    let receiver =
        Pipeline::load(&sender.save().unwrap(), None).unwrap();

    let plain: Vec<u8> = (0..65_536).map(|i| (i % 227) as u8).collect();
    let base_wire = sender.encrypt_stream_one_shot(&plain).unwrap();
    assert!(
        base_wire.len() > 128,
        "wire too short to place a distributed probe: {} bytes",
        base_wire.len(),
    );

    const PROBES: usize = 32;
    // Evenly spread through the wire body; skip the first / last
    // 16 bytes so a hit against the outer envelope framing does
    // not muddy the observation.
    let body_start = 16usize;
    let body_end = base_wire.len().saturating_sub(16);
    let stride = (body_end - body_start) / PROBES;

    for probe in 0..PROBES {
        let idx = body_start + probe * stride;

        let mut wire = base_wire.clone();
        wire[idx] ^= 0x01;

        let mut sess = receiver.decrypt_stream().unwrap();
        // Ignore Write / End status — the failure may surface on
        // either side or only on the drain that follows.
        let _ = sess.write(&wire);
        let _ = sess.end();

        let mut buf = [0u8; 4096];
        let mut first_err = None;
        let mut finished_clean = false;
        loop {
            match sess.read(&mut buf) {
                Ok((_, true)) => {
                    finished_clean = true;
                    break;
                }
                Ok((_, false)) => continue,
                Err(e) => {
                    first_err = Some(e);
                    break;
                }
            }
        }
        if finished_clean {
            // Residue hit at this offset — try the next probe.
            continue;
        }
        let first = first_err.expect("read loop exited without error nor finish");
        let first_status = first.status().expect("error carries a status code");
        assert_eq!(
            first_status,
            ItbStatus::MacFailure,
            "expected MAC failure on tampered wire at probe {probe} (byte {idx}), got {first_status:?}",
        );

        // Sticky: a subsequent read reports the same status.
        let again = sess.read(&mut buf).unwrap_err();
        assert_eq!(again.status(), Some(first_status));
        return;
    }
    panic!(
        "no probe among {PROBES} evenly-spaced positions surfaced a MAC failure — \
         either the probe pattern is degenerate or authentication is not \
         covering the wire body it should",
    );
}
