//! Plaintext content: the payload modes, the seeded per-worker
//! generator, and the buffer fill from the operating-system CSPRNG.

/// Payload mode selector values for the --payload-mode flag.
///
///   - fixed: one CSPRNG-generated buffer per worker, held unchanged
///     for the whole run (the default).
///   - rotating: the buffer is regenerated before every iteration, so
///     no two encrypt calls see the same plaintext.
///   - pattern-zero / pattern-ff: degenerate constant fills (all 0x00 /
///     all 0xFF) probing minimum-entropy plaintext handling.
///   - pattern-ascii: a repeating 'A'..'Z' ramp probing low-entropy
///     structured text.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum PayloadMode {
    Fixed,
    Rotating,
    PatternZero,
    PatternFf,
    PatternAscii,
}

const PAYLOAD_NAMES: [(&str, PayloadMode); 5] = [
    ("fixed", PayloadMode::Fixed),
    ("rotating", PayloadMode::Rotating),
    ("pattern-zero", PayloadMode::PatternZero),
    ("pattern-ff", PayloadMode::PatternFf),
    ("pattern-ascii", PayloadMode::PatternAscii),
];

impl PayloadMode {
    pub fn name(self) -> &'static str {
        PAYLOAD_NAMES
            .iter()
            .find(|(_, m)| *m == self)
            .map(|(n, _)| *n)
            .unwrap_or("fixed")
    }

    pub fn parse(s: &str) -> Option<Self> {
        PAYLOAD_NAMES.iter().find(|(n, _)| *n == s).map(|(_, m)| *m)
    }
}

/// Seeded plaintext. The seed makes plaintext content reproducible so
/// a failing iteration can be replayed with the same bytes; it governs
/// nothing else — pipeline keys, nonces and masters stay CSPRNG-drawn,
/// so a seeded run is a reproduction aid and never a security test.
/// Each worker's stream is domain-separated by its id so seeded
/// workers still hold pairwise-distinct buffers under the fixed and
/// rotating modes. The generator is splitmix64: a few lines in any
/// language, which is why it is the one every binding uses.
pub fn seed_worker(seed: u64, worker_id: usize) -> u64 {
    seed.wrapping_add(worker_id as u64).wrapping_add(1)
}

fn splitmix64(state: &mut u64) -> u64 {
    *state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
    let mut z = *state;
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

/// Fills `buf` from the operating-system CSPRNG. Rust-specific:
/// `getrandom` returns at most ~33 MiB per call and may return short on
/// a signal, so the fill loops until every byte is in place. `false`
/// on failure.
pub fn fill_random(buf: &mut [u8]) -> bool {
    let mut off = 0usize;
    while off < buf.len() {
        // SAFETY: the pointer / length pair describes the unfilled tail
        // of a live, writable slice.
        let r = unsafe { libc::getrandom(buf[off..].as_mut_ptr().cast(), buf.len() - off, 0) };
        if r <= 0 {
            return false;
        }
        off += r as usize;
    }
    true
}

/// Writes one plaintext buffer according to the payload mode. The
/// fixed and rotating modes draw from the seeded generator when the
/// run is seeded and from the OS CSPRNG otherwise; the pattern modes
/// are deterministic regardless of the seed. `false` when the CSPRNG
/// fails.
pub fn fill_payload(mode: PayloadMode, seeded: bool, rng: &mut u64, buf: &mut [u8]) -> bool {
    match mode {
        PayloadMode::Fixed | PayloadMode::Rotating => {
            if !seeded {
                return fill_random(buf);
            }
            for chunk in buf.chunks_mut(8) {
                let v = splitmix64(rng).to_le_bytes();
                chunk.copy_from_slice(&v[..chunk.len()]);
            }
            true
        }
        PayloadMode::PatternZero => {
            buf.fill(0x00);
            true
        }
        PayloadMode::PatternFf => {
            buf.fill(0xFF);
            true
        }
        PayloadMode::PatternAscii => {
            for (i, b) in buf.iter_mut().enumerate() {
                *b = b'A' + (i % 26) as u8;
            }
            true
        }
    }
}
