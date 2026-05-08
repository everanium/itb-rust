//! Shared scaffolding for the Rust Easy Mode benchmark binaries.
//!
//! The harness mirrors the Go ``testing.B`` benchmark style on the
//! itb_ext_test.go / itb3_ext_test.go side: each bench function runs a
//! short warm-up batch to reach steady state, then a measured batch
//! whose total wall-clock time is divided by the iteration count to
//! produce the canonical ``ns/op`` throughput line. The output line
//! also carries an MB/s figure derived from the configured payload
//! size, matching the Go reporter's ``-benchmem``-less default.
//!
//! Environment variables (mirrored from itb's bitbyte_test.go +
//! extended for Easy Mode):
//!
//! * `ITB_NONCE_BITS` — process-wide nonce width override; valid
//!   values 128 / 256 / 512. Maps to [`itb::set_nonce_bits`] before
//!   any encryptor is constructed. Default 128.
//! * `ITB_LOCKSEED` — when set to a non-empty / non-`0` value, every
//!   Easy Mode encryptor in this run calls
//!   [`itb::Encryptor::set_lock_seed`] with mode=1. The Go side's
//!   auto-couple invariant then engages BitSoup + LockSoup
//!   automatically; no separate flags required for Easy Mode.
//!   Default off.
//!
//! Worker count defaults to `itb::set_max_workers(0)` (auto-detect),
//! matching the Go bench default. Bench scripts may override before
//! calling [`run_all`].
//!
//! This module is shared via `#[path = "common.rs"] mod common;`
//! includes from `bench_single.rs` / `bench_triple.rs` rather than as
//! a `[[bench]]` target of its own.

#![allow(dead_code)]

use std::env;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

/// Default 16 MiB CSPRNG-filled payload, matching the Go bench /
/// Python bench surface.
pub const PAYLOAD_16MB: usize = 16 << 20;

/// Reads `ITB_NONCE_BITS` from the environment with the same
/// 128 / 256 / 512 validation as bitbyte_test.go's TestMain. Falls
/// back to `default` on missing / invalid input (with a stderr
/// diagnostic for the invalid case).
pub fn env_nonce_bits(default: i32) -> i32 {
    let v = match env::var("ITB_NONCE_BITS") {
        Ok(s) => s,
        Err(_) => return default,
    };
    if v.is_empty() {
        return default;
    }
    match v.as_str() {
        "128" => 128,
        "256" => 256,
        "512" => 512,
        _ => {
            eprintln!(
                "ITB_NONCE_BITS={v:?} invalid (expected 128/256/512); using {default}",
            );
            default
        }
    }
}

/// `true` when `ITB_LOCKSEED` is set to a non-empty / non-`0` value.
/// Triggers `Encryptor::set_lock_seed(1)` on every encryptor; Easy
/// Mode auto-couples BitSoup + LockSoup.
pub fn env_lock_seed() -> bool {
    match env::var("ITB_LOCKSEED") {
        Ok(s) => !(s.is_empty() || s == "0"),
        Err(_) => false,
    }
}

/// Optional substring filter for bench-function names, read from
/// `ITB_BENCH_FILTER`. Functions whose name does not contain the
/// filter substring are skipped; used to scope a run down to a
/// single primitive or operation during development.
pub fn env_filter() -> Option<String> {
    match env::var("ITB_BENCH_FILTER") {
        Ok(s) if !s.is_empty() => Some(s),
        _ => None,
    }
}

/// Minimum wall-clock seconds the measured iter loop should take,
/// read from `ITB_BENCH_MIN_SEC` (default 5.0). The runner keeps
/// doubling iteration count until the measured run reaches this
/// threshold, mirroring Go's `-benchtime=Ns` semantics. The 5-second
/// default is wide enough to absorb the cold-cache / warm-up
/// transient that distorts shorter measurement windows on the
/// 16 MiB encrypt / decrypt path.
pub fn env_min_seconds() -> f64 {
    let v = match env::var("ITB_BENCH_MIN_SEC") {
        Ok(s) => s,
        Err(_) => return 5.0,
    };
    if v.is_empty() {
        return 5.0;
    }
    match v.parse::<f64>() {
        Ok(f) if f > 0.0 => f,
        _ => {
            eprintln!(
                "ITB_BENCH_MIN_SEC={v:?} invalid (expected positive float); using 5.0",
            );
            5.0
        }
    }
}

/// Returns `n` non-deterministic test bytes via an `Instant`-mixed
/// LCG. Matches the crypto/rand-fill pattern used by
/// generateDataExt in itb_ext_test.go in spirit; the bench harness
/// does not require cryptographic strength here, only that the
/// payload is non-uniform and changes between runs so a primitive
/// cannot collapse on a constant input. The mixing pattern matches
/// the Phase-5 test files' inline LCG to avoid pulling in `rand` /
/// `getrandom` / any other dev-dependency.
pub fn random_bytes(n: usize) -> Vec<u8> {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let salt = COUNTER.fetch_add(1, Ordering::Relaxed);
    // Mix wall-clock nanos with a monotonic counter so successive
    // calls within the same nanosecond still diverge.
    let nanos = Instant::now().elapsed().as_nanos() as u64;
    let mut state = nanos
        .wrapping_mul(0x9E37_79B9_7F4A_7C15)
        .wrapping_add(salt)
        .wrapping_add(0xBF58_476D_1CE4_E5B9);
    if state == 0 {
        state = 0xDEAD_BEEF_CAFE_F00D;
    }
    let mut out = vec![0u8; n];
    let mut i = 0usize;
    while i < n {
        // xorshift64* — adequate for non-cryptographic test fill.
        state ^= state >> 12;
        state ^= state << 25;
        state ^= state >> 27;
        let v = state.wrapping_mul(0x2545_F491_4F6C_DD1D);
        let bytes = v.to_le_bytes();
        let take = std::cmp::min(8, n - i);
        out[i..i + take].copy_from_slice(&bytes[..take]);
        i += take;
    }
    out
}

/// Per-iter callable; accepts an iteration count and runs the
/// per-iter body that many times. The harness measures wall-clock
/// time outside the callable.
pub type BenchFn = Box<dyn FnMut(u64)>;

/// One bench case: name + per-iter callable + payload byte count
/// (used to compute the MB/s column).
pub struct BenchCase {
    pub name: String,
    pub run: BenchFn,
    pub payload_bytes: usize,
}

/// Run a benchmark case to convergence and emit a single
/// Go-bench-style report line.
///
/// Convergence policy: warm up with one iteration, then double the
/// iteration count until the measured wall-clock duration meets
/// `min_seconds`. The final `ns/op` figure is the measured duration
/// of that final batch divided by its iteration count.
fn measure(case: &mut BenchCase, min_seconds: f64) {
    // Warm-up — one iteration to hit cache / cold-start transients
    // before the measured loop.
    (case.run)(1);

    let min_ns = (min_seconds * 1e9) as u64;
    let mut iters: u64 = 1;
    let mut elapsed: u64;
    loop {
        let t0 = Instant::now();
        (case.run)(iters);
        elapsed = t0.elapsed().as_nanos() as u64;
        if elapsed >= min_ns {
            break;
        }
        // Double up; cap growth so a very fast op doesn't escalate
        // past 1 << 24 iters for one batch.
        if iters >= (1u64 << 24) {
            break;
        }
        iters *= 2;
    }

    let ns_per_op = elapsed as f64 / iters as f64;
    let mb_per_s = if ns_per_op > 0.0 {
        (case.payload_bytes as f64 / (ns_per_op / 1e9)) / (1u64 << 20) as f64
    } else {
        0.0
    };
    // Mirrors `BenchmarkX-8     N    ns/op    MB/s` Go format,
    // column-aligned for human reading.
    println!(
        "{:<60}\t{:>10}\t{:>14.1} ns/op\t{:>9.2} MB/s",
        case.name, iters, ns_per_op, mb_per_s,
    );
}

/// Run every case in `cases` and print one Go-bench-style line per
/// case to stdout. Honours `ITB_BENCH_FILTER` for substring scoping
/// and `ITB_BENCH_MIN_SEC` for per-case wall-clock budget.
pub fn run_all(cases: Vec<BenchCase>) {
    let flt = env_filter();
    let min_seconds = env_min_seconds();

    let total = cases.len();
    let names: Vec<String> = cases.iter().map(|c| c.name.clone()).collect();

    let mut selected: Vec<BenchCase> = match &flt {
        Some(s) => cases.into_iter().filter(|c| c.name.contains(s)).collect(),
        None => cases,
    };
    if selected.is_empty() {
        eprintln!(
            "no bench cases match filter {:?}; available: {:?}",
            flt, names,
        );
        return;
    }

    let payload_bytes = selected[0].payload_bytes;
    println!(
        "# benchmarks={} payload_bytes={} min_seconds={}",
        selected.len(),
        payload_bytes,
        min_seconds,
    );
    let _ = total; // total kept for symmetry with the Python harness's available-cases reporting
    for case in selected.iter_mut() {
        measure(case, min_seconds);
    }
}
