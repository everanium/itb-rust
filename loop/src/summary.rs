//! The final summary in both renderings, and the two measurements it
//! folds in that are not per-worker counters: the process resident
//! set and the shared library's pool counters.

use std::sync::atomic::Ordering;

use crate::size::{
    human_bytes, human_bytes_signed, human_duration, human_rate, mb_per_sec, round_to,
};
use crate::{CONCURRENCY, RunState, log_line, on_off, policy_label};

/// Parses one "Vm...:   1234 kB" line of /proc/self/status into
/// bytes; zero on any parse failure.
fn status_kb(line: &str) -> u64 {
    line.split(':')
        .nth(1)
        .and_then(|rest| rest.split_whitespace().next())
        .and_then(|kb| kb.parse::<u64>().ok())
        .map(|kb| kb * 1024)
        .unwrap_or(0)
}

/// The process's current resident set and its high-water mark in
/// bytes, from /proc/self/status (VmRSS and VmHWM, reported in kB).
/// Both are zero on a platform without that file; the figures are
/// informational and never enter the verdict.
pub fn read_rss() -> (u64, u64) {
    let Ok(text) = std::fs::read_to_string("/proc/self/status") else {
        return (0, 0);
    };
    let mut current = 0;
    let mut peak = 0;
    for line in text.lines() {
        if line.starts_with("VmRSS:") {
            current = status_kb(line);
        } else if line.starts_with("VmHWM:") {
            peak = status_kb(line);
        }
    }
    (current, peak)
}

/// Pool counters. The shared library keeps process-wide monotonic
/// totals at every pool checkout of its cipher core: per hash-array
/// tier the starter width, checkouts, constructor misses, regrow
/// replacements and bytes allocated; for the scratch byte pool and
/// the parallax chunk pool the checkouts, constructor misses, regrows
/// and regrow bytes. Two snapshots bracketing the main loop are
/// differenced into per-run hit / miss figures that tell whether a
/// pool keeps its items warm between calls or evicts them across GC
/// cycles. The slot layout is read from the library: slot 0 carries
/// the tier count T, tier i occupies the five slots at 1 + 5*i, and
/// the two byte pools occupy the eight slots at 1 + 5*T; the vector
/// is sized by the binding from the library's own length query, never
/// from a constant. Empty when the library is unavailable.
pub fn pool_snapshot() -> Vec<i64> {
    itb3::pool_stats().unwrap_or_default()
}

/// One starter tier of the hash-array pool, differenced.
struct Tier {
    index: i64,
    starter: i64,
    get: i64,
    fresh: i64,
    regrow: i64,
    new_bytes: i64,
}

/// One single-size byte pool, differenced.
#[derive(Default)]
struct BytePool {
    get: i64,
    fresh: i64,
    regrow: i64,
    regrow_bytes: i64,
}

#[derive(Default)]
struct PoolDelta {
    tiers: Vec<Tier>,
    buf: BytePool,
    chunk: BytePool,
}

fn pool_diff(steady: &[i64], warmup: &[i64]) -> PoolDelta {
    let mut d = PoolDelta::default();
    if steady.len() < 9 || warmup.len() != steady.len() {
        return d;
    }
    let tiers = steady[0];
    if tiers < 0 || (1 + 5 * tiers + 8) as usize > steady.len() {
        return d;
    }
    for i in 0..tiers {
        let base = (1 + 5 * i) as usize;
        if steady[base] == 0 {
            continue;
        }
        d.tiers.push(Tier {
            index: i,
            starter: steady[base],
            get: steady[base + 1] - warmup[base + 1],
            fresh: steady[base + 2] - warmup[base + 2],
            regrow: steady[base + 3] - warmup[base + 3],
            new_bytes: steady[base + 4] - warmup[base + 4],
        });
    }
    let tail = (1 + 5 * tiers) as usize;
    d.buf = BytePool {
        get: steady[tail] - warmup[tail],
        fresh: steady[tail + 1] - warmup[tail + 1],
        regrow: steady[tail + 2] - warmup[tail + 2],
        regrow_bytes: steady[tail + 3] - warmup[tail + 3],
    };
    d.chunk = BytePool {
        get: steady[tail + 4] - warmup[tail + 4],
        fresh: steady[tail + 5] - warmup[tail + 5],
        regrow: steady[tail + 6] - warmup[tail + 6],
        regrow_bytes: steady[tail + 7] - warmup[tail + 7],
    };
    d
}

/// Misses over checkouts as a percentage; zero when nothing was
/// checked out.
fn miss_percent(miss: i64, get: i64) -> f64 {
    if get <= 0 {
        return 0.0;
    }
    100.0 * miss as f64 / get as f64
}

/// Renders s as a JSON string literal with the escapes JSON requires.
fn json_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// The effective GC percentage as the runtime reports it: the query
/// form of the setter (a set-and-restore round trip inside the
/// library) so the field is the same whether the value came from the
/// flag, the environment, or the runtime default.
fn effective_gogc(flag: i32) -> i32 {
    if flag > 0 {
        return flag;
    }
    itb3::set_gc_percent(-1).unwrap_or(0)
}

/// Output contract. Both renderings are shared with the Go harness and
/// every other binding's loop utility field for field: the same lines
/// in the same order, the same keys in the same order, floats with a
/// fixed number of decimals so the JSON is byte-identical across
/// implementations. The Go harness alone adds its runtime-internal
/// lines after rss: and its runtime-internal keys after
/// parallax_chunk_pool; nothing here reproduces them because nothing
/// they read is reachable through the C ABI. Returns the exit code.
pub fn final_summary(r: &RunState, elapsed_ns: i64) -> i32 {
    let cfg = &r.cfg;
    let workers = cfg.workers as i64;
    let mut total_iters = 0i64;
    let mut total_enc = 0i64;
    let mut total_dec = 0i64;
    let mut nanos_enc = 0i64;
    let mut nanos_dec = 0i64;
    let mut per_worker = Vec::with_capacity(cfg.workers);
    let mut errors = Vec::new();
    for c in &r.workers {
        let n = c.iters.load(Ordering::SeqCst);
        per_worker.push(n);
        total_iters += n;
        total_enc += c.bytes_enc.load(Ordering::SeqCst);
        total_dec += c.bytes_dec.load(Ordering::SeqCst);
        nanos_enc += c.nanos_enc.load(Ordering::SeqCst);
        nanos_dec += c.nanos_dec.load(Ordering::SeqCst);
        if let Some(text) = c.error.lock().unwrap().as_ref() {
            errors.push(text.clone());
        }
    }

    // Throughput. Per-direction throughput divides the sum of every
    // worker's wall time in that direction by the worker count — the
    // equivalent single-stream wall time under N-way concurrency — so
    // each direction reports the aggregate rate it sustained rather
    // than collapsing to combined/2 (every iteration moves equal
    // encrypt and decrypt bytes, so a total-elapsed denominator would
    // give both directions the same figure). The combined rate keeps
    // total elapsed as the one-glance overall figure.
    let avg_enc = if nanos_enc > 0 {
        nanos_enc / workers
    } else {
        0
    };
    let avg_dec = if nanos_dec > 0 {
        nanos_dec / workers
    } else {
        0
    };

    let rss_delta = r.rss_final as i64 - r.rss_warmup as i64;
    let rss_growth = if r.rss_warmup > 0 {
        100.0 * rss_delta as f64 / r.rss_warmup as f64
    } else {
        0.0
    };

    let pd = pool_diff(&r.pool_steady, &r.pool_warmup);
    let pass = errors.is_empty();
    let rekeys = r.rekeys.load(Ordering::SeqCst);
    let cycles = r.blob_cycles.load(Ordering::SeqCst);
    let gomaxprocs = itb3::set_gomaxprocs(0).unwrap_or(0);
    let pipes = r.pipes.read().unwrap();
    let stream_profile = if pipes.stream.is_some() {
        r.stream_profile.as_str()
    } else {
        ""
    };
    let msg_profile = if pipes.msg.is_some() {
        r.msg_profile.as_str()
    } else {
        ""
    };
    drop(pipes);

    if cfg.json_output {
        let mut j = String::new();
        j.push_str(&format!(
            "{{\"duration_seconds\":{:.3}",
            elapsed_ns as f64 / 1e9
        ));
        j.push_str(&format!(",\"iterations\":{total_iters}"));
        j.push_str(",\"per_worker_iterations\":[");
        j.push_str(
            &per_worker
                .iter()
                .map(i64::to_string)
                .collect::<Vec<_>>()
                .join(","),
        );
        j.push(']');
        j.push_str(&format!(",\"bytes_encrypted\":{total_enc}"));
        j.push_str(&format!(",\"bytes_decrypted\":{total_dec}"));
        j.push_str(&format!(
            ",\"encrypt_mb_per_sec\":{:.1}",
            mb_per_sec(total_enc, avg_enc)
        ));
        j.push_str(&format!(
            ",\"decrypt_mb_per_sec\":{:.1}",
            mb_per_sec(total_dec, avg_dec)
        ));
        j.push_str(&format!(
            ",\"combined_mb_per_sec\":{:.1}",
            mb_per_sec(total_enc + total_dec, elapsed_ns)
        ));
        j.push_str(&format!(",\"rekeys\":{rekeys}"));
        j.push_str(&format!(",\"blob_cycles\":{cycles}"));
        j.push_str(",\"worker_errors\":[");
        j.push_str(
            &errors
                .iter()
                .map(|e| json_string(e))
                .collect::<Vec<_>>()
                .join(","),
        );
        j.push(']');
        j.push_str(&format!(
            ",\"verdict\":\"{}\"",
            if pass { "PASS" } else { "FAIL" }
        ));
        j.push_str(&format!(",\"shape\":\"{}\"", cfg.shape.name()));
        j.push_str(&format!(
            ",\"stream_profile\":{}",
            json_string(stream_profile)
        ));
        j.push_str(&format!(
            ",\"message_profile\":{}",
            json_string(msg_profile)
        ));
        j.push_str(&format!(",\"hash\":{}", json_string(&cfg.hash)));
        j.push_str(&format!(",\"mac\":{}", json_string(&cfg.mac)));
        j.push_str(&format!(",\"payload_bytes\":{}", cfg.payload));
        j.push_str(&format!(
            ",\"payload_mode\":\"{}\"",
            cfg.payload_mode.name()
        ));
        j.push_str(&format!(",\"seed\":{}", cfg.seed));
        j.push_str(&format!(",\"key_bits\":{}", cfg.key_bits));
        j.push_str(&format!(",\"nonce_bits\":{}", cfg.nonce_bits));
        j.push_str(&format!(",\"blob_mode\":{}", cfg.blob_mode));
        j.push_str(&format!(",\"drbg\":{}", json_string(&cfg.drbg)));
        j.push_str(&format!(
            ",\"drbg_auto_tier\":{}",
            json_string(&itb3::drbg_auto_tier().unwrap_or_default())
        ));
        j.push_str(&format!(",\"chunk_size_bytes\":{}", cfg.chunk_size));
        j.push_str(&format!(",\"barrier_fill\":{}", cfg.barrier_fill));
        j.push_str(&format!(",\"parallax\":\"{}\"", on_off(cfg.parallax)));
        j.push_str(&format!(",\"wrapper\":\"{}\"", on_off(cfg.wrapper)));
        j.push_str(&format!(
            ",\"goroutines_requested\":{}",
            cfg.workers_requested
        ));
        j.push_str(&format!(",\"goroutines\":{}", cfg.workers));
        j.push_str(&format!(",\"concurrency\":\"{CONCURRENCY}\""));
        j.push_str(&format!(",\"gogc\":\"{}\"", effective_gogc(cfg.gogc)));
        j.push_str(&format!(",\"memlimit_bytes\":{}", cfg.memlimit));
        j.push_str(&format!(",\"gomaxprocs\":{gomaxprocs}"));
        j.push_str(&format!(
            ",\"microbatch_tiers\":{}",
            json_string(&policy_label(std::env::var("ITB_MICROBATCH_TIERS").ok()))
        ));
        j.push_str(&format!(
            ",\"hashpool_starters\":{}",
            json_string(&policy_label(std::env::var("ITB_HASHPOOL_STARTERS").ok()))
        ));
        j.push_str(&format!(",\"rss_warmup_bytes\":{}", r.rss_warmup));
        j.push_str(&format!(",\"rss_peak_bytes\":{}", r.rss_peak));
        j.push_str(&format!(",\"rss_final_bytes\":{}", r.rss_final));
        j.push_str(&format!(",\"rss_growth_percent\":{rss_growth:.2}"));
        j.push_str(",\"hash_pool_tiers\":[");
        let tiers: Vec<String> = pd
            .tiers
            .iter()
            .map(|t| {
                format!(
                    "{{\"tier\":{},\"starter\":{},\"get\":{},\"new\":{},\"regrow\":{},\"new_bytes\":{},\"miss_percent\":{:.2}}}",
                    t.index, t.starter, t.get, t.fresh, t.regrow, t.new_bytes,
                    miss_percent(t.fresh + t.regrow, t.get)
                )
            })
            .collect();
        j.push_str(&tiers.join(","));
        j.push(']');
        j.push_str(&format!(
            ",\"buf_pool\":{{\"get\":{},\"new\":{},\"regrow\":{},\"regrow_bytes\":{},\"miss_percent\":{:.2}}}",
            pd.buf.get, pd.buf.fresh, pd.buf.regrow, pd.buf.regrow_bytes,
            miss_percent(pd.buf.regrow, pd.buf.get)
        ));
        j.push_str(&format!(
            ",\"parallax_chunk_pool\":{{\"get\":{},\"new\":{},\"regrow\":{},\"regrow_bytes\":{},\"miss_percent\":{:.2}}}",
            pd.chunk.get, pd.chunk.fresh, pd.chunk.regrow, pd.chunk.regrow_bytes,
            miss_percent(pd.chunk.regrow, pd.chunk.get)
        ));
        j.push('}');
        println!("{j}");
        return if pass { 0 } else { 1 };
    }

    log_line("=== FINAL ===");
    log_line(&format!(
        "  duration: {}",
        human_duration(round_to(elapsed_ns, 1_000_000))
    ));
    log_line(&format!(
        "  iterations: {} = {} total",
        per_worker
            .iter()
            .map(i64::to_string)
            .collect::<Vec<_>>()
            .join(" + "),
        total_iters
    ));
    log_line(&format!(
        "  throughput: encrypt {}, decrypt {}, combined {}",
        human_rate(total_enc, avg_enc),
        human_rate(total_dec, avg_dec),
        human_rate(total_enc + total_dec, elapsed_ns)
    ));
    log_line(&format!(
        "  bytes: {} encrypted, {} decrypted",
        human_bytes(total_enc),
        human_bytes(total_dec)
    ));
    log_line(&format!(
        "  data integrity: {total_iters}/{total_iters} PASS"
    ));
    log_line(&format!(
        "  concurrency: {CONCURRENCY}, workers {} (requested {})",
        cfg.workers, cfg.workers_requested
    ));
    log_line(&format!(
        "  rss: warmup {}, peak {}, final {} (delta {}, {:.1}% growth)",
        human_bytes(r.rss_warmup as i64),
        human_bytes(r.rss_peak as i64),
        human_bytes(r.rss_final as i64),
        human_bytes_signed(rss_delta),
        rss_growth
    ));
    for t in &pd.tiers {
        log_line(&format!(
            "  hash pool tier {} (starter {}): get {}, miss {} (new {} + regrow {}), miss {:.2}%, {} allocated",
            t.index,
            t.starter,
            t.get,
            t.fresh + t.regrow,
            t.fresh,
            t.regrow,
            miss_percent(t.fresh + t.regrow, t.get),
            human_bytes(t.new_bytes)
        ));
    }
    log_line(&format!(
        "  buf pool: get {}, regrow {} (of which fresh {}), miss {:.2}%, {} regrown",
        pd.buf.get,
        pd.buf.regrow,
        pd.buf.fresh,
        miss_percent(pd.buf.regrow, pd.buf.get),
        human_bytes(pd.buf.regrow_bytes)
    ));
    log_line(&format!(
        "  parallax chunk pool: get {}, regrow {} (of which fresh {}), miss {:.2}%, {} regrown",
        pd.chunk.get,
        pd.chunk.regrow,
        pd.chunk.fresh,
        miss_percent(pd.chunk.regrow, pd.chunk.get),
        human_bytes(pd.chunk.regrow_bytes)
    ));
    if rekeys > 0 {
        log_line(&format!("  rekeys: {rekeys}"));
    }
    if cycles > 0 {
        log_line(&format!("  blob cycles: {cycles}"));
    }
    for e in &errors {
        log_line(&format!("  ERROR: {e}"));
    }
    if pass {
        log_line("  verdict: PASS");
        0
    } else {
        log_line(&format!("  verdict: FAIL (errors={})", errors.len()));
        1
    }
}
