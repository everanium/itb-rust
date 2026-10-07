//! The worker: its thread body (one warmup iteration, the warmup
//! barrier, the main loop), one iteration, the session pump loop the
//! stream shape drives, and the round-trip comparison that decides
//! between a worker error and a data mismatch.

use std::sync::atomic::Ordering;
use std::time::Instant;

use itb3::{ItbError, Pipeline};

use crate::ops::maintenance;
use crate::payload::{PayloadMode, fill_payload};
use crate::{PUMP_SLICE, RunState, WorkerState};

/// Cipher surfaces the --shape flag selects.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Shape {
    /// Session pump: begin / write / read / end.
    Stream,
    /// Single Message: one whole-buffer call.
    Message,
    /// Stream surface, one whole-buffer call.
    StreamOneShot,
    /// All three, rotating by iteration number.
    Both,
}

const SHAPE_NAMES: [(&str, Shape); 4] = [
    ("stream", Shape::Stream),
    ("message", Shape::Message),
    ("stream_one_shot", Shape::StreamOneShot),
    ("both", Shape::Both),
];

impl Shape {
    pub fn name(self) -> &'static str {
        SHAPE_NAMES
            .iter()
            .find(|(_, s)| *s == self)
            .map(|(n, _)| *n)
            .unwrap_or("stream")
    }

    pub fn parse(s: &str) -> Option<Self> {
        SHAPE_NAMES.iter().find(|(n, _)| *n == s).map(|(_, m)| *m)
    }
}

/// Renders a binding error the way every implementation reports a
/// failed library call: `status <code>: <last error>`; any other error
/// kind carries its own text.
pub fn detail(e: &ItbError) -> String {
    match e {
        ItbError::Status { status, message } => {
            format!("status {}: {}", *status as i32, message)
        }
        other => other.to_string(),
    }
}

/// Records the worker's error text (first error wins) and requests a
/// stop of the whole run.
pub fn fail(r: &RunState, id: usize, text: String) {
    let mut slot = r.workers[id].error.lock().unwrap();
    if slot.is_none() {
        *slot = Some(text);
    }
    r.stop.store(true, Ordering::SeqCst);
}

/// Pump loop. The Go harness hands ITB an io.Reader / io.Writer pair
/// and ITB drives the chunk loop internally; the C ABI has no reader /
/// writer entry, so the caller drives it: open a session, feed slices
/// of at most 1 MiB, drain whatever the session has produced after
/// every write (a read before end never blocks), end, then drain until
/// the session reports finished (after end, a read on an empty spool
/// blocks until the terminal bytes arrive). The whole produced output
/// lands in the worker's reusable accumulator. The loop is written
/// here rather than delegated to the binding's pump convenience so it
/// stands in the utility, at the same place, in every language. On
/// failure the result names the failing call and carries its error.
fn pump(
    pipe: &Pipeline,
    encrypt: bool,
    src: &[u8],
    out: &mut Vec<u8>,
) -> Result<(), (&'static str, ItbError)> {
    out.clear();
    let mut scratch = vec![0u8; PUMP_SLICE];
    // Rust-specific. The two session types are distinct structs with
    // identical methods, so the loop body is a closure over one of
    // them rather than a single function taking a session handle.
    macro_rules! drive {
        ($sess:expr) => {{
            let mut sess = $sess;
            for slice in src.chunks(PUMP_SLICE) {
                sess.write(slice).map_err(|e| ("StreamWrite", e))?;
                loop {
                    let (n, _) = sess.read(&mut scratch).map_err(|e| ("StreamRead", e))?;
                    if n == 0 {
                        break;
                    }
                    out.extend_from_slice(&scratch[..n]);
                }
            }
            sess.end().map_err(|e| ("StreamEnd", e))?;
            loop {
                let (n, fin) = sess.read(&mut scratch).map_err(|e| ("StreamRead", e))?;
                out.extend_from_slice(&scratch[..n]);
                if fin {
                    break;
                }
            }
            Ok(())
        }};
    }
    if encrypt {
        drive!(pipe.encrypt_stream().map_err(|e| ("StreamBegin", e))?)
    } else {
        drive!(pipe.decrypt_stream().map_err(|e| ("StreamBegin", e))?)
    }
}

/// First offset at which a and b differ; the shorter length when one
/// is a prefix of the other.
fn first_difference(a: &[u8], b: &[u8]) -> usize {
    a.iter()
        .zip(b)
        .position(|(x, y)| x != y)
        .unwrap_or(a.len().min(b.len()))
}

/// Up to 16 bytes of buf from off as lowercase hex, or "-" when buf
/// has no bytes there.
fn hex_window(buf: &[u8], off: usize) -> String {
    if off >= buf.len() {
        return "-".to_string();
    }
    buf[off..buf.len().min(off + 16)]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Records a worker error for a failed cipher call.
fn cipher_fail(
    r: &RunState,
    id: usize,
    iter: i64,
    shape: Shape,
    direction: &str,
    what: Option<&str>,
    e: &ItbError,
) {
    let text = match what {
        Some(w) => format!(
            "g{} iter {} shape={}: {}: {}: {}",
            id,
            iter,
            shape.name(),
            direction,
            w,
            detail(e)
        ),
        None => format!(
            "g{} iter {} shape={}: {}: {}",
            id,
            iter,
            shape.name(),
            direction,
            detail(e)
        ),
    };
    fail(r, id, text);
}

/// One iteration. In order: refill the plaintext under rotating mode;
/// take the read lock; pick the surface; encrypt (timed); decrypt
/// (timed); compare the round-trip with the plaintext; bump the
/// counters; release the lock. The whole round-trip runs under the
/// read lock so handle-mutating maintenance (rekey, blob reopen) never
/// lands between an encrypt and its matching decrypt — maintenance
/// runs after this returns, from the worker loop. `false` after
/// recording a worker error.
fn iterate(r: &RunState, w: &mut WorkerState, iter: i64) -> bool {
    let c = &r.workers[w.id];
    if w.payload_mode == PayloadMode::Rotating
        && !fill_payload(
            PayloadMode::Rotating,
            w.seeded,
            &mut w.rng,
            &mut w.plaintext,
        )
    {
        fail(
            r,
            w.id,
            format!("g{} iter {}: payload refill: csprng", w.id, iter),
        );
        return false;
    }

    let pipes = r.pipes.read().unwrap();

    // Shape dispatch. message is one whole-buffer call on the Single
    // Message Pipeline; stream_one_shot is one whole-buffer call on
    // the streaming Pipeline (the C ABI's ITB_Triple_EncryptStream,
    // which routes to the same one-shot stream entry the Go
    // harness calls by name); stream opens a session on the same
    // streaming Pipeline and drives the chunk loop from here. Under
    // both the three rotate by iteration number so the session path
    // and the whole-buffer path alternate on one handle inside every
    // worker — the cross-path state-reuse hazard this harness exists
    // to catch.
    let shape = match r.cfg.shape {
        Shape::Both => match iter % 3 {
            0 => Shape::Stream,
            1 => Shape::Message,
            _ => Shape::StreamOneShot,
        },
        s => s,
    };

    // Rust-specific. The message and one-shot entries return an owned
    // Vec that drops at the end of the iteration; the pump
    // accumulators are the worker's own and are reused. `owned` holds
    // the round-trip output for the former, so one comparison below
    // serves both postures.
    let owned: Vec<u8>;
    let got: &[u8] = match shape {
        Shape::Stream => {
            let pipe = pipes.stream.as_ref().unwrap();
            let t0 = Instant::now();
            if let Err((what, e)) = pump(pipe, true, &w.plaintext, &mut w.wire) {
                cipher_fail(r, w.id, iter, shape, "encrypt", Some(what), &e);
                return false;
            }
            c.nanos_enc
                .fetch_add(t0.elapsed().as_nanos() as i64, Ordering::Relaxed);
            let t0 = Instant::now();
            if let Err((what, e)) = pump(pipe, false, &w.wire, &mut w.plain) {
                cipher_fail(r, w.id, iter, shape, "decrypt", Some(what), &e);
                return false;
            }
            c.nanos_dec
                .fetch_add(t0.elapsed().as_nanos() as i64, Ordering::Relaxed);
            &w.plain
        }
        Shape::StreamOneShot => {
            let pipe = pipes.stream.as_ref().unwrap();
            let t0 = Instant::now();
            let wire = match pipe.encrypt_stream_one_shot(&w.plaintext) {
                Ok(v) => v,
                Err(e) => {
                    cipher_fail(r, w.id, iter, shape, "encrypt", None, &e);
                    return false;
                }
            };
            c.nanos_enc
                .fetch_add(t0.elapsed().as_nanos() as i64, Ordering::Relaxed);
            let t0 = Instant::now();
            owned = match pipe.decrypt_stream_one_shot(&wire) {
                Ok(v) => v,
                Err(e) => {
                    cipher_fail(r, w.id, iter, shape, "decrypt", None, &e);
                    return false;
                }
            };
            c.nanos_dec
                .fetch_add(t0.elapsed().as_nanos() as i64, Ordering::Relaxed);
            &owned
        }
        Shape::Message => {
            let pipe = pipes.msg.as_ref().unwrap();
            let t0 = Instant::now();
            let wire = match pipe.encrypt_message(&w.plaintext) {
                Ok(v) => v,
                Err(e) => {
                    cipher_fail(r, w.id, iter, shape, "encrypt", None, &e);
                    return false;
                }
            };
            c.nanos_enc
                .fetch_add(t0.elapsed().as_nanos() as i64, Ordering::Relaxed);
            let t0 = Instant::now();
            owned = match pipe.decrypt_message(&wire) {
                Ok(v) => v,
                Err(e) => {
                    cipher_fail(r, w.id, iter, shape, "decrypt", None, &e);
                    return false;
                }
            };
            c.nanos_dec
                .fetch_add(t0.elapsed().as_nanos() as i64, Ordering::Relaxed);
            &owned
        }
        Shape::Both => unreachable!("resolved above"),
    };

    // Failure model. A cipher call that returns a non-OK status is a
    // worker error: it is recorded, the run is asked to stop, the
    // other workers finish their in-flight iteration, and the error
    // is listed in the summary with the FAIL verdict. A round-trip
    // that returns OK with different bytes is a data mismatch: the
    // process terminates here, without summary or cleanup, because
    // the Pipeline state that produced the wrong bytes is the
    // evidence and nothing that runs afterwards may touch it.
    if got != w.plaintext.as_slice() {
        let off = first_difference(&w.plaintext, got);
        eprintln!(
            "loop: DATA MISMATCH g{} iter {} shape={}: want {} bytes, got {} bytes, first difference at offset {}: want {} got {}",
            w.id,
            iter,
            shape.name(),
            w.plaintext.len(),
            got.len(),
            off,
            hex_window(&w.plaintext, off),
            hex_window(got, off)
        );
        std::process::exit(3);
    }

    c.iters.fetch_add(1, Ordering::Relaxed);
    c.bytes_enc
        .fetch_add(w.plaintext.len() as i64, Ordering::Relaxed);
    c.bytes_dec.fetch_add(got.len() as i64, Ordering::Relaxed);
    true
}

/// Marks this worker returned; the last one to return stamps the
/// finish instant and wakes main.
fn done(r: &RunState) {
    let mut d = r.done.lock().unwrap();
    d.active -= 1;
    if d.active == 0 {
        d.finish = Some(Instant::now());
        r.done_cv.notify_one();
    }
}

/// The worker thread body: one warmup iteration, the warmup barrier,
/// then the main loop until a stop is requested or the fixed
/// per-worker iteration budget (warmup included) is spent. A failing
/// warmup still passes both barriers so the launcher never waits on a
/// worker that has already given up.
pub fn run(r: &RunState, mut w: WorkerState) {
    // Warmup iteration — counted in the totals; its completion feeds
    // the post-warmup baselines.
    let ok = iterate(r, &mut w, 0);
    r.warmup_done.wait();
    r.release.wait();
    if !ok {
        done(r);
        return;
    }

    let mut iter = 1i64;
    loop {
        if r.cfg.iterations > 0 && iter >= r.cfg.iterations {
            break;
        }
        if r.stop.load(Ordering::SeqCst) {
            break;
        }
        if !iterate(r, &mut w, iter) {
            break;
        }
        if !maintenance(r, w.id, iter) {
            break;
        }
        iter += 1;
    }
    done(r);
}
