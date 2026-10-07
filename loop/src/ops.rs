//! The maintenance operations that mutate a live Pipeline handle
//! between iterations: master rotation (--rekey-every) and blob
//! reopen (--blob-cycle-every).

use std::sync::atomic::Ordering;

use itb3::Pipeline;

use crate::payload::fill_random;
use crate::worker::{detail, fail};
use crate::{RunState, log_line};

/// Byte length of each fresh master drawn for a rotation. Matches the
/// size Init auto-generates for both the parallax and the wrapper
/// master.
const REKEY_MASTER_SIZE: usize = 32;

/// Master rotation. Rotates the parallax + wrapper masters on every
/// active Pipeline under the write lock and retains the refreshed
/// blob for subsequent blob reopens. Masters are drawn fresh from the
/// OS CSPRNG on every rotation regardless of --seed (master rotation
/// is pipeline keying, not plaintext content); a disabled layer passes
/// no bytes, which Rekey ignores. The eight inner seeds and the MAC
/// key are untouched by design — Rekey targets only the two
/// outer-layer master secrets.
fn rekey_pipes(r: &RunState, id: usize, iter: i64) -> bool {
    let mut perm = Vec::new();
    let mut wrap = Vec::new();
    if r.cfg.parallax {
        perm = vec![0u8; REKEY_MASTER_SIZE];
        if !fill_random(&mut perm) {
            fail(r, id, format!("g{id} iter {iter}: csprng: parallax master"));
            return false;
        }
    }
    if r.cfg.wrapper {
        wrap = vec![0u8; REKEY_MASTER_SIZE];
        if !fill_random(&mut wrap) {
            fail(r, id, format!("g{id} iter {iter}: csprng: wrapper master"));
            return false;
        }
    }

    let mut pipes = r.pipes.write().unwrap();
    if let Some(pipe) = pipes.stream.as_mut() {
        match pipe.rekey(&perm, &wrap) {
            Ok(blob) => pipes.stream_blob = blob,
            Err(e) => {
                fail(
                    r,
                    id,
                    format!(
                        "g{id} iter {iter}: Rekey({}): {}",
                        r.stream_profile,
                        detail(&e)
                    ),
                );
                return false;
            }
        }
    }
    if let Some(pipe) = pipes.msg.as_mut() {
        match pipe.rekey(&perm, &wrap) {
            Ok(blob) => pipes.msg_blob = blob,
            Err(e) => {
                fail(
                    r,
                    id,
                    format!(
                        "g{id} iter {iter}: Rekey({}): {}",
                        r.msg_profile,
                        detail(&e)
                    ),
                );
                return false;
            }
        }
    }
    let n = r.rekeys.fetch_add(1, Ordering::SeqCst) + 1;
    log_line(&format!(
        "rekey: g{id} iter {iter} rotated parallax + wrapper masters (rekey #{n})"
    ));
    true
}

/// Blob reopen. Reopens every active Pipeline from its retained blob
/// under the write lock: a fresh handle is loaded from the blob, the
/// running handle is freed, and the fresh one is swapped in, so every
/// later iteration round-trips through seeds and masters that survived
/// a blob crossing. The input is the blob Init or the latest Rekey
/// handed out, not a fresh Save: that is what a receiver holds, and
/// reopening from it proves the handed-out bytes rather than the live
/// state. The blob carries the Pipeline's full shape, so no override
/// reaches the reopen. On a Load failure the running handle stays and
/// the failure aborts the run.
fn blob_cycle_pipes(r: &RunState, id: usize, iter: i64) -> bool {
    let mut pipes = r.pipes.write().unwrap();
    if pipes.stream.is_some() {
        match Pipeline::load(&pipes.stream_blob, None) {
            // Assigning drops the running handle, which frees it.
            Ok(fresh) => pipes.stream = Some(fresh),
            Err(e) => {
                fail(
                    r,
                    id,
                    format!(
                        "g{id} iter {iter}: Load({}): {}",
                        r.stream_profile,
                        detail(&e)
                    ),
                );
                return false;
            }
        }
    }
    if pipes.msg.is_some() {
        match Pipeline::load(&pipes.msg_blob, None) {
            Ok(fresh) => pipes.msg = Some(fresh),
            Err(e) => {
                fail(
                    r,
                    id,
                    format!("g{id} iter {iter}: Load({}): {}", r.msg_profile, detail(&e)),
                );
                return false;
            }
        }
    }
    let n = r.blob_cycles.fetch_add(1, Ordering::SeqCst) + 1;
    log_line(&format!(
        "blob-cycle: g{id} iter {iter} reopened from session blob (cycle #{n})"
    ));
    true
}

/// Handle mutation. Runs the periodic Pipeline-mutating operations
/// after a completed iteration: master rotation (--rekey-every) and
/// blob reopen (--blob-cycle-every). Both intervals count per-worker
/// iterations; the warmup iteration (iter 0) never triggers because
/// the worker loop calls this for iter >= 1 only. Rekey rewrites the
/// outer-layer keying of a live handle and a blob reopen replaces the
/// handle outright; each takes the write lock, so in-flight cipher
/// calls on other workers drain before anything changes and no
/// encrypt is separated from its decrypt by either. `false` after
/// recording the worker error.
pub fn maintenance(r: &RunState, id: usize, iter: i64) -> bool {
    let cfg = &r.cfg;
    if cfg.rekey_every > 0 && iter % cfg.rekey_every == 0 && !rekey_pipes(r, id, iter) {
        return false;
    }
    if cfg.blob_cycle_every > 0
        && iter % cfg.blob_cycle_every == 0
        && !blob_cycle_pipes(r, id, iter)
    {
        return false;
    }
    true
}
