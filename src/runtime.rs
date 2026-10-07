//! Process-wide Go runtime knobs, runtime diagnostics, and the library
//! version string.

use std::ffi::{CString, c_char, c_int};
use std::path::Path;

use crate::error::{ItbError, ItbResult, check};
use crate::ffi;
use crate::status::ItbStatus;

/// Sets the Go runtime's soft heap limit in bytes and returns the
/// previous limit. A negative value queries without changing.
pub fn set_memory_limit(bytes: i64) -> ItbResult<i64> {
    let s = ffi::syms()?;
    // SAFETY: plain value-in / value-out call.
    Ok(unsafe { (s.ITB_SetMemoryLimit)(bytes) })
}

/// Sets the Go GC trigger percentage and returns the previous value.
/// A negative value queries without changing.
pub fn set_gc_percent(pct: i32) -> ItbResult<i32> {
    let s = ffi::syms()?;
    // SAFETY: plain value-in / value-out call.
    Ok(unsafe { (s.ITB_SetGCPercent)(pct) })
}

/// Sets the Go runtime's GOMAXPROCS and returns the previous value.
/// Zero or a negative value queries without changing.
pub fn set_gomaxprocs(n: i32) -> ItbResult<i32> {
    let s = ffi::syms()?;
    // SAFETY: plain value-in / value-out call.
    Ok(unsafe { (s.ITB_SetGOMAXPROCS)(n) })
}

/// Writes the Go runtime's heap profile (pprof format) to `path`
/// after one forced garbage collection. An empty path falls back to
/// the `ITB_MEMPROFILE` environment variable inside libitb3; a path
/// that is still empty, or a file-system failure, fails with
/// [`ItbStatus::BadInput`] and the diagnostic in the error message.
pub fn write_heap_profile(path: impl AsRef<Path>) -> ItbResult<()> {
    let s = ffi::syms()?;
    let text = path
        .as_ref()
        .to_str()
        .ok_or(ItbError::Ffi("path is not valid UTF-8"))?;
    let path_c = CString::new(text).map_err(|_| ItbError::Ffi("path contains NUL"))?;
    // SAFETY: path_c is a live NUL-terminated string for the call.
    check(unsafe { (s.ITB_WriteHeapProfile)(path_c.as_ptr()) })
}

/// Number of `i64` slots [`pool_stats`] returns.
pub fn pool_stats_len() -> ItbResult<usize> {
    let s = ffi::syms()?;
    // SAFETY: value-out call.
    let n = unsafe { (s.ITB_PoolStatsLen)() };
    Ok(if n > 0 { n as usize } else { 0 })
}

/// One snapshot of the library's pool hit / miss counters. Every
/// counter is a monotonically increasing total since library load;
/// difference two snapshots. Slot layout, with `T` the tier count in
/// slot 0: tier `i` holds starter width, checkouts, constructor
/// misses, regrow replacements and bytes allocated at slots
/// `1 + 5*i .. 1 + 5*i + 4`; the scratch byte pool's get / new /
/// regrow / regrow-bytes follow at `1 + 5*T`, and the parallax chunk
/// pool's at `1 + 5*T + 4`.
pub fn pool_stats() -> ItbResult<Vec<i64>> {
    let s = ffi::syms()?;
    let mut v = vec![0i64; pool_stats_len()?];
    let mut written = 0usize;
    // SAFETY: v is writable for v.len() slots; written is a valid
    // out-param.
    check(unsafe { (s.ITB_PoolStats)(v.as_mut_ptr(), v.len(), &mut written) })?;
    v.truncate(written);
    Ok(v)
}

/// Returns the libitb3 library version string.
pub fn version() -> ItbResult<String> {
    let s = ffi::syms()?;
    // SAFETY (both calls): standard probe-then-read over the
    // size-out-param string contract; buffers are live for each call.
    read_cstr(|out, cap, len| unsafe { (s.ITB_Version)(out, cap, len) })
}

/// Returns the fill cipher the auto DRBG tier selected on this host
/// (`"aes-256-ctr"` or `"chacha20"`): the tier a Pipeline uses when its
/// drbg option is empty, resolved per host and recorded in no blob.
pub fn drbg_auto_tier() -> ItbResult<String> {
    let s = ffi::syms()?;
    // SAFETY (both calls): standard probe-then-read over the
    // size-out-param string contract; buffers are live for each call.
    read_cstr(|out, cap, len| unsafe { (s.ITB_DRBGAutoTier)(out, cap, len) })
}

/// Two-phase read over the `(out, cap, *out_len)` C-string contract:
/// probe with NULL / 0 for the required capacity, then read and
/// NUL-strip.
fn read_cstr(mut call: impl FnMut(*mut c_char, usize, *mut usize) -> c_int) -> ItbResult<String> {
    let mut need = 0usize;
    let rc = call(std::ptr::null_mut(), 0, &mut need);
    if rc != ItbStatus::Ok as i32 && rc != ItbStatus::BufferTooSmall as i32 {
        return Err(ItbError::from_rc(rc));
    }
    if need <= 1 {
        return Ok(String::new());
    }
    let mut buf = vec![0u8; need];
    check(call(buf.as_mut_ptr().cast(), buf.len(), &mut need))?;
    buf.truncate(need.saturating_sub(1));
    std::str::from_utf8(&buf)
        .map(str::to_owned)
        .map_err(ItbError::Utf8)
}
