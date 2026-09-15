//! Process-wide Go runtime knobs plus the library version string.

use std::ffi::{c_char, c_int};

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

/// Returns the libitb3 library version string.
pub fn version() -> ItbResult<String> {
    let s = ffi::syms()?;
    // SAFETY (both calls): standard probe-then-read over the
    // size-out-param string contract; buffers are live for each call.
    read_cstr(|out, cap, len| unsafe { (s.ITB_Version)(out, cap, len) })
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
