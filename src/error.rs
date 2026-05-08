//! Error type returned by every fallible libitb call.
//!
//! Wraps every fallible libitb call's status code with a single
//! error type carrying the structural status code (numeric) plus the
//! optional textual diagnostic from `ITB_LastError`. Callers usually
//! match on `code()` for control flow and use `Display` for logs.
//!
//! Threading caveat. The textual `message` is read from a process-wide
//! atomic inside libitb that follows the C `errno` discipline: the
//! most recent non-OK Status across the whole process wins, and a
//! sibling thread that calls into libitb between the failing call and
//! the diagnostic read overwrites the message. The structural `code`
//! on the failing call's return value is unaffected — only the
//! textual diagnostic is racy.

use std::ffi::c_char;
use std::fmt;

use crate::ffi;

/// The error type returned by every fallible libitb call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ITBError {
    code: i32,
    message: String,
}

impl ITBError {
    /// Constructs an `ITBError` from a raw status code. The textual
    /// diagnostic is read lazily via `ITB_LastError` at construction
    /// time.
    pub(crate) fn from_status(code: i32) -> Self {
        let message = read_last_error();
        Self { code, message }
    }

    /// Constructs an `ITBError` with an explicit message (used by
    /// callers like the Easy peek-config path that can supply a
    /// caller-side diagnostic such as the mismatched-field name).
    pub(crate) fn with_message(code: i32, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    /// Returns the structural status code (one of the `STATUS_*`
    /// constants in `crate::ffi`). The code is the only piece of
    /// `ITBError` that is reliably attributable to the failing call —
    /// the textual `message` is racy under concurrent FFI use.
    pub fn code(&self) -> i32 {
        self.code
    }

    /// Returns the textual diagnostic captured at construction time.
    /// Empty string if libitb did not record one.
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for ITBError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.message.is_empty() {
            write!(f, "itb: status={}", self.code)
        } else {
            write!(f, "itb: status={} ({})", self.code, self.message)
        }
    }
}

impl std::error::Error for ITBError {}

pub(crate) fn read_last_error() -> String {
    let lib = ffi::lib();
    let mut out_len: usize = 0;
    let rc = unsafe { (lib.ITB_LastError)(std::ptr::null_mut(), 0, &mut out_len) };
    if rc != ffi::STATUS_OK && rc != ffi::STATUS_BUFFER_TOO_SMALL {
        return String::new();
    }
    if out_len <= 1 {
        return String::new();
    }
    let mut buf = vec![0u8; out_len];
    let rc = unsafe {
        (lib.ITB_LastError)(buf.as_mut_ptr() as *mut c_char, out_len, &mut out_len)
    };
    if rc != ffi::STATUS_OK {
        return String::new();
    }
    let n = out_len.saturating_sub(1);
    buf.truncate(n);
    String::from_utf8(buf).unwrap_or_default()
}

/// Internal idiom for size-out-param string accessors: probe with
/// `cap=0` to discover the required size, then allocate and write.
///
/// `call` is a closure that takes `(out_ptr, cap, out_len_ptr)` and
/// returns the status code. Used by `version()`, `list_hashes()`,
/// `list_macs()`, `Seed::hash_name()`, `Encryptor::primitive()`, etc.
pub(crate) fn read_str<F>(mut call: F) -> Result<String, ITBError>
where
    F: FnMut(*mut c_char, usize, *mut usize) -> i32,
{
    let mut out_len: usize = 0;
    let rc = call(std::ptr::null_mut(), 0, &mut out_len);
    if rc != ffi::STATUS_OK && rc != ffi::STATUS_BUFFER_TOO_SMALL {
        return Err(ITBError::from_status(rc));
    }
    if out_len == 0 {
        return Ok(String::new());
    }
    let cap = out_len;
    let mut buf = vec![0u8; cap];
    let rc = call(buf.as_mut_ptr() as *mut c_char, cap, &mut out_len);
    if rc != ffi::STATUS_OK {
        return Err(ITBError::from_status(rc));
    }
    let n = out_len.saturating_sub(1);
    buf.truncate(n);
    String::from_utf8(buf).map_err(|e| {
        ITBError::with_message(ffi::STATUS_INTERNAL, format!("utf8 decode: {e}"))
    })
}

/// Helper for `Result<(), ITBError>` returns where the call only
/// produces a status code with no out-parameters.
pub(crate) fn check(rc: i32) -> Result<(), ITBError> {
    if rc == ffi::STATUS_OK {
        Ok(())
    } else {
        Err(ITBError::from_status(rc))
    }
}

/// Reads `ITB_LastError` for the most recent non-OK status returned
/// on this thread. Returns the empty string when no error has been
/// recorded.
///
/// The textual message follows C errno discipline: it is published
/// through a process-wide atomic, so a sibling thread that calls
/// into libitb between the failing call and this read can overwrite
/// the message. The structural status code on the failing call is
/// unaffected — only the textual message is racy. The
/// [`ITBError`] type already attaches this string at exception
/// construction time; the free-function form is exposed for callers
/// that want to read the diagnostic independently of the error path.
pub fn last_error() -> String {
    read_last_error()
}
