//! Error type shared by every fallible call in the crate.

use std::ffi::c_char;
use std::fmt;
use std::sync::Arc;

use crate::ffi;
use crate::status::ItbStatus;

/// Result alias used across the crate.
pub type ItbResult<T> = Result<T, ItbError>;

/// The error type returned by every fallible call.
#[derive(Debug)]
pub enum ItbError {
    /// libitb3 returned a non-OK status. `message` carries the
    /// `ITB_LastError` diagnostic captured immediately after the
    /// failing call (process-global last-write-wins — the message may
    /// belong to a different call under concurrent FFI use; the
    /// status code is always attributable).
    Status { status: ItbStatus, message: String },
    /// The shared library (or one of its symbols) failed to load.
    LibraryLoad(Arc<libloading::Error>),
    /// Rust-side misuse of the FFI surface.
    Ffi(&'static str),
    /// A string returned by libitb3 failed UTF-8 decoding.
    Utf8(std::str::Utf8Error),
    /// An IO error raised by a stream pump's source or sink.
    Io(std::io::Error),
}

impl ItbError {
    /// Returns the libitb3 status code when the error carries one.
    pub fn status(&self) -> Option<ItbStatus> {
        match self {
            Self::Status { status, .. } => Some(*status),
            _ => None,
        }
    }

    /// Builds a [`ItbError::Status`] from a raw return code, pulling
    /// the `ITB_LastError` diagnostic at construction time.
    pub(crate) fn from_rc(rc: i32) -> Self {
        let status = ItbStatus::try_from(rc).unwrap_or(ItbStatus::Internal);
        Self::Status {
            status,
            message: read_last_error(),
        }
    }
}

impl fmt::Display for ItbError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Status { status, message } if message.is_empty() => {
                write!(f, "itb: status={} ({status})", *status as i32)
            }
            Self::Status { status, message } => {
                write!(f, "itb: status={} ({status}): {message}", *status as i32)
            }
            Self::LibraryLoad(e) => write!(f, "itb: failed to load libitb3: {e}"),
            Self::Ffi(msg) => write!(f, "itb: {msg}"),
            Self::Utf8(e) => write!(f, "itb: utf8 decode: {e}"),
            Self::Io(e) => write!(f, "itb: io: {e}"),
        }
    }
}

impl std::error::Error for ItbError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::LibraryLoad(e) => Some(e.as_ref()),
            Self::Utf8(e) => Some(e),
            Self::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<std::io::Error> for ItbError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

impl From<ItbError> for std::io::Error {
    fn from(e: ItbError) -> Self {
        match e {
            ItbError::Io(io) => io,
            other => std::io::Error::other(other),
        }
    }
}

/// Maps a raw FFI return code onto `Ok(())` / [`ItbError::Status`].
pub(crate) fn check(rc: i32) -> ItbResult<()> {
    if rc == ItbStatus::Ok as i32 {
        Ok(())
    } else {
        Err(ItbError::from_rc(rc))
    }
}

/// Reads the `ITB_LastError` diagnostic (NUL-stripped, lossy UTF-8).
/// Returns the empty string when no diagnostic is recorded or the
/// library is unavailable.
pub(crate) fn read_last_error() -> String {
    let Ok(s) = ffi::syms() else {
        return String::new();
    };
    let mut need = 0usize;
    // SAFETY: the NULL/0 probe form is part of the ITB_LastError
    // contract — it reports the required capacity without writing.
    let rc = unsafe { (s.ITB_LastError)(std::ptr::null_mut(), 0, &mut need) };
    if (rc != ItbStatus::Ok as i32 && rc != ItbStatus::BufferTooSmall as i32) || need <= 1 {
        return String::new();
    }
    let mut buf = vec![0u8; need];
    // SAFETY: buf is writable for buf.len() bytes; need receives the
    // byte count written including the trailing NUL.
    let rc = unsafe { (s.ITB_LastError)(buf.as_mut_ptr() as *mut c_char, buf.len(), &mut need) };
    if rc != ItbStatus::Ok as i32 {
        return String::new();
    }
    buf.truncate(need.saturating_sub(1));
    String::from_utf8_lossy(&buf).into_owned()
}
