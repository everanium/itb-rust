//! RAII wrapper around the Triple Pipeline handle.

use std::ffi::CString;
use std::io::{Read, Write};
use std::path::Path;

use crate::error::{ItbError, ItbResult, check};
use crate::ffi::{self, FnTripleCipher, Syms};
use crate::opts::OptsBuilder;
use crate::profile::Profile;
use crate::status::ItbStatus;
use crate::stream::{DecryptStream, EncryptStream};

/// Floor capacity for blob / JSON output buffers (Init / Rekey / Save /
/// Inspect).
const BLOB_CAP: usize = 64 * 1024;

/// Pre-allocation formula for Message / one-shot stream outputs:
/// `max(131072, payload * 5/4 + 131072)`.
fn out_cap(payload: usize) -> usize {
    (payload + payload / 4 + 131_072).max(131_072)
}

/// Single retry-once dispatch site for every variable-size output
/// buffer: pre-allocate `cap`, and on `BufferTooSmall` retry once
/// with the exact size the FFI reported through the length out-param.
pub(crate) fn retry_once(
    cap: usize,
    mut call: impl FnMut(&mut [u8], &mut usize) -> i32,
) -> ItbResult<Vec<u8>> {
    let mut buf = vec![0u8; cap];
    let mut len = 0usize;
    let mut rc = call(&mut buf, &mut len);
    // Retry only when the reported length strictly exceeds the
    // current capacity. Guards against a stray BufferTooSmall report
    // with `len <= cap` (harmless in Rust — the second failure
    // propagates — but the guard keeps every binding in the fleet on
    // the same retry-once shape).
    if rc == ItbStatus::BufferTooSmall as i32 && len > cap {
        buf = vec![0u8; len];
        rc = call(&mut buf, &mut len);
    }
    check(rc)?;
    buf.truncate(len);
    Ok(buf)
}

/// A Triple Pipeline session.
///
/// [`Pipeline::save`] exports the session bundle the receiver feeds to
/// [`Pipeline::load`]; [`Pipeline::rekey`] refreshes it. Dropping the
/// Pipeline frees the handle (libitb3 zeroes key material internally).
///
/// Streaming-decrypt caveat: chunked Streaming AEAD verifies per
/// chunk, so plaintext of verified chunks is released before a later
/// chunk can fail authentication.
pub struct Pipeline {
    handle: usize,
}

impl Pipeline {
    /// Constructs a fresh Pipeline against the named profile. The
    /// session bundle is available through [`Pipeline::save`]. On a
    /// blob-buffer retry the Init re-runs and yields a fresh session
    /// (the undersized attempt is closed by libitb3 before returning).
    pub fn init(profile: &str, opts: &OptsBuilder) -> ItbResult<Self> {
        let s = ffi::syms()?;
        let profile_c = cstr(profile, "profile name contains NUL")?;
        let opts_c = opts.build();
        let mut handle = 0usize;
        retry_once(BLOB_CAP, |buf, len| {
            // SAFETY: all pointers reference live buffers for the
            // duration of the call; len / handle are valid out-params.
            unsafe {
                (s.ITB_Triple_Init)(
                    profile_c.as_ptr(),
                    opts_c.as_ptr(),
                    buf.as_mut_ptr().cast(),
                    buf.len(),
                    len,
                    &mut handle,
                )
            }
        })?;
        Ok(Self { handle })
    }

    /// Reconstructs a Pipeline from a blob produced by
    /// [`Pipeline::save`] or [`Pipeline::rekey`]. `masters` is `None`
    /// to use the blob-embedded masters, or `Some((perm, wrap))` to
    /// override them.
    pub fn load(blob: &[u8], masters: Option<(&[u8], &[u8])>) -> ItbResult<Self> {
        let s = ffi::syms()?;
        let (pm, wm, count) = split_masters(masters);
        let mut handle = 0usize;
        // SAFETY: all pointers reference live buffers for the duration
        // of the call; handle is a valid out-param. Empty slices cross
        // as (dangling, 0), which the Go side treats as absent.
        let rc = unsafe {
            (s.ITB_Triple_Load)(
                blob.as_ptr().cast(),
                blob.len(),
                pm.as_ptr().cast(),
                pm.len(),
                wm.as_ptr().cast(),
                wm.len(),
                count,
                &mut handle,
            )
        };
        check(rc)?;
        Ok(Self { handle })
    }

    /// [`Pipeline::load`] for a blob stored at `path`; the file is read
    /// inside libitb3.
    pub fn load_f(path: impl AsRef<Path>, masters: Option<(&[u8], &[u8])>) -> ItbResult<Self> {
        let s = ffi::syms()?;
        let path_c = path_cstr(path.as_ref())?;
        let (pm, wm, count) = split_masters(masters);
        let mut handle = 0usize;
        // SAFETY: as for `load`; path_c is a live NUL-terminated string.
        let rc = unsafe {
            (s.ITB_Triple_LoadF)(
                path_c.as_ptr(),
                pm.as_ptr().cast(),
                pm.len(),
                wm.as_ptr().cast(),
                wm.len(),
                count,
                &mut handle,
            )
        };
        check(rc)?;
        Ok(Self { handle })
    }

    /// The current session bundle bytes for the receiver side (the
    /// Init blob, or the bytes of the latest [`Pipeline::rekey`]).
    pub fn save(&self) -> ItbResult<Vec<u8>> {
        let s = ffi::syms()?;
        retry_once(BLOB_CAP, |buf, len| {
            // SAFETY: buf / len are valid for the duration of the call.
            unsafe { (s.ITB_Triple_Save)(self.handle, buf.as_mut_ptr().cast(), buf.len(), len) }
        })
    }

    /// Writes the current session bundle to `path` inside libitb3 (file
    /// mode 0600; the containing directory must exist).
    pub fn save_f(&self, path: impl AsRef<Path>) -> ItbResult<()> {
        let s = ffi::syms()?;
        let path_c = path_cstr(path.as_ref())?;
        // SAFETY: path_c is a live NUL-terminated string.
        check(unsafe { (s.ITB_Triple_SaveF)(self.handle, path_c.as_ptr()) })
    }

    /// Sets the worker cap for every subsequent cipher call. `n` is
    /// clamped by libitb3 (`<= 0` selects auto, `> 256` becomes 256);
    /// only the handle state is reported.
    pub fn max_workers(&self, n: i32) -> ItbResult<()> {
        let s = ffi::syms()?;
        // SAFETY: handle-only call.
        check(unsafe { (s.ITB_Triple_MaxWorkers)(self.handle, n) })
    }

    /// Rotates the parallax + wrapper masters and returns the fresh
    /// session bundle bytes (also available through
    /// [`Pipeline::save`]). Must not run concurrently with cipher
    /// calls or open stream sessions on the same Pipeline.
    pub fn rekey(&mut self, perm: &[u8], wrap: &[u8]) -> ItbResult<Vec<u8>> {
        let s = ffi::syms()?;
        retry_once(BLOB_CAP, |buf, len| {
            // SAFETY: all pointers reference live buffers for the
            // duration of the call; len is a valid out-param.
            unsafe {
                (s.ITB_Triple_Rekey)(
                    self.handle,
                    perm.as_ptr().cast(),
                    perm.len(),
                    wrap.as_ptr().cast(),
                    wrap.len(),
                    buf.as_mut_ptr().cast(),
                    buf.len(),
                    len,
                )
            }
        })
    }

    /// Zeroes the Pipeline's key material and marks it closed.
    /// Idempotent; subsequent cipher calls return
    /// [`ItbStatus::TripleClosed`].
    pub fn close(&mut self) -> ItbResult<()> {
        let s = ffi::syms()?;
        // SAFETY: handle-only call, idempotent on the Go side.
        check(unsafe { (s.ITB_Triple_Close)(self.handle) })
    }

    /// Single Message encrypt: one call, one self-contained wire.
    pub fn encrypt_message(&self, plain: &[u8]) -> ItbResult<Vec<u8>> {
        self.cipher(|s| s.ITB_Triple_EncryptMessage, plain)
    }

    /// Receive-side counterpart of [`Pipeline::encrypt_message`].
    pub fn decrypt_message(&self, wire: &[u8]) -> ItbResult<Vec<u8>> {
        self.cipher(|s| s.ITB_Triple_DecryptMessage, wire)
    }

    /// One-shot stream encrypt for callers holding the whole plaintext
    /// in memory. For bounded-memory streaming use
    /// [`Pipeline::encrypt_stream`] / [`Pipeline::encrypt_stream_pump`].
    pub fn encrypt_stream_one_shot(&self, plain: &[u8]) -> ItbResult<Vec<u8>> {
        self.cipher(|s| s.ITB_Triple_EncryptStream, plain)
    }

    /// Receive-side counterpart of [`Pipeline::encrypt_stream_one_shot`].
    pub fn decrypt_stream_one_shot(&self, wire: &[u8]) -> ItbResult<Vec<u8>> {
        self.cipher(|s| s.ITB_Triple_DecryptStream, wire)
    }

    /// Opens an incremental encrypt session (plaintext in, wire out).
    pub fn encrypt_stream(&self) -> ItbResult<EncryptStream<'_>> {
        EncryptStream::begin(self)
    }

    /// Opens an incremental decrypt session (wire in, plaintext out).
    pub fn decrypt_stream(&self) -> ItbResult<DecryptStream<'_>> {
        DecryptStream::begin(self)
    }

    /// Pumps `src` through an encrypt session into `dst` with bounded
    /// memory: feed a slice, drain available wire, repeat; end + final
    /// drain on source EOF. The session is freed on return.
    pub fn encrypt_stream_pump<R: Read, W: Write>(&self, src: R, dst: W) -> ItbResult<()> {
        self.encrypt_stream()?.pump(src, dst)
    }

    /// Receive-side counterpart of [`Pipeline::encrypt_stream_pump`].
    pub fn decrypt_stream_pump<R: Read, W: Write>(&self, src: R, dst: W) -> ItbResult<()> {
        self.decrypt_stream()?.pump(src, dst)
    }

    pub(crate) fn raw_handle(&self) -> usize {
        self.handle
    }

    /// Shared body for the four buffer-in / buffer-out cipher entries.
    fn cipher(
        &self,
        pick: impl Fn(&'static Syms) -> FnTripleCipher,
        src: &[u8],
    ) -> ItbResult<Vec<u8>> {
        let f = pick(ffi::syms()?);
        retry_once(out_cap(src.len()), |buf, len| {
            // SAFETY: src / buf reference live buffers for the duration
            // of the call; len is a valid out-param.
            unsafe {
                f(
                    self.handle,
                    src.as_ptr().cast(),
                    src.len(),
                    buf.as_mut_ptr().cast(),
                    buf.len(),
                    len,
                )
            }
        })
    }
}

/// Decodes the profile record embedded in `blob` without constructing
/// a Pipeline. No registry read and no primitive probe — a primitive
/// name the local build lacks is returned unchanged.
pub fn inspect(blob: &[u8]) -> ItbResult<Profile> {
    let s = ffi::syms()?;
    let json = retry_once(BLOB_CAP, |buf, len| {
        // SAFETY: blob / buf / len are valid for the duration of the call.
        unsafe {
            (s.ITB_Triple_Inspect)(
                blob.as_ptr().cast(),
                blob.len(),
                buf.as_mut_ptr().cast(),
                buf.len(),
                len,
            )
        }
    })?;
    crate::register::parse_profile(&json)
}

impl std::fmt::Debug for Pipeline {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Pipeline").finish_non_exhaustive()
    }
}

impl Drop for Pipeline {
    fn drop(&mut self) {
        if self.handle == 0 {
            return;
        }
        if let Ok(s) = ffi::syms() {
            // SAFETY: Free closes then releases the handle; safe from
            // any state. The status is deliberately ignored on the
            // drop path.
            let _ = unsafe { (s.ITB_Triple_Free)(self.handle) };
        }
        self.handle = 0;
    }
}

fn cstr(s: &str, msg: &'static str) -> ItbResult<CString> {
    CString::new(s).map_err(|_| ItbError::Ffi(msg))
}

fn path_cstr(path: &Path) -> ItbResult<CString> {
    let text = path.to_str().ok_or(ItbError::Ffi("path is not valid UTF-8"))?;
    cstr(text, "path contains NUL")
}

/// Splits the optional master override pair into the (perm, wrap,
/// count) triple the Load exports take; `None` crosses as absent.
fn split_masters<'a>(masters: Option<(&'a [u8], &'a [u8])>) -> (&'a [u8], &'a [u8], usize) {
    match masters {
        None => (&[][..], &[][..], 0usize),
        Some((pm, wm)) => (pm, wm, 2usize),
    }
}
