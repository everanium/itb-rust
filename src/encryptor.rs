//! High-level Encryptor wrapper over the libitb C ABI.
//!
//! Mirrors the `github.com/everanium/itb/easy` Go sub-package: one
//! constructor call replaces the lower-level seven-line setup ceremony
//! (hash factory, three or seven seeds, MAC closure, container-config
//! wiring) and returns an [`Encryptor`] value that owns its own
//! per-instance configuration. Two encryptors with different settings
//! can be used in parallel without cross-contamination of the
//! process-wide ITB configuration.
//!
//! Quick start (Single Ouroboros + KMAC256):
//!
//! ```no_run
//! use itb::Encryptor;
//!
//! let mut enc = Encryptor::new(Some("blake3"), Some(1024), Some("hmac-blake3"), 1).unwrap();
//! let ct = enc.encrypt_auth(b"hello world").unwrap();
//! let pt = enc.decrypt_auth(&ct).unwrap();
//! assert_eq!(pt, b"hello world");
//! ```
//!
//! Triple Ouroboros (7 seeds, mode = 3):
//!
//! ```no_run
//! use itb::Encryptor;
//!
//! let mut enc = Encryptor::new(Some("areion512"), Some(2048), Some("hmac-blake3"), 3).unwrap();
//! let big: Vec<u8> = b"large payload".repeat(1000);
//! let ct = enc.encrypt(&big).unwrap();
//! let pt = enc.decrypt(&ct).unwrap();
//! assert_eq!(pt, big);
//! ```
//!
//! Cross-process persistence (encrypt today / decrypt tomorrow):
//!
//! ```no_run
//! use itb::{Encryptor, encryptor::peek_config};
//!
//! # let enc = Encryptor::new(Some("blake3"), Some(1024), Some("hmac-blake3"), 1).unwrap();
//! let blob = enc.export().unwrap();
//! // ... save blob to disk / KMS / wire ...
//! let (primitive, key_bits, mode, mac_name) = peek_config(&blob).unwrap();
//! let mut dec = Encryptor::new(Some(&primitive), Some(key_bits), Some(&mac_name), mode).unwrap();
//! dec.import_state(&blob).unwrap();
//! ```
//!
//! Streaming. Chunking lives on the binding side (same pattern as the
//! lower-level API): slice the plaintext into chunks of `chunk_size`
//! bytes and call [`Encryptor::encrypt`] per chunk; on the decrypt side
//! walk the concatenated stream by reading the chunk header, calling
//! [`Encryptor::parse_chunk_len`], and feeding the chunk to
//! [`Encryptor::decrypt`]. The encryptor's chunk-size knob (set via
//! [`Encryptor::set_chunk_size`]) is consumed only by the Go-side
//! `EncryptStream` entry point; one-shot [`Encryptor::encrypt`] honours
//! the container-cap heuristic in `itb.ChunkSize`.
//!
//! Output-buffer cache. The cipher methods reuse a per-encryptor
//! `Vec<u8>` to avoid the per-call allocation cost; the buffer grows
//! on demand and survives between calls. Each cipher call returns a
//! fresh `Vec<u8>` copy of the current result, so the cache is never
//! exposed to the caller — but the cached bytes (the most recent
//! ciphertext or plaintext) sit in heap memory until the next cipher
//! call overwrites them or [`Encryptor::close`] / [`Encryptor::free`]
//! / `Drop` zeroes them. Callers handling sensitive plaintext under a
//! heap-scan threat model should call [`Encryptor::close`]
//! immediately after the last decrypt rather than relying on
//! Drop-time zeroisation at the end of scope.

use std::ffi::{c_char, c_int, c_void, CString};

use crate::error::{read_last_error, ITBError};
use crate::ffi;

/// Reads the offending JSON field name from the most recent
/// `ITB_Easy_Import` call that returned `STATUS_EASY_MISMATCH` on this
/// thread. Empty string when the most recent failure was not a
/// mismatch.
///
/// The [`Encryptor::import_state`] method already attaches this name
/// to the returned [`ITBError`]'s message; this free function is
/// exposed for callers that need to read the field independently of
/// the error path.
pub fn last_mismatch_field() -> String {
    let lib = ffi::lib();
    let mut out_len: usize = 0;
    let rc = unsafe {
        (lib.ITB_Easy_LastMismatchField)(std::ptr::null_mut(), 0, &mut out_len)
    };
    if rc != ffi::STATUS_OK && rc != ffi::STATUS_BUFFER_TOO_SMALL {
        return String::new();
    }
    if out_len <= 1 {
        return String::new();
    }
    let cap = out_len;
    let mut buf = vec![0u8; cap];
    let rc = unsafe {
        (lib.ITB_Easy_LastMismatchField)(
            buf.as_mut_ptr() as *mut c_char,
            cap,
            &mut out_len,
        )
    };
    if rc != ffi::STATUS_OK {
        return String::new();
    }
    let n = out_len.saturating_sub(1);
    buf.truncate(n);
    String::from_utf8(buf).unwrap_or_default()
}

/// Builds an `ITBError` for an Easy-surface failure. On
/// `STATUS_EASY_MISMATCH` the offending JSON field name is read via
/// [`last_mismatch_field`] and folded into the message; every other
/// status falls through to the plain `ITB_LastError` reading.
fn easy_error(code: i32) -> ITBError {
    if code == ffi::STATUS_EASY_MISMATCH {
        let field = last_mismatch_field();
        let last = read_last_error();
        let msg = if field.is_empty() {
            last
        } else if last.is_empty() {
            format!("mismatch on field {field}")
        } else {
            format!("mismatch on field {field}: {last}")
        };
        return ITBError::with_message(code, msg);
    }
    ITBError::from_status(code)
}

/// Helper for the `Result<(), ITBError>` shape with Easy-aware error
/// translation.
fn easy_check(rc: i32) -> Result<(), ITBError> {
    if rc == ffi::STATUS_OK {
        Ok(())
    } else {
        Err(easy_error(rc))
    }
}

/// Helper that treats `STATUS_EASY_MISMATCH` specially via
/// [`easy_error`] when the underlying call would otherwise fall back
/// to the bare `ITB_LastError` reading. Mirrors the size-probe /
/// allocate / write idiom in [`crate::error::read_str`] but routes
/// every non-OK rc through `easy_error` so the offending JSON field
/// name is folded into the message when the rc is
/// `STATUS_EASY_MISMATCH`.
fn easy_read_str<F>(mut call: F) -> Result<String, ITBError>
where
    F: FnMut(*mut c_char, usize, *mut usize) -> i32,
{
    let mut out_len: usize = 0;
    let rc = call(std::ptr::null_mut(), 0, &mut out_len);
    if rc != ffi::STATUS_OK && rc != ffi::STATUS_BUFFER_TOO_SMALL {
        return Err(easy_error(rc));
    }
    if out_len == 0 {
        return Ok(String::new());
    }
    let cap = out_len;
    let mut buf = vec![0u8; cap];
    let rc = call(buf.as_mut_ptr() as *mut c_char, cap, &mut out_len);
    if rc != ffi::STATUS_OK {
        return Err(easy_error(rc));
    }
    let n = out_len.saturating_sub(1);
    buf.truncate(n);
    String::from_utf8(buf).map_err(|e| {
        ITBError::with_message(ffi::STATUS_INTERNAL, format!("utf8 decode: {e}"))
    })
}

/// Parses a state blob's metadata `(primitive, key_bits, mode, mac)`
/// without performing full validation, allowing a caller to inspect a
/// saved blob before constructing a matching encryptor.
///
/// Returns the four-tuple on success; surfaces
/// `ITBError(STATUS_EASY_MALFORMED)` on JSON parse failure / kind
/// mismatch / too-new version / unknown mode value.
pub fn peek_config(blob: &[u8]) -> Result<(String, i32, i32, String), ITBError> {
    let lib = ffi::lib();
    let blob_ptr = if blob.is_empty() {
        std::ptr::null()
    } else {
        blob.as_ptr() as *const c_void
    };

    // Probe both string sizes first.
    let mut prim_len: usize = 0;
    let mut mac_len: usize = 0;
    let mut kb_out: c_int = 0;
    let mut mode_out: c_int = 0;
    let rc = unsafe {
        (lib.ITB_Easy_PeekConfig)(
            blob_ptr,
            blob.len(),
            std::ptr::null_mut(),
            0,
            &mut prim_len,
            &mut kb_out,
            &mut mode_out,
            std::ptr::null_mut(),
            0,
            &mut mac_len,
        )
    };
    if rc != ffi::STATUS_OK && rc != ffi::STATUS_BUFFER_TOO_SMALL {
        return Err(easy_error(rc));
    }

    let prim_cap = prim_len;
    let mac_cap = mac_len;
    let mut prim_buf = vec![0u8; prim_cap];
    let mut mac_buf = vec![0u8; mac_cap];
    let rc = unsafe {
        (lib.ITB_Easy_PeekConfig)(
            blob_ptr,
            blob.len(),
            prim_buf.as_mut_ptr() as *mut c_char,
            prim_cap,
            &mut prim_len,
            &mut kb_out,
            &mut mode_out,
            mac_buf.as_mut_ptr() as *mut c_char,
            mac_cap,
            &mut mac_len,
        )
    };
    if rc != ffi::STATUS_OK {
        return Err(easy_error(rc));
    }
    let prim_n = prim_len.saturating_sub(1);
    let mac_n = mac_len.saturating_sub(1);
    prim_buf.truncate(prim_n);
    mac_buf.truncate(mac_n);
    let primitive = String::from_utf8(prim_buf).map_err(|e| {
        ITBError::with_message(ffi::STATUS_INTERNAL, format!("utf8 decode: {e}"))
    })?;
    let mac_name = String::from_utf8(mac_buf).map_err(|e| {
        ITBError::with_message(ffi::STATUS_INTERNAL, format!("utf8 decode: {e}"))
    })?;
    Ok((primitive, kb_out as i32, mode_out as i32, mac_name))
}

/// High-level Encryptor over the libitb C ABI.
///
/// Construction is the heavy step — generates fresh PRF keys, fresh
/// seed components, and a fresh MAC key from `/dev/urandom`. Reusing
/// one [`Encryptor`] value across many encrypt / decrypt calls
/// amortises the cost across the lifetime of a session.
///
/// Lifecycle is RAII: dropping the value calls `ITB_Easy_Free`
/// best-effort. [`Encryptor::close`] is the explicit zeroing path
/// (wipes PRF / MAC / seed material on the Go side and wipes the
/// per-instance output cache on the Rust side); [`Encryptor::free`]
/// is the consuming counterpart that surfaces release-time errors.
///
/// # Thread-safety contract
///
/// Cipher methods ([`Encryptor::encrypt`] / [`Encryptor::decrypt`] /
/// [`Encryptor::encrypt_auth`] / [`Encryptor::decrypt_auth`]) write
/// into the per-instance output-buffer cache and are **not safe** to
/// invoke concurrently against the same encryptor — Rust's borrow
/// checker rejects parallel `&mut self` calls at compile time, but
/// callers that wrap an `Encryptor` in `Arc<Mutex<...>>` etc. must
/// keep the lock held for the duration of every cipher call. Sharing
/// one [`Encryptor`] across threads requires external
/// synchronisation. Per-instance configuration setters
/// ([`Encryptor::set_nonce_bits`] / [`Encryptor::set_barrier_fill`]
/// / [`Encryptor::set_bit_soup`] / [`Encryptor::set_lock_soup`] /
/// [`Encryptor::set_lock_seed`] / [`Encryptor::set_chunk_size`]) and
/// state-serialisation methods ([`Encryptor::export_state`] /
/// [`Encryptor::import_state`]) likewise require external
/// synchronisation when invoked against the same encryptor from
/// multiple threads. Distinct [`Encryptor`] values, each owned by
/// one thread, run independently against the libitb worker pool.
pub struct Encryptor {
    handle: usize,
    /// Per-encryptor output buffer cache. Grows on demand;
    /// [`Encryptor::close`] / [`Encryptor::free`] / `Drop` wipe it
    /// before drop.
    out_buf: Vec<u8>,
    /// Tracks the closed / freed state independently of the handle
    /// field so the preflight in [`Encryptor::check_open`] can
    /// surface `STATUS_EASY_CLOSED` after [`Encryptor::close`] /
    /// [`Encryptor::free`] without relying on the libitb-side
    /// handle-id lookup (which would surface `STATUS_BAD_HANDLE` once
    /// [`Encryptor::free`] has cleared the handle slot).
    closed: bool,
}

impl Encryptor {
    /// Preflight rejection for closed / freed encryptors. Surfaces
    /// `ITBError(STATUS_EASY_CLOSED)` before any libitb FFI call so
    /// callers see the canonical "encryptor has been closed" code
    /// regardless of whether the underlying handle slot has merely
    /// been zeroed (post-[`Encryptor::close`]) or has been released
    /// back to libitb (post-[`Encryptor::free`]).
    fn check_open(&self) -> Result<(), ITBError> {
        if self.closed || self.handle == 0 {
            return Err(ITBError::with_message(
                ffi::STATUS_EASY_CLOSED,
                "encryptor has been closed",
            ));
        }
        Ok(())
    }

    /// Constructs a fresh encryptor.
    ///
    /// `primitive` is a canonical hash name from
    /// [`crate::list_hashes`] — `"areion256"`, `"areion512"`,
    /// `"siphash24"`, `"aescmac"`, `"blake2b256"`, `"blake2b512"`,
    /// `"blake2s"`, `"blake3"`, `"chacha20"`. `None` selects the
    /// package default (`"areion512"`).
    ///
    /// `key_bits` is the ITB key width in bits (512, 1024, 2048;
    /// multiple of the primitive's native hash width). `None` selects
    /// 1024.
    ///
    /// `mac` is a canonical MAC name from [`crate::list_macs`] —
    /// `"kmac256"`, `"hmac-sha256"`, or `"hmac-blake3"`. `None`
    /// selects `"hmac-blake3"`.
    ///
    /// `mode` is 1 (Single Ouroboros, 3 seeds — noise / data / start)
    /// or 3 (Triple Ouroboros, 7 seeds — noise + 3 pairs of data /
    /// start). Other values surface as
    /// `ITBError(STATUS_BAD_INPUT)`.
    pub fn new(
        primitive: Option<&str>,
        key_bits: Option<i32>,
        mac: Option<&str>,
        mode: i32,
    ) -> Result<Self, ITBError> {
        let lib = ffi::lib();
        let prim_c = match primitive {
            Some(s) => Some(CString::new(s).map_err(|_| {
                ITBError::with_message(ffi::STATUS_BAD_INPUT, "primitive contains NUL")
            })?),
            None => None,
        };
        // Binding-side default override: when the caller passes
        // `mac=None` the binding picks `hmac-blake3` rather than
        // forwarding NULL through to libitb's own default. HMAC-BLAKE3
        // measures the lightest MAC overhead in the Easy Mode bench
        // surface; routing the default through it gives the
        // "constructor without arguments" path the lowest cost.
        let mac_str = mac.unwrap_or("hmac-blake3");
        let mac_c = CString::new(mac_str).map_err(|_| {
            ITBError::with_message(ffi::STATUS_BAD_INPUT, "mac contains NUL")
        })?;
        let prim_ptr = prim_c.as_ref().map_or(std::ptr::null(), |c| c.as_ptr());
        let mac_ptr = mac_c.as_ptr();
        let kb = key_bits.unwrap_or(0);

        let mut handle: usize = 0;
        let rc = unsafe {
            (lib.ITB_Easy_New)(prim_ptr, kb, mac_ptr, mode, &mut handle)
        };
        if rc != ffi::STATUS_OK {
            return Err(easy_error(rc));
        }
        Ok(Self {
            handle,
            out_buf: Vec::new(),
            closed: false,
        })
    }

    // ─── Mixed-mode constructors ───────────────────────────────────

    /// Constructs a Single-Ouroboros encryptor with per-slot PRF
    /// primitive selection.
    ///
    /// `primitive_n` / `primitive_d` / `primitive_s` cover the noise /
    /// data / start slots; `primitive_l` (default `None`) is the
    /// optional dedicated lockSeed primitive — when provided, a 4th
    /// seed slot is allocated under that primitive and BitSoup +
    /// LockSoup are auto-coupled on the on-direction.
    ///
    /// All four primitive names must resolve to the same native hash
    /// width via the libitb registry; mixed widths raise
    /// [`ITBError`] with the panic message captured in
    /// `read_last_error`.
    pub fn mixed_single(
        primitive_n: &str,
        primitive_d: &str,
        primitive_s: &str,
        primitive_l: Option<&str>,
        key_bits: i32,
        mac: &str,
    ) -> Result<Self, ITBError> {
        let lib = ffi::lib();
        let cn = CString::new(primitive_n).map_err(|_| {
            ITBError::with_message(ffi::STATUS_BAD_INPUT, "primitive_n contains NUL")
        })?;
        let cd = CString::new(primitive_d).map_err(|_| {
            ITBError::with_message(ffi::STATUS_BAD_INPUT, "primitive_d contains NUL")
        })?;
        let cs = CString::new(primitive_s).map_err(|_| {
            ITBError::with_message(ffi::STATUS_BAD_INPUT, "primitive_s contains NUL")
        })?;
        let cmac = CString::new(mac).map_err(|_| {
            ITBError::with_message(ffi::STATUS_BAD_INPUT, "mac contains NUL")
        })?;
        let cl = match primitive_l {
            Some(s) if !s.is_empty() => Some(CString::new(s).map_err(|_| {
                ITBError::with_message(ffi::STATUS_BAD_INPUT, "primitive_l contains NUL")
            })?),
            _ => None,
        };
        let l_ptr = cl.as_ref().map_or(std::ptr::null(), |c| c.as_ptr());

        let mut handle: usize = 0;
        let rc = unsafe {
            (lib.ITB_Easy_NewMixed)(
                cn.as_ptr(),
                cd.as_ptr(),
                cs.as_ptr(),
                l_ptr,
                key_bits,
                cmac.as_ptr(),
                &mut handle,
            )
        };
        if rc != ffi::STATUS_OK {
            return Err(easy_error(rc));
        }
        Ok(Self {
            handle,
            out_buf: Vec::new(),
            closed: false,
        })
    }

    /// Triple-Ouroboros counterpart of [`Encryptor::mixed_single`].
    /// Accepts seven per-slot primitive names (noise + 3 data +
    /// 3 start) plus the optional `primitive_l` lockSeed primitive.
    /// See [`Encryptor::mixed_single`] for the construction contract.
    #[allow(clippy::too_many_arguments)]
    pub fn mixed_triple(
        primitive_n: &str,
        primitive_d1: &str,
        primitive_d2: &str,
        primitive_d3: &str,
        primitive_s1: &str,
        primitive_s2: &str,
        primitive_s3: &str,
        primitive_l: Option<&str>,
        key_bits: i32,
        mac: &str,
    ) -> Result<Self, ITBError> {
        let lib = ffi::lib();
        let cn = CString::new(primitive_n).map_err(|_| {
            ITBError::with_message(ffi::STATUS_BAD_INPUT, "primitive_n contains NUL")
        })?;
        let cd1 = CString::new(primitive_d1).map_err(|_| {
            ITBError::with_message(ffi::STATUS_BAD_INPUT, "primitive_d1 contains NUL")
        })?;
        let cd2 = CString::new(primitive_d2).map_err(|_| {
            ITBError::with_message(ffi::STATUS_BAD_INPUT, "primitive_d2 contains NUL")
        })?;
        let cd3 = CString::new(primitive_d3).map_err(|_| {
            ITBError::with_message(ffi::STATUS_BAD_INPUT, "primitive_d3 contains NUL")
        })?;
        let cs1 = CString::new(primitive_s1).map_err(|_| {
            ITBError::with_message(ffi::STATUS_BAD_INPUT, "primitive_s1 contains NUL")
        })?;
        let cs2 = CString::new(primitive_s2).map_err(|_| {
            ITBError::with_message(ffi::STATUS_BAD_INPUT, "primitive_s2 contains NUL")
        })?;
        let cs3 = CString::new(primitive_s3).map_err(|_| {
            ITBError::with_message(ffi::STATUS_BAD_INPUT, "primitive_s3 contains NUL")
        })?;
        let cmac = CString::new(mac).map_err(|_| {
            ITBError::with_message(ffi::STATUS_BAD_INPUT, "mac contains NUL")
        })?;
        let cl = match primitive_l {
            Some(s) if !s.is_empty() => Some(CString::new(s).map_err(|_| {
                ITBError::with_message(ffi::STATUS_BAD_INPUT, "primitive_l contains NUL")
            })?),
            _ => None,
        };
        let l_ptr = cl.as_ref().map_or(std::ptr::null(), |c| c.as_ptr());

        let mut handle: usize = 0;
        let rc = unsafe {
            (lib.ITB_Easy_NewMixed3)(
                cn.as_ptr(),
                cd1.as_ptr(),
                cd2.as_ptr(),
                cd3.as_ptr(),
                cs1.as_ptr(),
                cs2.as_ptr(),
                cs3.as_ptr(),
                l_ptr,
                key_bits,
                cmac.as_ptr(),
                &mut handle,
            )
        };
        if rc != ffi::STATUS_OK {
            return Err(easy_error(rc));
        }
        Ok(Self {
            handle,
            out_buf: Vec::new(),
            closed: false,
        })
    }

    // ─── Per-slot primitive accessors ──────────────────────────────

    /// Returns the canonical hash primitive name bound to the given
    /// seed slot index.
    ///
    /// Slot ordering is canonical — 0 = noiseSeed, then
    /// dataSeed{,1..3}, then startSeed{,1..3}, with the optional
    /// dedicated lockSeed at the trailing slot. For single-primitive
    /// encryptors every slot returns the same [`Encryptor::primitive`]
    /// value; for encryptors built via [`Encryptor::mixed_single`] /
    /// [`Encryptor::mixed_triple`] each slot returns its
    /// independently-chosen primitive name.
    pub fn primitive_at(&self, slot: i32) -> Result<String, ITBError> {
        self.check_open()?;
        let lib = ffi::lib();
        let handle = self.handle;
        easy_read_str(|out: *mut c_char, cap, out_len| unsafe {
            (lib.ITB_Easy_PrimitiveAt)(handle, slot, out, cap, out_len)
        })
    }

    /// Returns `true` when the encryptor was constructed via
    /// [`Encryptor::mixed_single`] or [`Encryptor::mixed_triple`]
    /// (per-slot primitive selection); `false` for single-primitive
    /// encryptors built via [`Encryptor::new`].
    pub fn is_mixed(&self) -> Result<bool, ITBError> {
        self.check_open()?;
        let lib = ffi::lib();
        let mut st: c_int = 0;
        let v = unsafe { (lib.ITB_Easy_IsMixed)(self.handle, &mut st) };
        if st != ffi::STATUS_OK {
            return Err(easy_error(st));
        }
        Ok(v != 0)
    }

    // ─── Read-only field accessors ─────────────────────────────────

    /// Opaque libitb handle id (uintptr). Useful for diagnostics and
    /// FFI-level interop; bindings should not rely on its numerical
    /// value.
    pub fn handle(&self) -> usize {
        self.handle
    }

    /// Returns the canonical primitive name bound at construction.
    pub fn primitive(&self) -> Result<String, ITBError> {
        self.check_open()?;
        let lib = ffi::lib();
        let handle = self.handle;
        easy_read_str(|out: *mut c_char, cap, out_len| unsafe {
            (lib.ITB_Easy_Primitive)(handle, out, cap, out_len)
        })
    }

    /// Returns the ITB key width in bits.
    pub fn key_bits(&self) -> Result<i32, ITBError> {
        self.check_open()?;
        let lib = ffi::lib();
        let mut st: c_int = 0;
        let v = unsafe { (lib.ITB_Easy_KeyBits)(self.handle, &mut st) };
        if st != ffi::STATUS_OK {
            return Err(easy_error(st));
        }
        Ok(v as i32)
    }

    /// Returns 1 (Single Ouroboros) or 3 (Triple Ouroboros).
    pub fn mode(&self) -> Result<i32, ITBError> {
        self.check_open()?;
        let lib = ffi::lib();
        let mut st: c_int = 0;
        let v = unsafe { (lib.ITB_Easy_Mode)(self.handle, &mut st) };
        if st != ffi::STATUS_OK {
            return Err(easy_error(st));
        }
        Ok(v as i32)
    }

    /// Returns the canonical MAC name bound at construction.
    pub fn mac_name(&self) -> Result<String, ITBError> {
        self.check_open()?;
        let lib = ffi::lib();
        let handle = self.handle;
        easy_read_str(|out: *mut c_char, cap, out_len| unsafe {
            (lib.ITB_Easy_MACName)(handle, out, cap, out_len)
        })
    }

    /// Returns the nonce size in bits configured for this encryptor —
    /// either the value from the most recent
    /// [`Encryptor::set_nonce_bits`] call, or the process-wide
    /// [`crate::get_nonce_bits`] reading at construction time when no
    /// per-instance override has been issued. Reads the live
    /// `cfg.NonceBits` via `ITB_Easy_NonceBits` so a setter call on
    /// the Go side is reflected immediately.
    pub fn nonce_bits(&self) -> Result<i32, ITBError> {
        self.check_open()?;
        let lib = ffi::lib();
        let mut st: c_int = 0;
        let v = unsafe { (lib.ITB_Easy_NonceBits)(self.handle, &mut st) };
        if st != ffi::STATUS_OK {
            return Err(easy_error(st));
        }
        Ok(v as i32)
    }

    /// Returns the per-instance ciphertext-chunk header size in bytes
    /// (nonce + 2-byte width + 2-byte height).
    ///
    /// Tracks this encryptor's own [`Encryptor::nonce_bits`], NOT the
    /// process-wide [`crate::header_size`] reading — important when
    /// the encryptor has called [`Encryptor::set_nonce_bits`] to
    /// override the default. Use this when slicing a chunk header off
    /// the front of a ciphertext stream produced by this encryptor or
    /// when sizing a tamper region for an authenticated-decrypt test.
    pub fn header_size(&self) -> Result<i32, ITBError> {
        self.check_open()?;
        let lib = ffi::lib();
        let mut st: c_int = 0;
        let v = unsafe { (lib.ITB_Easy_HeaderSize)(self.handle, &mut st) };
        if st != ffi::STATUS_OK {
            return Err(easy_error(st));
        }
        Ok(v as i32)
    }

    /// Per-instance counterpart of [`crate::parse_chunk_len`].
    /// Inspects a chunk header (the fixed-size
    /// `[nonce(N) || width(2) || height(2)]` prefix where `N` comes
    /// from this encryptor's [`Encryptor::nonce_bits`]) and returns
    /// the total chunk length on the wire.
    ///
    /// Use this when walking a concatenated chunk stream produced by
    /// this encryptor: read [`Encryptor::header_size`] bytes from the
    /// wire, call `enc.parse_chunk_len(&buf[..enc.header_size()? as
    /// usize])`, read the remaining `chunk_len - header_size` bytes,
    /// and feed the full chunk to [`Encryptor::decrypt`] /
    /// [`Encryptor::decrypt_auth`].
    ///
    /// The buffer must contain at least
    /// [`Encryptor::header_size`] bytes; only the header is
    /// consulted, the body bytes do not need to be present. Surfaces
    /// `ITBError(STATUS_BAD_INPUT)` on too-short buffer, zero
    /// dimensions, or width × height overflow against the container
    /// pixel cap.
    pub fn parse_chunk_len(&self, header: &[u8]) -> Result<usize, ITBError> {
        self.check_open()?;
        let lib = ffi::lib();
        let hdr_ptr = if header.is_empty() {
            std::ptr::null()
        } else {
            header.as_ptr() as *const c_void
        };
        let mut out: usize = 0;
        let rc = unsafe {
            (lib.ITB_Easy_ParseChunkLen)(self.handle, hdr_ptr, header.len(), &mut out)
        };
        if rc != ffi::STATUS_OK {
            return Err(easy_error(rc));
        }
        Ok(out)
    }

    // ─── Cipher entry points ──────────────────────────────────────

    /// Encrypts `plaintext` using the encryptor's configured primitive
    /// / key_bits / mode and per-instance Config snapshot.
    ///
    /// Plain mode — does not attach a MAC tag; for authenticated
    /// encryption use [`Encryptor::encrypt_auth`].
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, ITBError> {
        let f = ffi::lib().ITB_Easy_Encrypt;
        self.cipher_call(f, plaintext)
    }

    /// Decrypts ciphertext produced by [`Encryptor::encrypt`] under
    /// the same encryptor.
    pub fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, ITBError> {
        let f = ffi::lib().ITB_Easy_Decrypt;
        self.cipher_call(f, ciphertext)
    }

    /// Encrypts `plaintext` and attaches a MAC tag using the
    /// encryptor's bound MAC closure.
    pub fn encrypt_auth(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, ITBError> {
        let f = ffi::lib().ITB_Easy_EncryptAuth;
        self.cipher_call(f, plaintext)
    }

    /// Verifies and decrypts ciphertext produced by
    /// [`Encryptor::encrypt_auth`]. Surfaces
    /// `ITBError(STATUS_MAC_FAILURE)` on tampered ciphertext / wrong
    /// MAC key.
    pub fn decrypt_auth(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, ITBError> {
        let f = ffi::lib().ITB_Easy_DecryptAuth;
        self.cipher_call(f, ciphertext)
    }

    /// Direct-call buffer-convention dispatcher with a per-encryptor
    /// output cache. Skips the size-probe round-trip the lower-level
    /// FFI helpers use: pre-allocates output capacity from a 1.25×
    /// upper bound (the empirical ITB ciphertext-expansion factor
    /// measured at ≤ 1.155 across every primitive / mode / nonce /
    /// payload-size combination) and falls through to an explicit
    /// grow-and-retry only on the rare under-shoot. Reuses the buffer
    /// across calls; [`Encryptor::close`] / [`Encryptor::free`]
    /// /`Drop` wipe it before drop.
    ///
    /// The current `Easy_Encrypt` / `Easy_Decrypt` C ABI does the
    /// full crypto on every call regardless of out-buffer capacity
    /// (it computes the result internally, then returns
    /// `BUFFER_TOO_SMALL` without exposing the work) — so the
    /// pre-allocation here avoids paying for a duplicate encrypt /
    /// decrypt on each Rust call.
    fn cipher_call(
        &mut self,
        f: ffi::FnEasyEncrypt,
        payload: &[u8],
    ) -> Result<Vec<u8>, ITBError> {
        self.check_open()?;
        let payload_len = payload.len();
        // 1.25× + 128 KiB headroom comfortably exceeds the worst-case
        // expansion observed across the primitive / mode / nonce-bits
        // / barrier-fill matrix; bf=32 with payloads near 1 MiB
        // pushes the absolute ratio to ~1.346, leaving roughly
        // 100 KiB of residual margin over the 1.25× term that the
        // constant pad must absorb. The 128 KiB pad covers that worst
        // case (and the ratio tapers below 1.25× + small-K beyond a
        // few MiB as the bf-induced sqrt-shaped border overhead
        // becomes asymptotically negligible). Floor at 128 KiB so the
        // very-small payload case still gets a usable buffer that
        // handles the Triple + auth-MAC + bf=32 short-payload
        // expansion (~35 KiB at ptlen=1). The `saturating_mul`
        // protects against `usize` wrap on 32-bit targets at very
        // large payload sizes — under wrap the grow-and-retry path
        // would still recover, but only at the cost of an extra
        // round-trip; saturating to `usize::MAX` keeps the first call
        // big enough on any host.
        let cap = std::cmp::max(131072, payload_len.saturating_mul(5) / 4 + 131072);
        if self.out_buf.len() < cap {
            // Wipe previous contents before drop — Vec's default drop
            // deallocates without zeroing the heap region.
            for b in self.out_buf.iter_mut() { *b = 0; }
            self.out_buf = vec![0u8; cap];
        }

        let in_ptr = if payload_len == 0 {
            std::ptr::null()
        } else {
            payload.as_ptr() as *const c_void
        };

        let mut out_len: usize = 0;
        let mut rc = unsafe {
            f(
                self.handle,
                in_ptr,
                payload_len,
                self.out_buf.as_mut_ptr() as *mut c_void,
                self.out_buf.len(),
                &mut out_len,
            )
        };
        if rc == ffi::STATUS_BUFFER_TOO_SMALL {
            // Pre-allocation was too tight (extremely rare given the
            // 1.25× safety margin) — grow exactly to the required
            // size and retry. The first call already paid for the
            // underlying crypto via the current C ABI's
            // full-encrypt-on-every-call contract, so the retry runs
            // the work again; this is strictly the fallback path and
            // not the hot loop.
            let need = out_len;
            for b in self.out_buf.iter_mut() { *b = 0; }
            self.out_buf = vec![0u8; need];
            rc = unsafe {
                f(
                    self.handle,
                    in_ptr,
                    payload_len,
                    self.out_buf.as_mut_ptr() as *mut c_void,
                    self.out_buf.len(),
                    &mut out_len,
                )
            };
        }
        if rc != ffi::STATUS_OK {
            return Err(easy_error(rc));
        }
        Ok(self.out_buf[..out_len].to_vec())
    }

    // ─── Per-instance configuration setters ───────────────────────

    /// Override the nonce size for this encryptor's subsequent
    /// encrypt / decrypt calls. Valid values: 128, 256, 512.
    ///
    /// Mutates only this encryptor's Config copy; process-wide
    /// [`crate::set_nonce_bits`] is unaffected. The
    /// [`Encryptor::nonce_bits`] / [`Encryptor::header_size`]
    /// accessors read through to the live Go-side `cfg.NonceBits`,
    /// so they reflect the new value automatically on the next
    /// access.
    pub fn set_nonce_bits(&self, n: i32) -> Result<(), ITBError> {
        self.check_open()?;
        let lib = ffi::lib();
        let rc = unsafe { (lib.ITB_Easy_SetNonceBits)(self.handle, n) };
        easy_check(rc)
    }

    /// Override the CSPRNG barrier-fill margin for this encryptor.
    /// Valid values: 1, 2, 4, 8, 16, 32. Asymmetric — receiver does
    /// not need the same value as sender.
    pub fn set_barrier_fill(&self, n: i32) -> Result<(), ITBError> {
        self.check_open()?;
        let lib = ffi::lib();
        let rc = unsafe { (lib.ITB_Easy_SetBarrierFill)(self.handle, n) };
        easy_check(rc)
    }

    /// 0 = byte-level split (default); non-zero = bit-level Bit Soup
    /// split.
    pub fn set_bit_soup(&self, mode: i32) -> Result<(), ITBError> {
        self.check_open()?;
        let lib = ffi::lib();
        let rc = unsafe { (lib.ITB_Easy_SetBitSoup)(self.handle, mode) };
        easy_check(rc)
    }

    /// 0 = off (default); non-zero = on. Auto-couples `BitSoup=1`
    /// on this encryptor.
    pub fn set_lock_soup(&self, mode: i32) -> Result<(), ITBError> {
        self.check_open()?;
        let lib = ffi::lib();
        let rc = unsafe { (lib.ITB_Easy_SetLockSoup)(self.handle, mode) };
        easy_check(rc)
    }

    /// 0 = off; 1 = on (allocates a dedicated lockSeed and routes the
    /// bit-permutation overlay through it; auto-couples
    /// `LockSoup=1 + BitSoup=1` on this encryptor). Calling after the
    /// first encrypt surfaces
    /// `ITBError(STATUS_EASY_LOCKSEED_AFTER_ENCRYPT)`.
    pub fn set_lock_seed(&self, mode: i32) -> Result<(), ITBError> {
        self.check_open()?;
        let lib = ffi::lib();
        let rc = unsafe { (lib.ITB_Easy_SetLockSeed)(self.handle, mode) };
        easy_check(rc)
    }

    /// Per-instance streaming chunk-size override (0 = auto-detect
    /// via `itb.ChunkSize` on the Go side).
    pub fn set_chunk_size(&self, n: i32) -> Result<(), ITBError> {
        self.check_open()?;
        let lib = ffi::lib();
        let rc = unsafe { (lib.ITB_Easy_SetChunkSize)(self.handle, n) };
        easy_check(rc)
    }

    // ─── Material getters (defensive copies) ──────────────────────

    /// Number of seed slots: 3 (Single without LockSeed),
    /// 4 (Single with LockSeed), 7 (Triple without LockSeed),
    /// 8 (Triple with LockSeed).
    pub fn seed_count(&self) -> Result<i32, ITBError> {
        self.check_open()?;
        let lib = ffi::lib();
        let mut st: c_int = 0;
        let v = unsafe { (lib.ITB_Easy_SeedCount)(self.handle, &mut st) };
        if st != ffi::STATUS_OK {
            return Err(easy_error(st));
        }
        Ok(v as i32)
    }

    /// Returns the uint64 components of one seed slot (defensive
    /// copy).
    ///
    /// Slot index follows the canonical ordering: Single =
    /// `[noise, data, start]`; Triple = `[noise, data1, data2,
    /// data3, start1, start2, start3]`; the dedicated lockSeed slot,
    /// when present, is appended at the trailing index (index 3 for
    /// Single, index 7 for Triple). Bindings can consult
    /// [`Encryptor::seed_count`] to determine the valid slot range
    /// for the active mode + lockSeed configuration.
    pub fn seed_components(&self, slot: i32) -> Result<Vec<u64>, ITBError> {
        self.check_open()?;
        let lib = ffi::lib();
        let mut out_len: c_int = 0;
        // Probe call — out=NULL / capCount=0 returns
        // STATUS_BUFFER_TOO_SMALL with the required size in *outLen.
        // STATUS_BAD_INPUT here would signal an out-of-range slot.
        let rc = unsafe {
            (lib.ITB_Easy_SeedComponents)(
                self.handle,
                slot,
                std::ptr::null_mut(),
                0,
                &mut out_len,
            )
        };
        if rc == ffi::STATUS_OK {
            return Ok(Vec::new());
        }
        if rc != ffi::STATUS_BUFFER_TOO_SMALL {
            return Err(easy_error(rc));
        }
        let n = out_len as usize;
        let mut buf = vec![0u64; n];
        let rc = unsafe {
            (lib.ITB_Easy_SeedComponents)(
                self.handle,
                slot,
                buf.as_mut_ptr(),
                n as c_int,
                &mut out_len,
            )
        };
        if rc != ffi::STATUS_OK {
            return Err(easy_error(rc));
        }
        buf.truncate(out_len as usize);
        Ok(buf)
    }

    /// `true` when the encryptor's primitive uses fixed PRF keys per
    /// seed slot (every shipped primitive except `siphash24`).
    pub fn has_prf_keys(&self) -> Result<bool, ITBError> {
        self.check_open()?;
        let lib = ffi::lib();
        let mut st: c_int = 0;
        let v = unsafe { (lib.ITB_Easy_HasPRFKeys)(self.handle, &mut st) };
        if st != ffi::STATUS_OK {
            return Err(easy_error(st));
        }
        Ok(v != 0)
    }

    /// Returns the fixed PRF key bytes for one seed slot (defensive
    /// copy). Surfaces `ITBError(STATUS_BAD_INPUT)` when the
    /// primitive has no fixed PRF keys (`siphash24` — caller should
    /// consult [`Encryptor::has_prf_keys`] first) or when `slot` is
    /// out of range.
    pub fn prf_key(&self, slot: i32) -> Result<Vec<u8>, ITBError> {
        self.check_open()?;
        let lib = ffi::lib();
        let mut out_len: usize = 0;
        let rc = unsafe {
            (lib.ITB_Easy_PRFKey)(self.handle, slot, std::ptr::null_mut(), 0, &mut out_len)
        };
        // Probe pattern: zero-length key → STATUS_OK + outLen=0
        // (e.g. siphash24); non-zero length → STATUS_BUFFER_TOO_SMALL
        // with outLen carrying the required size. STATUS_BAD_INPUT
        // is reserved for out-of-range slot or no-fixed-key primitive.
        if rc == ffi::STATUS_OK && out_len == 0 {
            return Ok(Vec::new());
        }
        if rc != ffi::STATUS_BUFFER_TOO_SMALL {
            return Err(easy_error(rc));
        }
        let n = out_len;
        let mut buf = vec![0u8; n];
        let rc = unsafe {
            (lib.ITB_Easy_PRFKey)(self.handle, slot, buf.as_mut_ptr(), n, &mut out_len)
        };
        if rc != ffi::STATUS_OK {
            return Err(easy_error(rc));
        }
        buf.truncate(out_len);
        Ok(buf)
    }

    /// Returns a defensive copy of the encryptor's bound MAC fixed
    /// key. Save these bytes alongside the seed material for
    /// cross-process restore via [`Encryptor::export`] /
    /// [`Encryptor::import_state`].
    pub fn mac_key(&self) -> Result<Vec<u8>, ITBError> {
        self.check_open()?;
        let lib = ffi::lib();
        let mut out_len: usize = 0;
        let rc = unsafe {
            (lib.ITB_Easy_MACKey)(self.handle, std::ptr::null_mut(), 0, &mut out_len)
        };
        if rc == ffi::STATUS_OK && out_len == 0 {
            return Ok(Vec::new());
        }
        if rc != ffi::STATUS_BUFFER_TOO_SMALL {
            return Err(easy_error(rc));
        }
        let n = out_len;
        let mut buf = vec![0u8; n];
        let rc = unsafe {
            (lib.ITB_Easy_MACKey)(self.handle, buf.as_mut_ptr(), n, &mut out_len)
        };
        if rc != ffi::STATUS_OK {
            return Err(easy_error(rc));
        }
        buf.truncate(out_len);
        Ok(buf)
    }

    // ─── State serialization ──────────────────────────────────────

    /// Serialises the encryptor's full state (PRF keys, seed
    /// components, MAC key, dedicated lockSeed material when active)
    /// as a JSON blob. The caller saves the bytes as it sees fit
    /// (disk, KMS, wire) and later passes them back to
    /// [`Encryptor::import_state`] on a fresh encryptor to
    /// reconstruct the exact state.
    ///
    /// Per-instance configuration knobs (NonceBits, BarrierFill,
    /// BitSoup, LockSoup, ChunkSize) are NOT carried in the v1 blob
    /// — both sides communicate them via deployment config.
    /// LockSeed is carried because activating it changes the
    /// structural seed count.
    pub fn export(&self) -> Result<Vec<u8>, ITBError> {
        self.check_open()?;
        let lib = ffi::lib();
        let mut out_len: usize = 0;
        let rc = unsafe {
            (lib.ITB_Easy_Export)(self.handle, std::ptr::null_mut(), 0, &mut out_len)
        };
        if rc == ffi::STATUS_OK {
            return Ok(Vec::new());
        }
        if rc != ffi::STATUS_BUFFER_TOO_SMALL {
            return Err(easy_error(rc));
        }
        let need = out_len;
        let mut buf = vec![0u8; need];
        let rc = unsafe {
            (lib.ITB_Easy_Export)(
                self.handle,
                buf.as_mut_ptr() as *mut c_void,
                need,
                &mut out_len,
            )
        };
        if rc != ffi::STATUS_OK {
            return Err(easy_error(rc));
        }
        buf.truncate(out_len);
        Ok(buf)
    }

    /// Replaces the encryptor's PRF keys, seed components, MAC key,
    /// and (optionally) dedicated lockSeed material with the values
    /// carried in a JSON blob produced by a prior
    /// [`Encryptor::export`] call.
    ///
    /// On any failure the encryptor's pre-import state is unchanged
    /// (the underlying Go-side `Encryptor.Import` is transactional).
    /// Mismatch on primitive / key_bits / mode / mac surfaces as
    /// [`ITBError`] with code
    /// [`crate::STATUS_EASY_MISMATCH`]; the offending JSON field
    /// name is folded into the error's message and is also
    /// retrievable via [`last_mismatch_field`].
    pub fn import_state(&self, blob: &[u8]) -> Result<(), ITBError> {
        self.check_open()?;
        let lib = ffi::lib();
        let blob_ptr = if blob.is_empty() {
            std::ptr::null()
        } else {
            blob.as_ptr() as *const c_void
        };
        let rc = unsafe { (lib.ITB_Easy_Import)(self.handle, blob_ptr, blob.len()) };
        easy_check(rc)
    }

    // ─── Lifecycle ────────────────────────────────────────────────

    /// Zeroes the encryptor's PRF keys, MAC key, and seed components,
    /// and marks the encryptor as closed. Idempotent — multiple
    /// [`Encryptor::close`] calls return without error. Also wipes
    /// the per-encryptor output cache so the last ciphertext /
    /// plaintext does not linger in heap memory after the
    /// encryptor's working set has been zeroed on the Go side.
    pub fn close(&mut self) -> Result<(), ITBError> {
        // Wipe the cached output buffer regardless of close state —
        // repeated close calls keep the cache wiped without racing the
        // Go-side close.
        for b in self.out_buf.iter_mut() {
            *b = 0;
        }
        self.out_buf.clear();
        if self.closed || self.handle == 0 {
            // Idempotent — already closed.
            self.closed = true;
            return Ok(());
        }
        let lib = ffi::lib();
        let rc = unsafe { (lib.ITB_Easy_Close)(self.handle) };
        self.closed = true;
        // Close is documented as idempotent on the Go side; treat any
        // non-OK return after close as a bug.
        easy_check(rc)
    }

    /// Releases the underlying libitb handle slot. Wipes the
    /// per-encryptor output-buffer cache (so key material does not
    /// linger in heap memory) and then releases the libitb handle
    /// slot. Idempotent — `free` on an already-freed encryptor returns
    /// silently.
    pub fn free(mut self) -> Result<(), ITBError> {
        // Wipe the output buffer cache; the Go-side close already
        // happens implicitly on Free, so skip the close round-trip
        // here and call Free directly.
        for b in self.out_buf.iter_mut() {
            *b = 0;
        }
        self.out_buf.clear();
        let h = self.handle;
        self.handle = 0;
        self.closed = true;
        if h == 0 {
            return Ok(());
        }
        let lib = ffi::lib();
        let rc = unsafe { (lib.ITB_Easy_Free)(h) };
        easy_check(rc)
    }
}

impl Drop for Encryptor {
    fn drop(&mut self) {
        if self.handle != 0 {
            let lib = ffi::lib();
            // Best-effort release; errors during drop are swallowed
            // because there is no path to surface them (Drop has no
            // return value) and process-shutdown ordering can be
            // unpredictable.
            unsafe {
                let _ = (lib.ITB_Easy_Free)(self.handle);
            }
            self.handle = 0;
        }
        self.closed = true;
        // Wipe any residual output bytes left in the buffer cache.
        for b in self.out_buf.iter_mut() {
            *b = 0;
        }
        self.out_buf.clear();
    }
}

// --------------------------------------------------------------------
// Encryptor — Streaming AEAD methods.
// --------------------------------------------------------------------
//
// The Easy Mode Streaming AEAD surface mirrors the seed-based one:
// caller slices plaintext into chunks and the binding manages the
// 32-byte CSPRNG `stream_id` prefix, the per-chunk
// `cumulative_pixel_offset` running sum, and the terminating chunk's
// `final_flag = true`. The encryptor's bound primitive / key-bits /
// mode / MAC closure is reused across every chunk; per-call binding
// components are managed internally.
//
// Closed-state preflight applies — calling any auth-stream method on
// a closed / freed encryptor surfaces `STATUS_EASY_CLOSED`.

use std::io::{Read, Write};

const STREAM_ID_LEN: usize = 32;

fn enc_io_err(e: std::io::Error) -> ITBError {
    ITBError::with_message(ffi::STATUS_INTERNAL, format!("io: {e}"))
}

fn read_be16_at(p: &[u8]) -> usize {
    ((p[0] as usize) << 8) | (p[1] as usize)
}

/// Generates a CSPRNG-fresh 32-byte stream_id by piggybacking on
/// libitb's CSPRNG. Same shape as `streams::generate_stream_id` but
/// scoped here so the encryptor module does not pull `streams` as a
/// hard dependency.
fn easy_generate_stream_id() -> Result<[u8; STREAM_ID_LEN], ITBError> {
    let lib = ffi::lib();
    let cname = CString::new("blake3").unwrap();
    let comps: [u64; 8] = [1, 2, 3, 4, 5, 6, 7, 8];
    let mut handle: usize = 0;
    let rc = unsafe {
        (lib.ITB_NewSeedFromComponents)(
            cname.as_ptr(),
            comps.as_ptr(),
            comps.len() as c_int,
            std::ptr::null(),
            0,
            &mut handle,
        )
    };
    if rc != ffi::STATUS_OK {
        return Err(ITBError::with_message(rc, "stream_id seed alloc failed"));
    }
    let mut out = [0u8; STREAM_ID_LEN];
    let mut got: usize = 0;
    let rc = unsafe {
        (lib.ITB_GetSeedHashKey)(handle, out.as_mut_ptr(), STREAM_ID_LEN, &mut got)
    };
    let free_rc = unsafe { (lib.ITB_FreeSeed)(handle) };
    if rc != ffi::STATUS_OK {
        return Err(ITBError::with_message(rc, "stream_id hash-key fetch failed"));
    }
    if free_rc != ffi::STATUS_OK {
        return Err(ITBError::with_message(free_rc, "stream_id seed free failed"));
    }
    if got != STREAM_ID_LEN {
        return Err(ITBError::with_message(
            ffi::STATUS_INTERNAL,
            "stream_id CSPRNG draw returned wrong byte count",
        ));
    }
    Ok(out)
}

impl Encryptor {
    /// Per-chunk authenticated-stream encrypt under the encryptor's
    /// bound primitive / key-bits / mode / MAC closure. Plaintext may
    /// be empty when `final_flag = true`.
    ///
    /// Reuses the per-encryptor `out_buf` cache (Bonus 1 in
    /// .NEXTBIND.md §7.1) — same scope as the single-shot
    /// [`Encryptor::cipher_call`] path — so the streaming hot loop
    /// amortises the allocation across every chunk just like the
    /// single-shot Easy Mode path does. Returns
    /// `self.out_buf[..out_len].to_vec()` (the eager copy detaches
    /// the bytes from the cache so the next chunk's call may safely
    /// overwrite the cache).
    fn easy_emit_chunk_auth(
        &mut self,
        plaintext: &[u8],
        stream_id: &[u8; STREAM_ID_LEN],
        cum_pixels: u64,
        final_flag: bool,
    ) -> Result<Vec<u8>, ITBError> {
        let lib = ffi::lib();
        let f = lib.ITB_Easy_EncryptStreamAuth;
        let payload_len = plaintext.len();
        let in_ptr: *const c_void = if payload_len == 0 {
            std::ptr::null()
        } else {
            plaintext.as_ptr() as *const c_void
        };
        let ff: c_int = if final_flag { 1 } else { 0 };
        // 1.25× + 128 KiB headroom; see Encryptor::cipher_call.
        let cap = std::cmp::max(131072, payload_len.saturating_mul(5) / 4 + 131072);
        if self.out_buf.len() < cap {
            // Wipe previous contents before drop — Vec's default drop
            // deallocates without zeroing the heap region.
            for b in self.out_buf.iter_mut() { *b = 0; }
            self.out_buf = vec![0u8; cap];
        }
        let mut out_len: usize = 0;
        let mut rc = unsafe {
            f(
                self.handle,
                in_ptr,
                payload_len,
                stream_id.as_ptr(),
                cum_pixels,
                ff,
                self.out_buf.as_mut_ptr() as *mut c_void,
                self.out_buf.len(),
                &mut out_len,
            )
        };
        if rc == ffi::STATUS_BUFFER_TOO_SMALL {
            let need = out_len;
            for b in self.out_buf.iter_mut() { *b = 0; }
            self.out_buf = vec![0u8; need];
            rc = unsafe {
                f(
                    self.handle,
                    in_ptr,
                    payload_len,
                    stream_id.as_ptr(),
                    cum_pixels,
                    ff,
                    self.out_buf.as_mut_ptr() as *mut c_void,
                    self.out_buf.len(),
                    &mut out_len,
                )
            };
        }
        if rc != ffi::STATUS_OK {
            return Err(easy_error(rc));
        }
        Ok(self.out_buf[..out_len].to_vec())
    }

    /// Per-chunk authenticated-stream decrypt. Returns
    /// `(plaintext, final_flag)` on a verified chunk; surfaces
    /// `STATUS_MAC_FAILURE` on tampered transcript.
    ///
    /// Reuses the per-encryptor `out_buf` cache (Bonus 1 in
    /// .NEXTBIND.md §7.1) — see [`Encryptor::easy_emit_chunk_auth`]
    /// for the rationale.
    fn easy_consume_chunk_auth(
        &mut self,
        ciphertext: &[u8],
        stream_id: &[u8; STREAM_ID_LEN],
        cum_pixels: u64,
    ) -> Result<(Vec<u8>, bool), ITBError> {
        let lib = ffi::lib();
        let f = lib.ITB_Easy_DecryptStreamAuth;
        let payload_len = ciphertext.len();
        let in_ptr: *const c_void = if payload_len == 0 {
            std::ptr::null()
        } else {
            ciphertext.as_ptr() as *const c_void
        };
        // 1.25× + 128 KiB headroom; see Encryptor::cipher_call.
        let cap = std::cmp::max(131072, payload_len.saturating_mul(5) / 4 + 131072);
        if self.out_buf.len() < cap {
            for b in self.out_buf.iter_mut() { *b = 0; }
            self.out_buf = vec![0u8; cap];
        }
        let mut out_len: usize = 0;
        let mut ff: c_int = 0;
        let mut rc = unsafe {
            f(
                self.handle,
                in_ptr,
                payload_len,
                stream_id.as_ptr(),
                cum_pixels,
                self.out_buf.as_mut_ptr() as *mut c_void,
                self.out_buf.len(),
                &mut out_len,
                &mut ff,
            )
        };
        if rc == ffi::STATUS_BUFFER_TOO_SMALL {
            let need = out_len;
            for b in self.out_buf.iter_mut() { *b = 0; }
            self.out_buf = vec![0u8; need];
            rc = unsafe {
                f(
                    self.handle,
                    in_ptr,
                    payload_len,
                    stream_id.as_ptr(),
                    cum_pixels,
                    self.out_buf.as_mut_ptr() as *mut c_void,
                    self.out_buf.len(),
                    &mut out_len,
                    &mut ff,
                )
            };
        }
        if rc != ffi::STATUS_OK {
            return Err(easy_error(rc));
        }
        Ok((self.out_buf[..out_len].to_vec(), ff != 0))
    }

    /// Reads plaintext from `fin` until EOF, encrypts in chunks of
    /// `chunk_size` under the encryptor's bound config + MAC, and
    /// writes the 32-byte stream prefix followed by concatenated
    /// authenticated chunks to `fout`. `chunk_size` must be positive.
    pub fn encrypt_stream_auth<R: Read, W: Write>(
        &mut self,
        mut fin: R,
        mut fout: W,
        chunk_size: usize,
    ) -> Result<(), ITBError> {
        self.check_open()?;
        if chunk_size == 0 {
            return Err(ITBError::with_message(
                ffi::STATUS_BAD_INPUT,
                "chunk_size must be positive",
            ));
        }
        let stream_id = easy_generate_stream_id()?;
        let header_size = self.header_size()? as usize;
        fout.write_all(&stream_id).map_err(enc_io_err)?;

        let mut cum: u64 = 0;
        let mut buf: Vec<u8> = Vec::with_capacity(chunk_size + 1);
        let mut read_buf = vec![0u8; chunk_size];
        let mut eof = false;
        // Deferred-final pattern: drain reads until buf > chunk_size,
        // then emit one non-terminal chunk. On EOF, emit residual as
        // terminal (possibly empty).
        while !eof {
            // Fill until buf has at least chunk_size + 1 bytes (the +1
            // byte signals more chunks follow) or EOF.
            while buf.len() <= chunk_size && !eof {
                let n = fin.read(&mut read_buf).map_err(enc_io_err)?;
                if n == 0 {
                    eof = true;
                    break;
                }
                buf.extend_from_slice(&read_buf[..n]);
            }
            if buf.len() > chunk_size {
                // Emit one full chunk as non-terminal.
                let chunk: Vec<u8> = buf.drain(..chunk_size).collect();
                let ct = self.easy_emit_chunk_auth(&chunk, &stream_id, cum, false)?;
                let mut chunk = chunk;
                for b in chunk.iter_mut() { *b = 0; }
                if ct.len() >= header_size {
                    let w = read_be16_at(&ct[header_size - 4..header_size - 2]);
                    let h = read_be16_at(&ct[header_size - 2..header_size]);
                    cum += (w as u64) * (h as u64);
                }
                fout.write_all(&ct).map_err(enc_io_err)?;
            }
        }
        // Residual (possibly empty) is the terminating chunk.
        let chunk: Vec<u8> = std::mem::take(&mut buf);
        let ct = self.easy_emit_chunk_auth(&chunk, &stream_id, cum, true)?;
        let mut chunk = chunk;
        for b in chunk.iter_mut() { *b = 0; }
        fout.write_all(&ct).map_err(enc_io_err)?;
        for b in read_buf.iter_mut() { *b = 0; }
        Ok(())
    }

    /// Reads an authenticated stream transcript from `fin` and writes
    /// the recovered plaintext to `fout`. Surfaces
    /// `STATUS_STREAM_TRUNCATED` when input exhausts without a
    /// terminating chunk, `STATUS_STREAM_AFTER_FINAL` when extra
    /// bytes follow a terminator, and `STATUS_MAC_FAILURE` on
    /// tampered transcript. `chunk_size` controls the read-buffer
    /// granularity and must be positive.
    pub fn decrypt_stream_auth<R: Read, W: Write>(
        &mut self,
        mut fin: R,
        mut fout: W,
        chunk_size: usize,
    ) -> Result<(), ITBError> {
        self.check_open()?;
        if chunk_size == 0 {
            return Err(ITBError::with_message(
                ffi::STATUS_BAD_INPUT,
                "chunk_size must be positive",
            ));
        }
        let header_size = self.header_size()? as usize;
        let mut accum: Vec<u8> = Vec::new();
        let mut read_buf = vec![0u8; chunk_size];
        let mut stream_id = [0u8; STREAM_ID_LEN];
        let mut sid_have: usize = 0;
        let mut cum: u64 = 0;
        let mut seen_final = false;

        loop {
            let n = fin.read(&mut read_buf).map_err(enc_io_err)?;
            if n == 0 {
                break;
            }
            let mut off = 0usize;
            if sid_have < STREAM_ID_LEN {
                let need = STREAM_ID_LEN - sid_have;
                let take = std::cmp::min(need, n);
                stream_id[sid_have..sid_have + take]
                    .copy_from_slice(&read_buf[..take]);
                sid_have += take;
                off = take;
            }
            if off < n {
                accum.extend_from_slice(&read_buf[off..n]);
            }
            if sid_have == STREAM_ID_LEN {
                // Drain whole chunks.
                loop {
                    if seen_final {
                        if !accum.is_empty() {
                            for b in read_buf.iter_mut() { *b = 0; }
                            return Err(ITBError::with_message(
                                ffi::STATUS_STREAM_AFTER_FINAL,
                                "auth stream: trailing bytes after terminator",
                            ));
                        }
                        break;
                    }
                    if accum.len() < header_size {
                        break;
                    }
                    let chunk_len = self.parse_chunk_len(&accum[..header_size])?;
                    if accum.len() < chunk_len {
                        break;
                    }
                    let w = read_be16_at(&accum[header_size - 4..header_size - 2]);
                    let h = read_be16_at(&accum[header_size - 2..header_size]);
                    let pixels = (w as u64) * (h as u64);
                    let chunk: Vec<u8> = accum.drain(..chunk_len).collect();
                    let (mut pt, ff) =
                        self.easy_consume_chunk_auth(&chunk, &stream_id, cum)?;
                    fout.write_all(&pt).map_err(enc_io_err)?;
                    for b in pt.iter_mut() { *b = 0; }
                    cum += pixels;
                    if ff {
                        seen_final = true;
                    }
                }
            }
        }
        // EOF: drain remainder.
        if sid_have < STREAM_ID_LEN {
            for b in read_buf.iter_mut() { *b = 0; }
            return Err(ITBError::with_message(
                ffi::STATUS_BAD_INPUT,
                "auth stream: 32-byte stream prefix incomplete",
            ));
        }
        loop {
            if seen_final {
                if !accum.is_empty() {
                    for b in read_buf.iter_mut() { *b = 0; }
                    return Err(ITBError::with_message(
                        ffi::STATUS_STREAM_AFTER_FINAL,
                        "auth stream: trailing bytes after terminator",
                    ));
                }
                break;
            }
            if accum.len() < header_size {
                break;
            }
            let chunk_len = self.parse_chunk_len(&accum[..header_size])?;
            if accum.len() < chunk_len {
                break;
            }
            let w = read_be16_at(&accum[header_size - 4..header_size - 2]);
            let h = read_be16_at(&accum[header_size - 2..header_size]);
            let pixels = (w as u64) * (h as u64);
            let chunk: Vec<u8> = accum.drain(..chunk_len).collect();
            let (mut pt, ff) =
                self.easy_consume_chunk_auth(&chunk, &stream_id, cum)?;
            fout.write_all(&pt).map_err(enc_io_err)?;
            for b in pt.iter_mut() { *b = 0; }
            cum += pixels;
            if ff {
                seen_final = true;
            }
        }
        for b in read_buf.iter_mut() { *b = 0; }
        if !seen_final {
            return Err(ITBError::with_message(
                ffi::STATUS_STREAM_TRUNCATED,
                "auth stream: terminator never observed",
            ));
        }
        Ok(())
    }
}
