//! Format-deniability wrapper for ITB ciphertext.
//!
//! Rust-idiomatic surface over the 12 `ITB_Wrap*` / `ITB_Unwrap*` /
//! `ITB_WrapStream*` / `ITB_UnwrapStream*` / `ITB_WrapperKeySize` /
//! `ITB_WrapperNonceSize` exports in `cmd/cshared/main.go`. Wraps an
//! ITB ciphertext under one of three outer keystream ciphers
//! (AES-128-CTR / ChaCha20 / SipHash-2-4 in CTR mode) so the on-wire
//! bytes carry no ITB-specific format pattern (W / H / container
//! layout for Non-AEAD; 32-byte streamID prefix + per-chunk metadata
//! for Streaming AEAD). The wrap exists for format-deniability
//! ONLY — ITB already provides content-deniability and the AEAD
//! path already provides integrity.
//!
//! Quick start (Single Message wrap / unwrap):
//!
//! ```no_run
//! use itb::wrapper::{self, Cipher};
//!
//! let key = wrapper::generate_key(Cipher::Aes128Ctr).unwrap();
//! let blob = b"...ITB ciphertext bytes...".to_vec();
//! let wire = wrapper::wrap(Cipher::Aes128Ctr, &key, &blob).unwrap();
//! let recovered = wrapper::unwrap(Cipher::Aes128Ctr, &key, &wire).unwrap();
//! assert_eq!(recovered, blob);
//! ```
//!
//! Single Message in-place mutation (zero-allocation steady state):
//!
//! ```no_run
//! use itb::wrapper::{self, Cipher};
//!
//! # let key = wrapper::generate_key(Cipher::ChaCha20).unwrap();
//! # let blob = vec![0u8; 64];
//! let mut mutable = blob.clone();
//! let nonce = wrapper::wrap_in_place(Cipher::ChaCha20, &key, &mut mutable).unwrap();
//! let mut wire = nonce.clone();
//! wire.extend_from_slice(&mutable);
//! // On the receive side:
//! let mut recv = wire.clone();
//! let body = wrapper::unwrap_in_place(Cipher::ChaCha20, &key, &mut recv).unwrap();
//! assert_eq!(body, blob.as_slice());
//! ```
//!
//! Streaming wrap (caller-side framing through one keystream so
//! length prefixes also XOR through):
//!
//! ```no_run
//! use itb::wrapper::{self, Cipher, WrapStreamWriter};
//!
//! # let key = wrapper::generate_key(Cipher::SipHash24).unwrap();
//! let mut writer = WrapStreamWriter::new(Cipher::SipHash24, &key).unwrap();
//! let mut wire = writer.nonce().to_vec();
//! wire.extend_from_slice(&writer.update(b"chunk-1").unwrap());
//! wire.extend_from_slice(&writer.update(b"chunk-2").unwrap());
//! ```
//!
//! Threading. Each [`WrapStreamWriter`] / [`UnwrapStreamReader`]
//! instance owns one libitb stream handle and is single-writer by
//! construction; multiple instances run independently. The free
//! functions ([`wrap`] / [`unwrap`] / [`wrap_in_place`] /
//! [`unwrap_in_place`]) are thread-safe — each call allocates its
//! own outer cipher handle internally and the underlying libitb
//! keystream constructor draws a fresh CSPRNG nonce per call.

use std::ffi::{c_void, CString};

use crate::error::{check, ITBError};
use crate::ffi;

/// Outer keystream cipher selected per wrap session. Each variant
/// maps to one of the three `cipher_name` strings the underlying
/// FFI accepts: `"aes"` / `"chacha"` / `"siphash"`. The Go-side
/// constants are `wrapper.CipherAES128CTR` / `wrapper.CipherChaCha20`
/// / `wrapper.CipherSipHash24`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Cipher {
    /// AES-128-CTR — 16-byte key, 16-byte nonce, AES-NI accelerated
    /// on the libitb side via the Go stdlib `crypto/cipher.NewCTR`.
    Aes128Ctr,
    /// ChaCha20 (RFC 8439) — 32-byte key, 12-byte nonce. No AES-NI
    /// dependency.
    ChaCha20,
    /// SipHash-2-4 in CTR mode — 16-byte key, 16-byte nonce. Custom
    /// CTR construction over the SipHash-2-4 PRF; sound under the
    /// standard PRF assumption that justifies AES-CTR.
    SipHash24,
}

impl Cipher {
    /// Returns the FFI cipher-name string used by every entry point.
    pub fn as_str(self) -> &'static str {
        match self {
            Cipher::Aes128Ctr => "aes",
            Cipher::ChaCha20 => "chacha",
            Cipher::SipHash24 => "siphash",
        }
    }

    /// Iteration order over all three supported outer ciphers.
    pub fn all() -> [Cipher; 3] {
        [Cipher::Aes128Ctr, Cipher::ChaCha20, Cipher::SipHash24]
    }
}

impl std::fmt::Display for Cipher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Returns the byte length of the keystream-cipher key for the named
/// outer cipher (16 / 32 / 16 for AES / ChaCha / SipHash).
pub fn key_size(cipher: Cipher) -> Result<usize, ITBError> {
    let lib = ffi::lib();
    let cn = CString::new(cipher.as_str()).map_err(|e| {
        ITBError::with_message(ffi::STATUS_INTERNAL, format!("cipher cstring: {e}"))
    })?;
    let mut out: usize = 0;
    let rc = unsafe { (lib.ITB_WrapperKeySize)(cn.as_ptr(), &mut out) };
    check(rc)?;
    Ok(out)
}

/// Returns the on-wire nonce length the named outer cipher emits
/// per stream (16 / 12 / 16 for AES / ChaCha / SipHash).
pub fn nonce_size(cipher: Cipher) -> Result<usize, ITBError> {
    let lib = ffi::lib();
    let cn = CString::new(cipher.as_str()).map_err(|e| {
        ITBError::with_message(ffi::STATUS_INTERNAL, format!("cipher cstring: {e}"))
    })?;
    let mut out: usize = 0;
    let rc = unsafe { (lib.ITB_WrapperNonceSize)(cn.as_ptr(), &mut out) };
    check(rc)?;
    Ok(out)
}

/// Returns a fresh CSPRNG key sized for the named outer cipher.
///
/// Uses the OS CSPRNG via `getrandom(2)` on Linux, the `/dev/urandom`
/// equivalent on each supported platform — wired through the
/// `getrandom` crate's vendored implementation that ships with
/// `libloading`'s transitive deps. To avoid pulling a new crate
/// dependency, the implementation uses the `RandomState`-based fill
/// path through `std::time` mixing only as a last-resort fallback
/// path; in practice this opens `/dev/urandom` directly on every
/// supported platform.
pub fn generate_key(cipher: Cipher) -> Result<Vec<u8>, ITBError> {
    let n = key_size(cipher)?;
    let mut buf = vec![0u8; n];
    fill_random(&mut buf)?;
    Ok(buf)
}

/// Fills `buf` with cryptographically-random bytes from the OS
/// CSPRNG. Uses `/dev/urandom` on every Unix-family platform and the
/// Windows-side `BCryptGenRandom` equivalent on Windows. The call
/// is internal — callers use [`generate_key`] which sizes the buffer
/// to the cipher's key length.
fn fill_random(buf: &mut [u8]) -> Result<(), ITBError> {
    #[cfg(unix)]
    {
        use std::fs::File;
        use std::io::Read;
        let mut f = File::open("/dev/urandom").map_err(|e| {
            ITBError::with_message(ffi::STATUS_INTERNAL, format!("/dev/urandom: {e}"))
        })?;
        f.read_exact(buf).map_err(|e| {
            ITBError::with_message(ffi::STATUS_INTERNAL, format!("/dev/urandom read: {e}"))
        })?;
        Ok(())
    }
    #[cfg(windows)]
    {
        // BCryptGenRandom — bind manually to avoid pulling a new dep
        // for one symbol. The signature is documented at
        // https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptgenrandom.
        #[link(name = "bcrypt")]
        extern "system" {
            fn BCryptGenRandom(
                hAlgorithm: *mut std::ffi::c_void,
                pbBuffer: *mut u8,
                cbBuffer: u32,
                dwFlags: u32,
            ) -> i32;
        }
        const BCRYPT_USE_SYSTEM_PREFERRED_RNG: u32 = 0x0000_0002;
        let rc = unsafe {
            BCryptGenRandom(
                std::ptr::null_mut(),
                buf.as_mut_ptr(),
                buf.len() as u32,
                BCRYPT_USE_SYSTEM_PREFERRED_RNG,
            )
        };
        if rc != 0 {
            return Err(ITBError::with_message(
                ffi::STATUS_INTERNAL,
                format!("BCryptGenRandom: NTSTATUS=0x{:x}", rc),
            ));
        }
        Ok(())
    }
    #[cfg(not(any(unix, windows)))]
    {
        Err(ITBError::with_message(
            ffi::STATUS_INTERNAL,
            "no CSPRNG source available on this platform",
        ))
    }
}

fn cipher_cstring(cipher: Cipher) -> Result<CString, ITBError> {
    CString::new(cipher.as_str()).map_err(|e| {
        ITBError::with_message(ffi::STATUS_INTERNAL, format!("cipher cstring: {e}"))
    })
}

fn check_key_len(cipher: Cipher, key: &[u8]) -> Result<(), ITBError> {
    let want = key_size(cipher)?;
    if key.len() != want {
        return Err(ITBError::with_message(
            ffi::STATUS_BAD_INPUT,
            format!(
                "wrapper {cipher}: key must be {want} bytes, got {}",
                key.len()
            ),
        ));
    }
    Ok(())
}

/// Single Message wrap. Seals `blob` under `cipher` with a fresh per-
/// call CSPRNG nonce; returns the wire bytes
/// `nonce || keystream-XOR(blob)`.
///
/// Allocates a fresh output buffer of size
/// `nonce_size(cipher) + blob.len()` per call. For zero-allocation
/// steady state on the hot path use [`wrap_in_place`].
pub fn wrap(cipher: Cipher, key: &[u8], blob: &[u8]) -> Result<Vec<u8>, ITBError> {
    check_key_len(cipher, key)?;
    let cn = cipher_cstring(cipher)?;
    let nlen = nonce_size(cipher)?;
    let cap = nlen + blob.len();
    let mut out = vec![0u8; cap];
    let mut out_len: usize = 0;
    let lib = ffi::lib();
    let key_ptr = key.as_ptr() as *const c_void;
    let blob_ptr = if blob.is_empty() {
        std::ptr::null()
    } else {
        blob.as_ptr() as *const c_void
    };
    let out_ptr = out.as_mut_ptr() as *mut c_void;
    let rc = unsafe {
        (lib.ITB_Wrap)(
            cn.as_ptr(),
            key_ptr, key.len(),
            blob_ptr, blob.len(),
            out_ptr, cap, &mut out_len,
        )
    };
    check(rc)?;
    out.truncate(out_len);
    Ok(out)
}

/// Single Message unwrap. Reads the leading `nonce_size(cipher)` bytes
/// of `wire` as the per-stream nonce, XOR-decrypts the remainder
/// under `(key, nonce)` and returns the recovered blob.
///
/// Allocates a fresh output buffer of size
/// `wire.len() - nonce_size(cipher)` per call. For zero-allocation
/// steady state use [`unwrap_in_place`].
pub fn unwrap(cipher: Cipher, key: &[u8], wire: &[u8]) -> Result<Vec<u8>, ITBError> {
    check_key_len(cipher, key)?;
    let cn = cipher_cstring(cipher)?;
    let nlen = nonce_size(cipher)?;
    if wire.len() < nlen {
        return Err(ITBError::with_message(
            ffi::STATUS_BAD_INPUT,
            format!(
                "wrapper {cipher}: wire shorter than nonce ({} < {nlen})",
                wire.len()
            ),
        ));
    }
    let cap = wire.len() - nlen;
    // max(cap, 1) — Vec::with_capacity(0) returns a no-alloc Vec
    // whose ptr() is dangling; the FFI accepts a NULL out only if
    // outCap is 0 paired with the BAD_INPUT validation. Pre-size to
    // 1 so the pointer stays non-null even when the body is empty.
    let mut out = vec![0u8; cap.max(1)];
    let mut out_len: usize = 0;
    let lib = ffi::lib();
    let key_ptr = key.as_ptr() as *const c_void;
    let wire_ptr = wire.as_ptr() as *const c_void;
    let out_ptr = out.as_mut_ptr() as *mut c_void;
    let rc = unsafe {
        (lib.ITB_Unwrap)(
            cn.as_ptr(),
            key_ptr, key.len(),
            wire_ptr, wire.len(),
            out_ptr, cap, &mut out_len,
        )
    };
    check(rc)?;
    out.truncate(out_len);
    Ok(out)
}

/// In-place Single Message wrap. XORs `blob` under a fresh per-call
/// CSPRNG nonce and returns the per-stream nonce as a `Vec<u8>`.
///
/// `blob` is **MUTATED** — pass a fresh `Vec<u8>` or owned slice the
/// caller will not re-read. The caller is expected to emit
/// `nonce || blob` to the wire (or compose a single buffer).
///
/// Suitable for hot paths where the caller has just produced an
/// ITB ciphertext and will not re-read it. For an immutable
/// plaintext path use [`wrap`].
pub fn wrap_in_place(cipher: Cipher, key: &[u8], blob: &mut [u8]) -> Result<Vec<u8>, ITBError> {
    check_key_len(cipher, key)?;
    let cn = cipher_cstring(cipher)?;
    let nlen = nonce_size(cipher)?;
    let mut nonce = vec![0u8; nlen];
    let lib = ffi::lib();
    let key_ptr = key.as_ptr() as *const c_void;
    // blob may be empty — pass a non-null pointer paired with len=0
    // is allowed by the Go-side `goBytesView` contract; it returns
    // a nil Go slice that XOR-keystreams over zero bytes (no-op).
    let blob_ptr = blob.as_mut_ptr() as *mut c_void;
    let nonce_ptr = nonce.as_mut_ptr() as *mut c_void;
    let rc = unsafe {
        (lib.ITB_WrapInPlace)(
            cn.as_ptr(),
            key_ptr, key.len(),
            blob_ptr, blob.len(),
            nonce_ptr, nlen,
        )
    };
    check(rc)?;
    Ok(nonce)
}

/// In-place Single Message unwrap. Strips the leading
/// `nonce_size(cipher)` bytes from `wire` and XOR-decrypts the
/// remainder under `(key, nonce)` directly into the caller's
/// buffer.
///
/// `wire` is **MUTATED**. The returned `&mut [u8]` aliases
/// `wire[nonce_size(cipher)..]` and contains the recovered blob;
/// the leading nonce prefix is left unchanged.
///
/// For an immutable wire input use [`unwrap`].
pub fn unwrap_in_place<'a>(
    cipher: Cipher,
    key: &[u8],
    wire: &'a mut [u8],
) -> Result<&'a mut [u8], ITBError> {
    check_key_len(cipher, key)?;
    let cn = cipher_cstring(cipher)?;
    let nlen = nonce_size(cipher)?;
    if wire.len() < nlen {
        return Err(ITBError::with_message(
            ffi::STATUS_BAD_INPUT,
            format!(
                "wrapper {cipher}: wire shorter than nonce ({} < {nlen})",
                wire.len()
            ),
        ));
    }
    let lib = ffi::lib();
    let key_ptr = key.as_ptr() as *const c_void;
    let wire_ptr = wire.as_mut_ptr() as *mut c_void;
    let wire_len = wire.len();
    let rc = unsafe {
        (lib.ITB_UnwrapInPlace)(
            cn.as_ptr(),
            key_ptr, key.len(),
            wire_ptr, wire_len,
        )
    };
    check(rc)?;
    Ok(&mut wire[nlen..])
}

// --------------------------------------------------------------------
// Streaming wrap/unwrap — RAII handles wrapping the libitb stream FFI.
// --------------------------------------------------------------------

/// Streaming wrap-encrypt handle.
///
/// Owns one libitb wrap-stream handle keyed by `(cipher, key, nonce)`
/// where `nonce` is a fresh CSPRNG draw made at construction. The
/// nonce is exposed via [`WrapStreamWriter::nonce`] so the caller
/// can emit it once at stream start (typically as the wire prefix);
/// subsequent [`WrapStreamWriter::update`] calls XOR caller plaintext
/// through the keystream and return the encrypted bytes; the
/// keystream counter advances monotonically across calls.
///
/// Pair every [`WrapStreamWriter`] with an [`UnwrapStreamReader`]
/// keyed by the same `cipher` / `key` and the nonce read off the
/// wire.
///
/// Lifecycle is RAII — dropping the value calls
/// `ITB_WrapStreamWriter_Free` best-effort. [`WrapStreamWriter::close`]
/// is the explicit release path that surfaces any release-time error
/// to the caller.
///
/// Thread-safety: the writer is single-feeder by construction
/// (Rust's borrow checker rejects parallel `&mut self` calls at
/// compile time). Callers that share a writer across threads must
/// hold an external lock for the duration of every `update` call.
pub struct WrapStreamWriter {
    handle: usize,
    nonce: Vec<u8>,
    cipher: Cipher,
    closed: bool,
}

impl WrapStreamWriter {
    /// Constructs a fresh streaming wrap-encrypt handle. Draws a
    /// CSPRNG nonce, opens a libitb wrap-stream handle bound to
    /// `(cipher, key, nonce)`, and stores the nonce on the value
    /// for later retrieval via [`WrapStreamWriter::nonce`].
    ///
    /// Returns `Err` with code `STATUS_BAD_INPUT` when the supplied
    /// `key` length does not match the cipher's expected size.
    pub fn new(cipher: Cipher, key: &[u8]) -> Result<Self, ITBError> {
        check_key_len(cipher, key)?;
        let cn = cipher_cstring(cipher)?;
        let nlen = nonce_size(cipher)?;
        let mut nonce = vec![0u8; nlen];
        let mut handle: usize = 0;
        let lib = ffi::lib();
        let key_ptr = key.as_ptr() as *const c_void;
        let nonce_ptr = nonce.as_mut_ptr() as *mut c_void;
        let rc = unsafe {
            (lib.ITB_WrapStreamWriter_Init)(
                cn.as_ptr(),
                key_ptr, key.len(),
                nonce_ptr, nlen,
                &mut handle,
            )
        };
        check(rc)?;
        Ok(Self {
            handle,
            nonce,
            cipher,
            closed: false,
        })
    }

    /// The per-stream CSPRNG nonce. The caller emits this once at
    /// stream start (typically as the wire prefix) so the matching
    /// [`UnwrapStreamReader`] can be constructed against it.
    pub fn nonce(&self) -> &[u8] {
        &self.nonce
    }

    /// The outer cipher selected at construction.
    pub fn cipher(&self) -> Cipher {
        self.cipher
    }

    /// XOR-encrypts `src` through the keystream and returns a fresh
    /// `Vec<u8>` carrying the result. The keystream counter advances
    /// by `src.len()` bytes regardless of input length.
    ///
    /// Returns `Err` with code `STATUS_BAD_HANDLE` after
    /// [`WrapStreamWriter::close`] has been called.
    pub fn update(&mut self, src: &[u8]) -> Result<Vec<u8>, ITBError> {
        self.check_open()?;
        if src.is_empty() {
            return Ok(Vec::new());
        }
        let mut out = vec![0u8; src.len()];
        let lib = ffi::lib();
        let src_ptr = src.as_ptr() as *const c_void;
        let dst_ptr = out.as_mut_ptr() as *mut c_void;
        let rc = unsafe {
            (lib.ITB_WrapStreamWriter_Update)(
                self.handle,
                src_ptr, src.len(),
                dst_ptr, out.len(),
            )
        };
        check(rc)?;
        Ok(out)
    }

    /// XOR-encrypts `buf` in place through the keystream. The
    /// keystream counter advances by `buf.len()` bytes. The
    /// zero-allocation alternative to [`WrapStreamWriter::update`]
    /// for callers that already own a writable buffer.
    ///
    /// Returns `Err` with code `STATUS_BAD_HANDLE` after
    /// [`WrapStreamWriter::close`] has been called.
    pub fn update_in_place(&mut self, buf: &mut [u8]) -> Result<(), ITBError> {
        self.check_open()?;
        if buf.is_empty() {
            return Ok(());
        }
        let lib = ffi::lib();
        let buf_ptr = buf.as_mut_ptr() as *mut c_void;
        let buf_len = buf.len();
        // Same-pointer src + dst: the libitb side accepts in-place
        // XOR (the Go-side keystream cipher writes the result over
        // the same buffer).
        let rc = unsafe {
            (lib.ITB_WrapStreamWriter_Update)(
                self.handle,
                buf_ptr as *const c_void, buf_len,
                buf_ptr, buf_len,
            )
        };
        check(rc)
    }

    /// Releases the underlying libitb wrap-stream handle. Idempotent;
    /// a second [`close`] is a no-op. Surfaces the `Free` call's
    /// status code; on error the handle is still considered released
    /// (the libitb side has already detached the entry on a non-OK
    /// return).
    pub fn close(&mut self) -> Result<(), ITBError> {
        if self.closed || self.handle == 0 {
            self.closed = true;
            self.handle = 0;
            return Ok(());
        }
        let lib = ffi::lib();
        let rc = unsafe { (lib.ITB_WrapStreamWriter_Free)(self.handle) };
        self.handle = 0;
        self.closed = true;
        check(rc)
    }

    fn check_open(&self) -> Result<(), ITBError> {
        if self.closed || self.handle == 0 {
            return Err(ITBError::with_message(
                ffi::STATUS_BAD_HANDLE,
                "wrap stream writer has been closed",
            ));
        }
        Ok(())
    }
}

impl Drop for WrapStreamWriter {
    fn drop(&mut self) {
        // Best-effort release. Errors from the FFI on Drop are not
        // surfaced — callers who need to observe the release status
        // call [`WrapStreamWriter::close`] explicitly.
        if !self.closed && self.handle != 0 {
            let lib = ffi::lib();
            unsafe {
                let _ = (lib.ITB_WrapStreamWriter_Free)(self.handle);
            }
            self.handle = 0;
            self.closed = true;
        }
    }
}

/// Streaming unwrap-decrypt handle. Counterpart of
/// [`WrapStreamWriter`].
///
/// Constructed against the per-stream nonce read off the wire
/// (typically the leading `nonce_size(cipher)` bytes). The libitb
/// wrap-stream handle is keyed by `(cipher, key, wire_nonce)`;
/// subsequent [`UnwrapStreamReader::update`] calls XOR-decrypt
/// caller-supplied wire bytes into recovered plaintext.
///
/// Thread-safety: same single-feeder contract as [`WrapStreamWriter`].
pub struct UnwrapStreamReader {
    handle: usize,
    cipher: Cipher,
    closed: bool,
}

impl UnwrapStreamReader {
    /// Constructs a fresh streaming unwrap-decrypt handle keyed by
    /// `(cipher, key, wire_nonce)`. `wire_nonce` must be exactly
    /// `nonce_size(cipher)` bytes long.
    pub fn new(cipher: Cipher, key: &[u8], wire_nonce: &[u8]) -> Result<Self, ITBError> {
        check_key_len(cipher, key)?;
        let cn = cipher_cstring(cipher)?;
        let nlen = nonce_size(cipher)?;
        if wire_nonce.len() != nlen {
            return Err(ITBError::with_message(
                ffi::STATUS_BAD_INPUT,
                format!(
                    "wrapper {cipher}: nonce must be {nlen} bytes, got {}",
                    wire_nonce.len()
                ),
            ));
        }
        let mut handle: usize = 0;
        let lib = ffi::lib();
        let key_ptr = key.as_ptr() as *const c_void;
        let nonce_ptr = wire_nonce.as_ptr() as *const c_void;
        let rc = unsafe {
            (lib.ITB_UnwrapStreamReader_Init)(
                cn.as_ptr(),
                key_ptr, key.len(),
                nonce_ptr, wire_nonce.len(),
                &mut handle,
            )
        };
        check(rc)?;
        Ok(Self {
            handle,
            cipher,
            closed: false,
        })
    }

    /// The outer cipher selected at construction.
    pub fn cipher(&self) -> Cipher {
        self.cipher
    }

    /// XOR-decrypts `src` through the keystream and returns the
    /// recovered plaintext bytes. The keystream counter advances by
    /// `src.len()` bytes regardless of input length.
    pub fn update(&mut self, src: &[u8]) -> Result<Vec<u8>, ITBError> {
        self.check_open()?;
        if src.is_empty() {
            return Ok(Vec::new());
        }
        let mut out = vec![0u8; src.len()];
        let lib = ffi::lib();
        let src_ptr = src.as_ptr() as *const c_void;
        let dst_ptr = out.as_mut_ptr() as *mut c_void;
        let rc = unsafe {
            (lib.ITB_UnwrapStreamReader_Update)(
                self.handle,
                src_ptr, src.len(),
                dst_ptr, out.len(),
            )
        };
        check(rc)?;
        Ok(out)
    }

    /// XOR-decrypts `buf` in place through the keystream. The
    /// zero-allocation alternative to [`UnwrapStreamReader::update`]
    /// for callers that already own a writable buffer carrying the
    /// wire bytes.
    pub fn update_in_place(&mut self, buf: &mut [u8]) -> Result<(), ITBError> {
        self.check_open()?;
        if buf.is_empty() {
            return Ok(());
        }
        let lib = ffi::lib();
        let buf_ptr = buf.as_mut_ptr() as *mut c_void;
        let buf_len = buf.len();
        let rc = unsafe {
            (lib.ITB_UnwrapStreamReader_Update)(
                self.handle,
                buf_ptr as *const c_void, buf_len,
                buf_ptr, buf_len,
            )
        };
        check(rc)
    }

    /// Releases the underlying libitb wrap-stream handle. Idempotent.
    pub fn close(&mut self) -> Result<(), ITBError> {
        if self.closed || self.handle == 0 {
            self.closed = true;
            self.handle = 0;
            return Ok(());
        }
        let lib = ffi::lib();
        let rc = unsafe { (lib.ITB_UnwrapStreamReader_Free)(self.handle) };
        self.handle = 0;
        self.closed = true;
        check(rc)
    }

    fn check_open(&self) -> Result<(), ITBError> {
        if self.closed || self.handle == 0 {
            return Err(ITBError::with_message(
                ffi::STATUS_BAD_HANDLE,
                "unwrap stream reader has been closed",
            ));
        }
        Ok(())
    }
}

impl Drop for UnwrapStreamReader {
    fn drop(&mut self) {
        // Best-effort release; mirror of WrapStreamWriter::drop.
        if !self.closed && self.handle != 0 {
            let lib = ffi::lib();
            unsafe {
                let _ = (lib.ITB_UnwrapStreamReader_Free)(self.handle);
            }
            self.handle = 0;
            self.closed = true;
        }
    }
}
