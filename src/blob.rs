//! Native-Blob wrapper over the libitb C ABI.
//!
//! Mirrors the github.com/everanium/itb Blob128 / Blob256 / Blob512 Go
//! types: a width-specific container that packs the low-level
//! encryptor material (per-seed hash key + components + optional
//! dedicated lockSeed + optional MAC key + name) plus the captured
//! process-wide configuration into one self-describing JSON blob.
//! Intended for the low-level encrypt / decrypt path where each seed
//! slot may carry a different primitive — the high-level
//! [`crate::Encryptor`] wraps a narrower one-primitive-per-encryptor
//! surface.
//!
//! Quick start (sender, Single Ouroboros + Areion-SoEM-512 + KMAC256):
//!
//! ```no_run
//! use itb::{Seed, Blob512, MAC, encrypt_auth};
//!
//! let mac_key = [0x11u8; 32];
//! let ns = Seed::new("areion512", 2048).unwrap();
//! let ds = Seed::new("areion512", 2048).unwrap();
//! let ss = Seed::new("areion512", 2048).unwrap();
//! let mac = MAC::new("kmac256", &mac_key).unwrap();
//! let ct = encrypt_auth(&ns, &ds, &ss, &mac, b"payload").unwrap();
//! let b = Blob512::new().unwrap();
//! b.set_key(itb::SLOT_N, &ns.hash_key().unwrap()).unwrap();
//! b.set_components(itb::SLOT_N, &ns.components().unwrap()).unwrap();
//! b.set_key(itb::SLOT_D, &ds.hash_key().unwrap()).unwrap();
//! b.set_components(itb::SLOT_D, &ds.components().unwrap()).unwrap();
//! b.set_key(itb::SLOT_S, &ss.hash_key().unwrap()).unwrap();
//! b.set_components(itb::SLOT_S, &ss.components().unwrap()).unwrap();
//! b.set_mac_key(Some(&mac_key)).unwrap();
//! b.set_mac_name(Some("kmac256")).unwrap();
//! let blob_bytes = b.export(false, true).unwrap();
//! // ... persist blob_bytes ...
//! ```
//!
//! Receiver:
//!
//! ```no_run
//! use itb::{Blob512, Seed};
//! # let blob_bytes: Vec<u8> = vec![];
//! let b2 = Blob512::new().unwrap();
//! b2.import_blob(&blob_bytes).unwrap();
//! let comps = b2.get_components(itb::SLOT_N).unwrap();
//! let key = b2.get_key(itb::SLOT_N).unwrap();
//! let _ns = Seed::from_components("areion512", &comps, &key).unwrap();
//! // ... wire ds, ss the same way; rebuild MAC; decrypt_auth ...
//! ```
//!
//! The blob is mode-discriminated: [`Blob128::export`] / [`Blob256::export`] /
//! [`Blob512::export`] pack Single material, the `export3` counterparts
//! pack Triple material; `import_blob` and `import_triple` are the
//! corresponding receivers. A blob built under one mode rejects the
//! wrong importer with `ITBError(STATUS_BLOB_MODE_MISMATCH)`.
//!
//! Globals (NonceBits / BarrierFill / BitSoup / LockSoup) are captured
//! into the blob at export time and applied process-wide on import via
//! the existing [`crate::set_nonce_bits`] / [`crate::set_barrier_fill`]
//! / [`crate::set_bit_soup`] / [`crate::set_lock_soup`] setters. The
//! worker count and the global LockSeed flag are not serialised — the
//! former is a deployment knob, the latter is irrelevant on the native
//! path which consults [`crate::Seed::attach_lock_seed`] directly.

use std::ffi::{c_char, c_void, CString};

use crate::error::{check, ITBError};
use crate::ffi;

// --------------------------------------------------------------------
// Slot identifiers — must mirror the BlobSlot* constants in
// cmd/cshared/internal/capi/blob_handles.go.
// --------------------------------------------------------------------

pub const SLOT_N: i32 = 0;
pub const SLOT_D: i32 = 1;
pub const SLOT_S: i32 = 2;
pub const SLOT_L: i32 = 3;
pub const SLOT_D1: i32 = 4;
pub const SLOT_D2: i32 = 5;
pub const SLOT_D3: i32 = 6;
pub const SLOT_S1: i32 = 7;
pub const SLOT_S2: i32 = 8;
pub const SLOT_S3: i32 = 9;

/// Typed enumeration of the blob slot identifiers. Convenient
/// alternative to passing the `SLOT_*` integer constants directly;
/// `BlobSlot` converts to the underlying `i32` via `From`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlobSlot {
    /// Noise seed (Single Ouroboros).
    N,
    /// Data seed (Single Ouroboros).
    D,
    /// Start seed (Single Ouroboros).
    S,
    /// Dedicated lockSeed.
    L,
    /// Triple Ouroboros — data seed 1.
    D1,
    /// Triple Ouroboros — data seed 2.
    D2,
    /// Triple Ouroboros — data seed 3.
    D3,
    /// Triple Ouroboros — start seed 1.
    S1,
    /// Triple Ouroboros — start seed 2.
    S2,
    /// Triple Ouroboros — start seed 3.
    S3,
}

impl From<BlobSlot> for i32 {
    fn from(s: BlobSlot) -> i32 {
        match s {
            BlobSlot::N => SLOT_N,
            BlobSlot::D => SLOT_D,
            BlobSlot::S => SLOT_S,
            BlobSlot::L => SLOT_L,
            BlobSlot::D1 => SLOT_D1,
            BlobSlot::D2 => SLOT_D2,
            BlobSlot::D3 => SLOT_D3,
            BlobSlot::S1 => SLOT_S1,
            BlobSlot::S2 => SLOT_S2,
            BlobSlot::S3 => SLOT_S3,
        }
    }
}

/// Resolves a slot identifier from a case-insensitive string name —
/// `"n"`, `"d"`, `"s"`, `"l"`, `"d1"`..`"d3"`, `"s1"`..`"s3"`. Returns
/// `None` for any other input.
pub fn slot_from_name(s: &str) -> Option<i32> {
    match s.to_ascii_lowercase().as_str() {
        "n" => Some(SLOT_N),
        "d" => Some(SLOT_D),
        "s" => Some(SLOT_S),
        "l" => Some(SLOT_L),
        "d1" => Some(SLOT_D1),
        "d2" => Some(SLOT_D2),
        "d3" => Some(SLOT_D3),
        "s1" => Some(SLOT_S1),
        "s2" => Some(SLOT_S2),
        "s3" => Some(SLOT_S3),
        _ => None,
    }
}

// --------------------------------------------------------------------
// Export option bitmask — must mirror BlobOpt* in blob_handles.go.
// --------------------------------------------------------------------

/// Export option flag — emit the `l` slot's lockSeed material (KeyL +
/// components) into the blob.
pub const OPT_LOCKSEED: i32 = 1 << 0;

/// Export option flag — emit the MAC key + name into the blob. Both
/// must be non-empty on the handle.
pub const OPT_MAC: i32 = 1 << 1;

/// Constructs an `ITBError` for a non-OK status code returned by a
/// Blob entry point. Consumers that need to distinguish blob-specific
/// failures match on `err.code()` against the
/// [`crate::STATUS_BLOB_MODE_MISMATCH`] (parsed blob carries the wrong
/// mode for the chosen importer), [`crate::STATUS_BLOB_MALFORMED`]
/// (JSON parse / shape failure), and [`crate::STATUS_BLOB_VERSION_TOO_NEW`]
/// (producer is a newer libitb than the consumer) constants.
pub fn raise_blob(code: i32) -> ITBError {
    ITBError::from_status(code)
}

// --------------------------------------------------------------------
// Shared low-level operations — take a raw handle so each width-typed
// wrapper struct can delegate without duplication.
// --------------------------------------------------------------------

pub(crate) fn blob_width(handle: usize) -> Result<i32, ITBError> {
    let lib = ffi::lib();
    let mut st: i32 = 0;
    let v = unsafe { (lib.ITB_Blob_Width)(handle, &mut st) };
    check(st)?;
    Ok(v)
}

pub(crate) fn blob_mode(handle: usize) -> Result<i32, ITBError> {
    let lib = ffi::lib();
    let mut st: i32 = 0;
    let v = unsafe { (lib.ITB_Blob_Mode)(handle, &mut st) };
    check(st)?;
    Ok(v)
}

pub(crate) fn blob_set_key(
    handle: usize,
    slot: i32,
    key: &[u8],
) -> Result<(), ITBError> {
    let lib = ffi::lib();
    let key_ptr = if key.is_empty() {
        std::ptr::null()
    } else {
        key.as_ptr() as *const c_void
    };
    let rc = unsafe { (lib.ITB_Blob_SetKey)(handle, slot, key_ptr, key.len()) };
    check(rc)
}

pub(crate) fn blob_set_components(
    handle: usize,
    slot: i32,
    components: &[u64],
) -> Result<(), ITBError> {
    let lib = ffi::lib();
    let comps_ptr = if components.is_empty() {
        std::ptr::null()
    } else {
        components.as_ptr()
    };
    let rc = unsafe {
        (lib.ITB_Blob_SetComponents)(handle, slot, comps_ptr, components.len())
    };
    check(rc)
}

pub(crate) fn blob_set_mac_key(
    handle: usize,
    key: Option<&[u8]>,
) -> Result<(), ITBError> {
    let lib = ffi::lib();
    let rc = match key {
        None | Some([]) => unsafe { (lib.ITB_Blob_SetMACKey)(handle, std::ptr::null(), 0) },
        Some(k) => unsafe {
            (lib.ITB_Blob_SetMACKey)(handle, k.as_ptr() as *const c_void, k.len())
        },
    };
    check(rc)
}

pub(crate) fn blob_set_mac_name(
    handle: usize,
    name: Option<&str>,
) -> Result<(), ITBError> {
    let lib = ffi::lib();
    match name {
        None | Some("") => {
            let rc = unsafe { (lib.ITB_Blob_SetMACName)(handle, std::ptr::null(), 0) };
            check(rc)
        }
        Some(s) => {
            let cname = CString::new(s).map_err(|_| {
                ITBError::with_message(ffi::STATUS_BAD_INPUT, "MAC name contains NUL")
            })?;
            let bytes = cname.as_bytes();
            let rc = unsafe {
                (lib.ITB_Blob_SetMACName)(handle, cname.as_ptr(), bytes.len())
            };
            check(rc)
        }
    }
}

pub(crate) fn blob_get_key(handle: usize, slot: i32) -> Result<Vec<u8>, ITBError> {
    let lib = ffi::lib();
    let mut out_len: usize = 0;
    let rc = unsafe {
        (lib.ITB_Blob_GetKey)(handle, slot, std::ptr::null_mut(), 0, &mut out_len)
    };
    if rc != ffi::STATUS_OK && rc != ffi::STATUS_BUFFER_TOO_SMALL {
        return Err(ITBError::from_status(rc));
    }
    let n = out_len;
    if n == 0 {
        return Ok(Vec::new());
    }
    let mut buf = vec![0u8; n];
    let rc = unsafe {
        (lib.ITB_Blob_GetKey)(
            handle,
            slot,
            buf.as_mut_ptr() as *mut c_void,
            n,
            &mut out_len,
        )
    };
    check(rc)?;
    buf.truncate(out_len);
    Ok(buf)
}

pub(crate) fn blob_get_components(
    handle: usize,
    slot: i32,
) -> Result<Vec<u64>, ITBError> {
    let lib = ffi::lib();
    let mut out_count: usize = 0;
    let rc = unsafe {
        (lib.ITB_Blob_GetComponents)(
            handle,
            slot,
            std::ptr::null_mut(),
            0,
            &mut out_count,
        )
    };
    if rc != ffi::STATUS_OK && rc != ffi::STATUS_BUFFER_TOO_SMALL {
        return Err(ITBError::from_status(rc));
    }
    let n = out_count;
    if n == 0 {
        return Ok(Vec::new());
    }
    let mut buf = vec![0u64; n];
    let rc = unsafe {
        (lib.ITB_Blob_GetComponents)(handle, slot, buf.as_mut_ptr(), n, &mut out_count)
    };
    check(rc)?;
    buf.truncate(out_count);
    Ok(buf)
}

pub(crate) fn blob_get_mac_key(handle: usize) -> Result<Vec<u8>, ITBError> {
    let lib = ffi::lib();
    let mut out_len: usize = 0;
    let rc = unsafe {
        (lib.ITB_Blob_GetMACKey)(handle, std::ptr::null_mut(), 0, &mut out_len)
    };
    if rc != ffi::STATUS_OK && rc != ffi::STATUS_BUFFER_TOO_SMALL {
        return Err(ITBError::from_status(rc));
    }
    let n = out_len;
    if n == 0 {
        return Ok(Vec::new());
    }
    let mut buf = vec![0u8; n];
    let rc = unsafe {
        (lib.ITB_Blob_GetMACKey)(
            handle,
            buf.as_mut_ptr() as *mut c_void,
            n,
            &mut out_len,
        )
    };
    check(rc)?;
    buf.truncate(out_len);
    Ok(buf)
}

pub(crate) fn blob_get_mac_name(handle: usize) -> Result<String, ITBError> {
    let lib = ffi::lib();
    let mut out_len: usize = 0;
    let rc = unsafe {
        (lib.ITB_Blob_GetMACName)(handle, std::ptr::null_mut(), 0, &mut out_len)
    };
    if rc != ffi::STATUS_OK && rc != ffi::STATUS_BUFFER_TOO_SMALL {
        return Err(ITBError::from_status(rc));
    }
    let cap = out_len;
    if cap <= 1 {
        return Ok(String::new());
    }
    let mut buf = vec![0u8; cap];
    let rc = unsafe {
        (lib.ITB_Blob_GetMACName)(
            handle,
            buf.as_mut_ptr() as *mut c_char,
            cap,
            &mut out_len,
        )
    };
    check(rc)?;
    let n = out_len.saturating_sub(1);
    buf.truncate(n);
    String::from_utf8(buf).map_err(|e| {
        ITBError::with_message(ffi::STATUS_INTERNAL, format!("utf8 decode: {e}"))
    })
}

fn opts_mask(lockseed: bool, mac: bool) -> i32 {
    let mut m = 0;
    if lockseed {
        m |= OPT_LOCKSEED;
    }
    if mac {
        m |= OPT_MAC;
    }
    m
}

pub(crate) fn blob_export(
    handle: usize,
    opts: i32,
    triple: bool,
) -> Result<Vec<u8>, ITBError> {
    let lib = ffi::lib();
    // Two-phase probe-then-retry buffer convention.
    let mut out_len: usize = 0;
    let probe_rc = unsafe {
        if triple {
            (lib.ITB_Blob_Export3)(handle, opts, std::ptr::null_mut(), 0, &mut out_len)
        } else {
            (lib.ITB_Blob_Export)(handle, opts, std::ptr::null_mut(), 0, &mut out_len)
        }
    };
    if probe_rc != ffi::STATUS_OK && probe_rc != ffi::STATUS_BUFFER_TOO_SMALL {
        return Err(ITBError::from_status(probe_rc));
    }
    let cap = out_len;
    if cap == 0 {
        return Ok(Vec::new());
    }
    let mut buf = vec![0u8; cap];
    let rc = unsafe {
        if triple {
            (lib.ITB_Blob_Export3)(
                handle,
                opts,
                buf.as_mut_ptr() as *mut c_void,
                cap,
                &mut out_len,
            )
        } else {
            (lib.ITB_Blob_Export)(
                handle,
                opts,
                buf.as_mut_ptr() as *mut c_void,
                cap,
                &mut out_len,
            )
        }
    };
    check(rc)?;
    buf.truncate(out_len);
    Ok(buf)
}

pub(crate) fn blob_import(handle: usize, blob: &[u8]) -> Result<(), ITBError> {
    let lib = ffi::lib();
    let in_ptr = if blob.is_empty() {
        std::ptr::null()
    } else {
        blob.as_ptr() as *const c_void
    };
    let rc = unsafe { (lib.ITB_Blob_Import)(handle, in_ptr, blob.len()) };
    check(rc)
}

pub(crate) fn blob_import_triple(handle: usize, blob: &[u8]) -> Result<(), ITBError> {
    let lib = ffi::lib();
    let in_ptr = if blob.is_empty() {
        std::ptr::null()
    } else {
        blob.as_ptr() as *const c_void
    };
    let rc = unsafe { (lib.ITB_Blob_Import3)(handle, in_ptr, blob.len()) };
    check(rc)
}

pub(crate) fn blob_free(handle: usize) -> Result<(), ITBError> {
    let lib = ffi::lib();
    let rc = unsafe { (lib.ITB_Blob_Free)(handle) };
    check(rc)
}

// --------------------------------------------------------------------
// Width-typed wrapper structs.
// --------------------------------------------------------------------

/// 128-bit width Blob — covers `siphash24` and `aescmac` primitives.
/// Hash key length is variable: empty for siphash24 (no internal fixed
/// key), 16 bytes for aescmac. The 128-bit width is reserved for
/// testing and below-spec stress controls; for production traffic
/// prefer [`Blob256`] or [`Blob512`].
pub struct Blob128 {
    handle: usize,
}

/// 256-bit width Blob — covers `areion256`, `blake2s`, `blake2b256`,
/// `blake3`, `chacha20`. Hash key length is fixed at 32 bytes.
pub struct Blob256 {
    handle: usize,
}

/// 512-bit width Blob — covers `areion512` (via the SoEM-512
/// construction) and `blake2b512`. Hash key length is fixed at 64
/// bytes.
pub struct Blob512 {
    handle: usize,
}

macro_rules! impl_blob_methods {
    ($T:ident) => {
        impl $T {
            /// Returns the opaque libitb handle id (uintptr). Useful for
            /// diagnostics; consumers should not rely on its numerical
            /// value.
            pub fn handle(&self) -> usize {
                self.handle
            }

            /// Returns the native hash width — 128, 256, or 512. Pinned
            /// at construction time and stable for the lifetime of the
            /// handle.
            pub fn width(&self) -> Result<i32, ITBError> {
                blob_width(self.handle)
            }

            /// Returns the blob mode field — `0` = unset (freshly
            /// constructed handle), `1` = Single Ouroboros, `3` =
            /// Triple Ouroboros. Updated by [`Self::import_blob`] /
            /// [`Self::import_triple`] from the parsed blob's mode
            /// discriminator.
            pub fn mode(&self) -> Result<i32, ITBError> {
                blob_mode(self.handle)
            }

            /// Stores the hash key bytes for the given slot. The 256 /
            /// 512 widths require exactly 32 / 64 bytes; the 128 width
            /// accepts variable lengths (empty for siphash24 — no
            /// internal fixed key — or 16 bytes for aescmac).
            pub fn set_key(&self, slot: i32, key: &[u8]) -> Result<(), ITBError> {
                blob_set_key(self.handle, slot, key)
            }

            /// Stores the seed components (slice of unsigned 64-bit
            /// integers) for the given slot. Component count must
            /// satisfy the 8..MaxKeyBits/64 multiple-of-8 invariants —
            /// same rules as [`crate::Seed::from_components`].
            /// Validation is deferred to [`Self::export`] /
            /// [`Self::import_blob`] time.
            pub fn set_components(
                &self,
                slot: i32,
                components: &[u64],
            ) -> Result<(), ITBError> {
                blob_set_components(self.handle, slot, components)
            }

            /// Stores the optional MAC key bytes. Pass `None` or an
            /// empty slice to clear a previously-set key. The MAC
            /// section is only emitted by [`Self::export`] /
            /// [`Self::export3`] when `mac=true` is passed AND the MAC
            /// key on the handle is non-empty.
            pub fn set_mac_key(&self, key: Option<&[u8]>) -> Result<(), ITBError> {
                blob_set_mac_key(self.handle, key)
            }

            /// Stores the optional MAC name on the handle (e.g.
            /// `"kmac256"`, `"hmac-blake3"`). Pass `None` or an empty
            /// string to clear a previously-set name.
            pub fn set_mac_name(&self, name: Option<&str>) -> Result<(), ITBError> {
                blob_set_mac_name(self.handle, name)
            }

            /// Returns a fresh copy of the hash key bytes from the
            /// given slot. Returns an empty `Vec<u8>` for an unset
            /// slot or siphash24's no-internal-key path (callers
            /// distinguish by `len() == 0` and the slot they queried).
            pub fn get_key(&self, slot: i32) -> Result<Vec<u8>, ITBError> {
                blob_get_key(self.handle, slot)
            }

            /// Returns a `Vec<u64>` of seed components stored at the
            /// given slot. Returns an empty vector for an unset slot.
            pub fn get_components(&self, slot: i32) -> Result<Vec<u64>, ITBError> {
                blob_get_components(self.handle, slot)
            }

            /// Returns a fresh copy of the MAC key bytes from the
            /// handle, or an empty `Vec<u8>` if no MAC is associated.
            pub fn get_mac_key(&self) -> Result<Vec<u8>, ITBError> {
                blob_get_mac_key(self.handle)
            }

            /// Returns the MAC name from the handle, or an empty
            /// string if no MAC is associated.
            pub fn get_mac_name(&self) -> Result<String, ITBError> {
                blob_get_mac_name(self.handle)
            }

            /// Serialises the handle's Single-Ouroboros state into a
            /// JSON blob. The optional `lockseed` and `mac` flags opt
            /// the matching sections in: when `lockseed=true` the `l`
            /// slot's KeyL + components are emitted; when `mac=true`
            /// the MAC key + name are emitted (both must be non-empty
            /// on the handle).
            pub fn export(
                &self,
                lockseed: bool,
                mac: bool,
            ) -> Result<Vec<u8>, ITBError> {
                blob_export(self.handle, opts_mask(lockseed, mac), false)
            }

            /// Serialises the handle's Triple-Ouroboros state into a
            /// JSON blob. See [`Self::export`] for the `lockseed` /
            /// `mac` flag semantics.
            pub fn export3(
                &self,
                lockseed: bool,
                mac: bool,
            ) -> Result<Vec<u8>, ITBError> {
                blob_export(self.handle, opts_mask(lockseed, mac), true)
            }

            /// Parses a Single-Ouroboros JSON blob, populates the
            /// handle's slots, and applies the captured globals via
            /// the process-wide setters.
            ///
            /// Returns `ITBError(STATUS_BLOB_MODE_MISMATCH)` when the
            /// blob is Triple-mode,
            /// `ITBError(STATUS_BLOB_MALFORMED)` on parse / shape
            /// failure, `ITBError(STATUS_BLOB_VERSION_TOO_NEW)` on a
            /// version field higher than this build supports.
            pub fn import_blob(&self, blob: &[u8]) -> Result<(), ITBError> {
                blob_import(self.handle, blob)
            }

            /// Triple-Ouroboros counterpart of [`Self::import_blob`].
            /// Same error contract.
            pub fn import_triple(&self, blob: &[u8]) -> Result<(), ITBError> {
                blob_import_triple(self.handle, blob)
            }

            /// Explicitly releases the underlying libitb handle.
            /// `Drop` calls this automatically when the value goes out
            /// of scope; an explicit call is only needed when the
            /// caller wants to surface a release-time error (rare).
            pub fn free(mut self) -> Result<(), ITBError> {
                if self.handle != 0 {
                    let h = self.handle;
                    self.handle = 0;
                    blob_free(h)
                } else {
                    Ok(())
                }
            }
        }

        impl Drop for $T {
            fn drop(&mut self) {
                if self.handle != 0 {
                    let lib = ffi::lib();
                    // Best-effort release; errors during drop are
                    // swallowed because there is no path to surface
                    // them.
                    unsafe {
                        let _ = (lib.ITB_Blob_Free)(self.handle);
                    }
                    self.handle = 0;
                }
            }
        }
    };
}

impl Blob128 {
    /// Constructs a fresh 128-bit width Blob handle.
    pub fn new() -> Result<Self, ITBError> {
        let lib = ffi::lib();
        let mut handle: usize = 0;
        let rc = unsafe { (lib.ITB_Blob128_New)(&mut handle) };
        check(rc)?;
        Ok(Self { handle })
    }
}

impl Blob256 {
    /// Constructs a fresh 256-bit width Blob handle.
    pub fn new() -> Result<Self, ITBError> {
        let lib = ffi::lib();
        let mut handle: usize = 0;
        let rc = unsafe { (lib.ITB_Blob256_New)(&mut handle) };
        check(rc)?;
        Ok(Self { handle })
    }
}

impl Blob512 {
    /// Constructs a fresh 512-bit width Blob handle.
    pub fn new() -> Result<Self, ITBError> {
        let lib = ffi::lib();
        let mut handle: usize = 0;
        let rc = unsafe { (lib.ITB_Blob512_New)(&mut handle) };
        check(rc)?;
        Ok(Self { handle })
    }
}

impl_blob_methods!(Blob128);
impl_blob_methods!(Blob256);
impl_blob_methods!(Blob512);
