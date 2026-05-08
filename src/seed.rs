//! ITB seed handle.
//!
//! Provides a thin RAII wrapper over `ITB_NewSeed` / `ITB_FreeSeed`
//! plus the introspection accessors (`width`, `hash_name`, `hash_key`,
//! `components`) and the deterministic-rebuild path
//! `Seed::from_components`.

use std::ffi::{c_char, CString};

use crate::error::{check, read_str, ITBError};
use crate::ffi;

/// A handle to one ITB seed.
///
/// Construct via [`Seed::new`] for a CSPRNG-keyed seed or
/// [`Seed::from_components`] for a deterministic rebuild from
/// caller-supplied uint64 components and an optional fixed hash key.
///
/// All three seeds passed to [`crate::encrypt::encrypt`] / [`crate::encrypt::decrypt`]
/// must share the same hash name (or at least the same native hash
/// width); mixing widths surfaces as
/// `ITBError(STATUS_SEED_WIDTH_MIX)`.
pub struct Seed {
    handle: usize,
    hash_name: String,
}

impl Seed {
    /// Constructs a fresh seed with CSPRNG-generated keying material.
    ///
    /// `hash_name` is a canonical hash name from
    /// [`crate::list_hashes`] (e.g. `"blake3"`, `"areion256"`).
    /// `key_bits` is the ITB key width in bits — 512, 1024, or 2048
    /// (multiple of 64).
    pub fn new(hash_name: &str, key_bits: i32) -> Result<Self, ITBError> {
        let lib = ffi::lib();
        let cname = CString::new(hash_name).map_err(|_| {
            ITBError::with_message(ffi::STATUS_BAD_INPUT, "hash_name contains NUL")
        })?;
        let mut handle: usize = 0;
        let rc = unsafe { (lib.ITB_NewSeed)(cname.as_ptr(), key_bits, &mut handle) };
        check(rc)?;
        Ok(Self {
            handle,
            hash_name: hash_name.to_owned(),
        })
    }

    /// Builds a seed deterministically from caller-supplied uint64
    /// components and an optional fixed hash key. Use this on the
    /// persistence-restore path (encrypt today, decrypt tomorrow);
    /// pass `&[]` for `hash_key` to request a CSPRNG-generated key
    /// (still useful when only the components need to be
    /// deterministic).
    ///
    /// `components` length must be 8..=32 (multiple of 8).
    /// `hash_key` length, when non-empty, must match the primitive's
    /// native fixed-key size: 16 (`aescmac`), 32 (`areion256` /
    /// `blake2{s,b256}` / `blake3` / `chacha20`), 64 (`areion512` /
    /// `blake2b512`). Pass `&[]` for `siphash24` (no internal fixed
    /// key).
    pub fn from_components(
        hash_name: &str,
        components: &[u64],
        hash_key: &[u8],
    ) -> Result<Self, ITBError> {
        let lib = ffi::lib();
        let cname = CString::new(hash_name).map_err(|_| {
            ITBError::with_message(ffi::STATUS_BAD_INPUT, "hash_name contains NUL")
        })?;
        let comps_ptr = if components.is_empty() {
            std::ptr::null()
        } else {
            components.as_ptr()
        };
        let key_ptr = if hash_key.is_empty() {
            std::ptr::null()
        } else {
            hash_key.as_ptr()
        };
        let comps_len = i32::try_from(components.len()).map_err(|_| {
            ITBError::with_message(
                ffi::STATUS_BAD_INPUT,
                "components length exceeds i32::MAX",
            )
        })?;
        let key_len = i32::try_from(hash_key.len()).map_err(|_| {
            ITBError::with_message(
                ffi::STATUS_BAD_INPUT,
                "hash_key length exceeds i32::MAX",
            )
        })?;
        let mut handle: usize = 0;
        let rc = unsafe {
            (lib.ITB_NewSeedFromComponents)(
                cname.as_ptr(),
                comps_ptr,
                comps_len,
                key_ptr,
                key_len,
                &mut handle,
            )
        };
        check(rc)?;
        Ok(Self {
            handle,
            hash_name: hash_name.to_owned(),
        })
    }

    /// Returns the raw libitb handle (an opaque `uintptr_t` token).
    /// Used by the low-level `encrypt` / `decrypt` free functions and
    /// by [`Seed::attach_lock_seed`].
    pub fn handle(&self) -> usize {
        self.handle
    }

    /// Returns the canonical hash name this seed was constructed with.
    pub fn hash_name(&self) -> &str {
        &self.hash_name
    }

    /// Returns the seed's native hash width in bits (128 / 256 / 512).
    pub fn width(&self) -> Result<i32, ITBError> {
        let lib = ffi::lib();
        let mut st: i32 = 0;
        let w = unsafe { (lib.ITB_SeedWidth)(self.handle, &mut st) };
        check(st)?;
        Ok(w)
    }

    /// Returns the fixed key the underlying hash closure is bound to
    /// (16 / 32 / 64 bytes depending on the primitive). Save these
    /// bytes alongside [`Seed::components`] for cross-process
    /// persistence — the pair fully reconstructs the seed via
    /// [`Seed::from_components`].
    ///
    /// `siphash24` returns an empty `Vec<u8>` since SipHash-2-4 has no
    /// internal fixed key (its keying material is the seed components
    /// themselves).
    pub fn hash_key(&self) -> Result<Vec<u8>, ITBError> {
        let lib = ffi::lib();
        let mut out_len: usize = 0;
        // Two-call pattern: first probe length (cap=0), then allocate.
        let rc = unsafe { (lib.ITB_GetSeedHashKey)(self.handle, std::ptr::null_mut(), 0, &mut out_len) };
        // Probing returns BUFFER_TOO_SMALL when the key is non-empty
        // (no buffer to write into); empty key is OK.
        if rc == ffi::STATUS_OK && out_len == 0 {
            return Ok(Vec::new());
        }
        if rc != ffi::STATUS_BUFFER_TOO_SMALL {
            return Err(ITBError::from_status(rc));
        }
        let cap = out_len;
        let mut buf = vec![0u8; cap];
        let rc = unsafe {
            (lib.ITB_GetSeedHashKey)(self.handle, buf.as_mut_ptr(), cap, &mut out_len)
        };
        check(rc)?;
        buf.truncate(out_len);
        Ok(buf)
    }

    /// Returns the seed's underlying uint64 components (8..=32
    /// elements). Save these alongside [`Seed::hash_key`] for
    /// cross-process persistence — the pair fully reconstructs the
    /// seed via [`Seed::from_components`].
    pub fn components(&self) -> Result<Vec<u64>, ITBError> {
        let lib = ffi::lib();
        let mut out_len: i32 = 0;
        let rc = unsafe {
            (lib.ITB_GetSeedComponents)(self.handle, std::ptr::null_mut(), 0, &mut out_len)
        };
        if rc != ffi::STATUS_BUFFER_TOO_SMALL {
            return Err(ITBError::from_status(rc));
        }
        let n = out_len as usize;
        let mut buf = vec![0u64; n];
        let rc = unsafe {
            (lib.ITB_GetSeedComponents)(self.handle, buf.as_mut_ptr(), n as i32, &mut out_len)
        };
        check(rc)?;
        buf.truncate(out_len as usize);
        Ok(buf)
    }

    /// Returns the canonical hash name reported by libitb (round-trip
    /// of the constructor argument).
    pub fn hash_name_introspect(&self) -> Result<String, ITBError> {
        let lib = ffi::lib();
        let handle = self.handle;
        read_str(|out: *mut c_char, cap, out_len| unsafe {
            (lib.ITB_SeedHashName)(handle, out, cap, out_len)
        })
    }

    /// Wires a dedicated lockSeed onto this noise seed. The per-chunk
    /// PRF closure for the bit-permutation overlay captures BOTH the
    /// lockSeed's components AND its hash function — keying-material
    /// isolation plus algorithm diversity (the lockSeed primitive may
    /// legitimately differ from the noise-seed primitive within the
    /// same native hash width) for defence-in-depth on the overlay
    /// channel. Both seeds must share the same native hash width.
    ///
    /// The dedicated lockSeed has no observable effect on the wire
    /// output unless the bit-permutation overlay is engaged via
    /// [`crate::set_bit_soup`]`(1)` or [`crate::set_lock_soup`]`(1)`
    /// before the first encrypt / decrypt call. The Go-side
    /// build-PRF guard panics on encrypt-time when an attach is
    /// present without either flag, surfacing as `ITBError`.
    ///
    /// Misuse paths surface as `ITBError(STATUS_BAD_INPUT)`:
    /// self-attach (passing the same seed twice), component-array
    /// aliasing (two distinct Seed handles whose components share the
    /// same backing array — only reachable via raw FFI), and
    /// post-encrypt switching (calling `attach_lock_seed` on a noise
    /// seed that has already produced ciphertext). Width mismatch
    /// surfaces as `ITBError(STATUS_SEED_WIDTH_MIX)`.
    ///
    /// The dedicated lockSeed remains owned by the caller — attach
    /// only records the pointer on the noise seed, so keep the
    /// lockSeed alive for the lifetime of the noise seed (do not drop
    /// the lockSeed before encrypt finishes).
    pub fn attach_lock_seed(&self, lock_seed: &Seed) -> Result<(), ITBError> {
        let lib = ffi::lib();
        let rc = unsafe { (lib.ITB_AttachLockSeed)(self.handle, lock_seed.handle) };
        check(rc)
    }

    /// Explicitly releases the underlying handle. Idempotent.
    /// `Drop` calls this automatically when the value goes out of
    /// scope; an explicit call is only needed when the caller wants
    /// to surface a release-time error (rare).
    pub fn free(mut self) -> Result<(), ITBError> {
        if self.handle != 0 {
            let lib = ffi::lib();
            let rc = unsafe { (lib.ITB_FreeSeed)(self.handle) };
            self.handle = 0;
            check(rc)
        } else {
            Ok(())
        }
    }
}

impl Drop for Seed {
    fn drop(&mut self) {
        if self.handle != 0 {
            let lib = ffi::lib();
            // Best-effort release; errors during drop are swallowed
            // because there is no path to surface them (Drop has no
            // return value) and process-shutdown ordering can be
            // unpredictable.
            unsafe {
                let _ = (lib.ITB_FreeSeed)(self.handle);
            }
            self.handle = 0;
        }
    }
}
