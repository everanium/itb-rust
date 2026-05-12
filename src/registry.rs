//! Registry, library configuration, and stream-header helpers.
//!
//! Exposes the libitb free-function surface that is not tied to a
//! specific seed / MAC / encryptor instance: hash + MAC catalogs,
//! `version()`, the global `set_*` / `get_*` knobs, and the
//! `parse_chunk_len()` helper used by streaming consumers.

use std::ffi::c_void;

use crate::error::{check, read_str, ITBError};
use crate::ffi;

/// Returns the libitb library version string.
pub fn version() -> Result<String, ITBError> {
    let lib = ffi::lib();
    read_str(|out, cap, out_len| unsafe { (lib.ITB_Version)(out, cap, out_len) })
}

/// Returns `(name, native_width_bits)` pairs in canonical FFI order.
pub fn list_hashes() -> Result<Vec<(String, i32)>, ITBError> {
    let lib = ffi::lib();
    let n = unsafe { (lib.ITB_HashCount)() };
    let mut out = Vec::with_capacity(n as usize);
    for i in 0..n {
        let name = read_str(|buf, cap, out_len| unsafe {
            (lib.ITB_HashName)(i, buf, cap, out_len)
        })?;
        let width = unsafe { (lib.ITB_HashWidth)(i) };
        out.push((name, width));
    }
    Ok(out)
}

/// Returns `(name, key_size, tag_size, min_key_bytes)` quadruples in
/// canonical FFI order (`kmac256`, `hmac-sha256`, `hmac-blake3`).
pub fn list_macs() -> Result<Vec<(String, i32, i32, i32)>, ITBError> {
    let lib = ffi::lib();
    let n = unsafe { (lib.ITB_MACCount)() };
    let mut out = Vec::with_capacity(n as usize);
    for i in 0..n {
        let name = read_str(|buf, cap, out_len| unsafe {
            (lib.ITB_MACName)(i, buf, cap, out_len)
        })?;
        let key_size = unsafe { (lib.ITB_MACKeySize)(i) };
        let tag_size = unsafe { (lib.ITB_MACTagSize)(i) };
        let min_key = unsafe { (lib.ITB_MACMinKeyBytes)(i) };
        out.push((name, key_size, tag_size, min_key));
    }
    Ok(out)
}

/// Returns the maximum supported ITB key width in bits.
pub fn max_key_bits() -> i32 {
    unsafe { (ffi::lib().ITB_MaxKeyBits)() }
}

/// Returns the number of native-channel slots (typically 7 for the
/// 128 / 256 / 512-bit shipping primitives).
pub fn channels() -> i32 {
    unsafe { (ffi::lib().ITB_Channels)() }
}

/// Returns the current ciphertext-chunk header size in bytes
/// (nonce + width(2) + height(2)). Tracks the active `set_nonce_bits`
/// configuration: 20 by default, 36 under `set_nonce_bits(256)`,
/// 68 under `set_nonce_bits(512)`. Used by streaming consumers to
/// know how many bytes to read from disk / wire before calling
/// `parse_chunk_len()` on each chunk.
pub fn header_size() -> i32 {
    unsafe { (ffi::lib().ITB_HeaderSize)() }
}

/// Inspects a chunk header (the fixed-size
/// `[nonce || width(2) || height(2)]` prefix at the start of a
/// ciphertext chunk) and returns the total chunk length on the wire.
///
/// The buffer must contain at least `header_size()` bytes; only the
/// header is consulted, the body bytes do not need to be present.
/// Returns `ITBError` on too-short buffer, zero dimensions, or
/// overflow.
pub fn parse_chunk_len(header: &[u8]) -> Result<usize, ITBError> {
    let lib = ffi::lib();
    let mut out: usize = 0;
    let rc = unsafe {
        (lib.ITB_ParseChunkLen)(header.as_ptr() as *const c_void, header.len(), &mut out)
    };
    check(rc)?;
    Ok(out)
}

// ----- Global toggles --------------------------------------------------

/// Sets the process-wide Bit Soup mode (0 = byte-level split,
/// non-zero = bit-level Bit Soup split). Independent of `set_lock_soup`
/// at the setter level — there is no `BitSoup → LockSoup` cascade. In
/// Single Ouroboros, either flag alone activates the dispatcher's
/// keyed bit-permutation overlay (Single OR-gates the two flags).
pub fn set_bit_soup(mode: i32) -> Result<(), ITBError> {
    let rc = unsafe { (ffi::lib().ITB_SetBitSoup)(mode) };
    check(rc)
}

pub fn get_bit_soup() -> i32 {
    unsafe { (ffi::lib().ITB_GetBitSoup)() }
}

/// Sets the process-wide Lock Soup mode (0 = off, non-zero = on). A
/// non-zero value auto-couples `set_bit_soup(1)` (Lock Soup overlay
/// layers on top of bit soup; one-direction cascade). The off-direction
/// does not auto-disable bit soup.
pub fn set_lock_soup(mode: i32) -> Result<(), ITBError> {
    let rc = unsafe { (ffi::lib().ITB_SetLockSoup)(mode) };
    check(rc)
}

pub fn get_lock_soup() -> i32 {
    unsafe { (ffi::lib().ITB_GetLockSoup)() }
}

pub fn set_max_workers(n: i32) -> Result<(), ITBError> {
    let rc = unsafe { (ffi::lib().ITB_SetMaxWorkers)(n) };
    check(rc)
}

pub fn get_max_workers() -> i32 {
    unsafe { (ffi::lib().ITB_GetMaxWorkers)() }
}

/// Accepts 128, 256, or 512. Other values raise
/// `ITBError(STATUS_BAD_INPUT)`.
pub fn set_nonce_bits(n: i32) -> Result<(), ITBError> {
    let rc = unsafe { (ffi::lib().ITB_SetNonceBits)(n) };
    check(rc)
}

pub fn get_nonce_bits() -> i32 {
    unsafe { (ffi::lib().ITB_GetNonceBits)() }
}

/// Accepts 1, 2, 4, 8, 16, 32. Other values raise
/// `ITBError(STATUS_BAD_INPUT)`.
pub fn set_barrier_fill(n: i32) -> Result<(), ITBError> {
    let rc = unsafe { (ffi::lib().ITB_SetBarrierFill)(n) };
    check(rc)
}

pub fn get_barrier_fill() -> i32 {
    unsafe { (ffi::lib().ITB_GetBarrierFill)() }
}

/// Configures the Go runtime's heap-size soft limit (bytes). Pass -1
/// (or any negative value) to query the current limit without changing
/// it; the previous limit is returned. Setter calls override any
/// ITB_GOMEMLIMIT env var set at libitb load time.
pub fn set_memory_limit(limit: i64) -> i64 {
    unsafe { (ffi::lib().ITB_SetMemoryLimit)(limit) }
}

/// Configures the Go runtime's GC trigger percentage. The default is
/// 100 (GC fires at +100% heap growth); lower values trigger GC more
/// aggressively. Pass -1 (or any negative value) to query the current
/// value without changing it; the previous value is returned. Setter
/// calls override any ITB_GOGC env var set at libitb load time.
pub fn set_gc_percent(pct: i32) -> i32 {
    unsafe { (ffi::lib().ITB_SetGCPercent)(pct) }
}
