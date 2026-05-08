//! Raw libloading-based FFI bindings over libitb's C ABI.
//!
//! Loads libitb.so / .dll / .dylib at runtime via the `libloading` crate
//! (no build-time linking, no C compiler at install). The shared library
//! is searched in this order:
//!
//!   1. `ITB_LIBRARY_PATH` environment variable (absolute path).
//!   2. `<repo>/dist/<os>-<arch>/libitb.<ext>` resolved from the crate
//!      manifest directory by walking two directory levels up
//!      (`bindings/rust/` → repo root → `dist/...`).
//!   3. system loader path (`ldconfig` / `DYLD_LIBRARY_PATH` / `PATH`).
//!
//! Status codes returned by every entry point are translated to
//! `ITBError` by the higher-level wrappers in `crate::registry` and the
//! `Seed` / `MAC` / `Encryptor` modules.
//!
//! Threading note. `ITB_LastError` and `ITB_Easy_LastMismatchField`
//! read process-global atomics that follow the C `errno` discipline:
//! the most recent non-OK Status across the whole process wins, and a
//! sibling thread that calls into libitb between the failing call and
//! the diagnostic read overwrites the message. Multi-threaded Rust
//! applications that need reliable diagnostic attribution should
//! serialise FFI calls under a process-wide lock or accept that the
//! textual message returned by `ITBError` may belong to a different
//! call. The structural Status code on the failing call's return value
//! is unaffected — only the textual diagnostic is racy.

#![allow(non_snake_case)]
#![allow(dead_code)]

use std::ffi::{c_char, c_int, c_void};
use std::path::PathBuf;
use std::sync::OnceLock;

use libloading::Library;

// --------------------------------------------------------------------
// Status codes — must mirror cmd/cshared/internal/capi/errors.go
// --------------------------------------------------------------------

pub const STATUS_OK: c_int = 0;
pub const STATUS_BAD_HASH: c_int = 1;
pub const STATUS_BAD_KEY_BITS: c_int = 2;
pub const STATUS_BAD_HANDLE: c_int = 3;
pub const STATUS_BAD_INPUT: c_int = 4;
pub const STATUS_BUFFER_TOO_SMALL: c_int = 5;
pub const STATUS_ENCRYPT_FAILED: c_int = 6;
pub const STATUS_DECRYPT_FAILED: c_int = 7;
pub const STATUS_SEED_WIDTH_MIX: c_int = 8;
pub const STATUS_BAD_MAC: c_int = 9;
pub const STATUS_MAC_FAILURE: c_int = 10;
// Easy encryptor (itb/easy sub-package) sentinel codes — block 11..18
// is dedicated to the Encryptor surface so the lower codes 0..10 remain
// reserved for the low-level Encrypt / Decrypt path.
pub const STATUS_EASY_CLOSED: c_int = 11;
pub const STATUS_EASY_MALFORMED: c_int = 12;
pub const STATUS_EASY_VERSION_TOO_NEW: c_int = 13;
pub const STATUS_EASY_UNKNOWN_PRIMITIVE: c_int = 14;
pub const STATUS_EASY_UNKNOWN_MAC: c_int = 15;
pub const STATUS_EASY_BAD_KEY_BITS: c_int = 16;
pub const STATUS_EASY_MISMATCH: c_int = 17;
pub const STATUS_EASY_LOCKSEED_AFTER_ENCRYPT: c_int = 18;
// Native Blob (itb.Blob128 / 256 / 512) sentinel codes — block 19..22
// is dedicated to the low-level state-blob surface so the lower codes
// 0..18 remain reserved for the seed-handle / Encrypt / Decrypt /
// Encryptor paths.
pub const STATUS_BLOB_MODE_MISMATCH: c_int = 19;
pub const STATUS_BLOB_MALFORMED: c_int = 20;
pub const STATUS_BLOB_VERSION_TOO_NEW: c_int = 21;
pub const STATUS_BLOB_TOO_MANY_OPTS: c_int = 22;
// Streaming AEAD end-of-stream sentinels — block 23..24 is reserved
// for the stream-loop helper to surface the two end-of-stream failure
// modes that the per-chunk libitb ABI cannot express on its own.
pub const STATUS_STREAM_TRUNCATED: c_int = 23;
pub const STATUS_STREAM_AFTER_FINAL: c_int = 24;
pub const STATUS_INTERNAL: c_int = 99;

// --------------------------------------------------------------------
// Raw extern fn pointer typedefs
// --------------------------------------------------------------------
//
// Every signature mirrors a `//export` wrapper in cmd/cshared/main.go,
// canonicalised by cgo into dist/<os>-<arch>/libitb.h.
//
// Type mapping:
//   C `int`        → `c_int`
//   C `size_t`     → `usize`
//   C `uintptr_t`  → `usize`        (host word size)
//   C `uint64_t`   → `u64`
//   C `uint8_t*`   → `*const u8` / `*mut u8`
//   C `void*`      → `*const c_void` / `*mut c_void`
//   C `char*` (in) → `*const c_char`
//   C `char*` (out)→ `*mut c_char`

pub type FnVersion = unsafe extern "C" fn(*mut c_char, usize, *mut usize) -> c_int;
pub type FnHashCount = unsafe extern "C" fn() -> c_int;
pub type FnHashName = unsafe extern "C" fn(c_int, *mut c_char, usize, *mut usize) -> c_int;
pub type FnHashWidth = unsafe extern "C" fn(c_int) -> c_int;
pub type FnLastError = unsafe extern "C" fn(*mut c_char, usize, *mut usize) -> c_int;

pub type FnNewSeed = unsafe extern "C" fn(*const c_char, c_int, *mut usize) -> c_int;
pub type FnFreeSeed = unsafe extern "C" fn(usize) -> c_int;
pub type FnSeedWidth = unsafe extern "C" fn(usize, *mut c_int) -> c_int;
pub type FnSeedHashName = unsafe extern "C" fn(usize, *mut c_char, usize, *mut usize) -> c_int;

pub type FnNewSeedFromComponents = unsafe extern "C" fn(
    *const c_char,
    *const u64,
    c_int,
    *const u8,
    c_int,
    *mut usize,
) -> c_int;
pub type FnGetSeedHashKey = unsafe extern "C" fn(usize, *mut u8, usize, *mut usize) -> c_int;
pub type FnGetSeedComponents = unsafe extern "C" fn(usize, *mut u64, c_int, *mut c_int) -> c_int;

pub type FnEncrypt = unsafe extern "C" fn(
    usize,
    usize,
    usize,
    *const c_void,
    usize,
    *mut c_void,
    usize,
    *mut usize,
) -> c_int;
pub type FnDecrypt = FnEncrypt;
pub type FnEncrypt3 = unsafe extern "C" fn(
    usize,
    usize,
    usize,
    usize,
    usize,
    usize,
    usize,
    *const c_void,
    usize,
    *mut c_void,
    usize,
    *mut usize,
) -> c_int;
pub type FnDecrypt3 = FnEncrypt3;

pub type FnMACCount = unsafe extern "C" fn() -> c_int;
pub type FnMACName = unsafe extern "C" fn(c_int, *mut c_char, usize, *mut usize) -> c_int;
pub type FnMACKeySize = unsafe extern "C" fn(c_int) -> c_int;
pub type FnMACTagSize = unsafe extern "C" fn(c_int) -> c_int;
pub type FnMACMinKeyBytes = unsafe extern "C" fn(c_int) -> c_int;
pub type FnNewMAC =
    unsafe extern "C" fn(*const c_char, *const c_void, usize, *mut usize) -> c_int;
pub type FnFreeMAC = unsafe extern "C" fn(usize) -> c_int;

pub type FnEncryptAuth = unsafe extern "C" fn(
    usize,
    usize,
    usize,
    usize,
    *const c_void,
    usize,
    *mut c_void,
    usize,
    *mut usize,
) -> c_int;
pub type FnDecryptAuth = FnEncryptAuth;
pub type FnEncryptAuth3 = unsafe extern "C" fn(
    usize,
    usize,
    usize,
    usize,
    usize,
    usize,
    usize,
    usize,
    *const c_void,
    usize,
    *mut c_void,
    usize,
    *mut usize,
) -> c_int;
pub type FnDecryptAuth3 = FnEncryptAuth3;

// Streaming AEAD per-chunk ABI typedefs — Single (3 seeds + MAC) and
// Triple (7 seeds + MAC) at every native hash width (128 / 256 / 512).
// Encrypt path takes streamID + cumulativePixelOffset + finalFlag in;
// Decrypt path takes streamID + cumulativePixelOffset in and writes
// finalFlagOut.
pub type FnEncryptStreamAuth = unsafe extern "C" fn(
    usize,                  // noiseHandle
    usize,                  // dataHandle
    usize,                  // startHandle
    usize,                  // macHandle
    *const c_void,          // plaintext
    usize,                  // ptlen
    *const u8,              // streamID[32]
    u64,                    // cumulativePixelOffset
    c_int,                  // finalFlag
    *mut c_void,            // out
    usize,                  // outCap
    *mut usize,             // outLen
) -> c_int;
pub type FnDecryptStreamAuth = unsafe extern "C" fn(
    usize,                  // noiseHandle
    usize,                  // dataHandle
    usize,                  // startHandle
    usize,                  // macHandle
    *const c_void,          // ciphertext
    usize,                  // ctlen
    *const u8,              // streamID[32]
    u64,                    // cumulativePixelOffset
    *mut c_void,            // out
    usize,                  // outCap
    *mut usize,             // outLen
    *mut c_int,             // finalFlagOut
) -> c_int;
pub type FnEncryptStreamAuth3 = unsafe extern "C" fn(
    usize,                  // noiseHandle
    usize,                  // dataHandle1
    usize,                  // dataHandle2
    usize,                  // dataHandle3
    usize,                  // startHandle1
    usize,                  // startHandle2
    usize,                  // startHandle3
    usize,                  // macHandle
    *const c_void,          // plaintext
    usize,                  // ptlen
    *const u8,              // streamID[32]
    u64,                    // cumulativePixelOffset
    c_int,                  // finalFlag
    *mut c_void,            // out
    usize,                  // outCap
    *mut usize,             // outLen
) -> c_int;
pub type FnDecryptStreamAuth3 = unsafe extern "C" fn(
    usize,                  // noiseHandle
    usize,                  // dataHandle1
    usize,                  // dataHandle2
    usize,                  // dataHandle3
    usize,                  // startHandle1
    usize,                  // startHandle2
    usize,                  // startHandle3
    usize,                  // macHandle
    *const c_void,          // ciphertext
    usize,                  // ctlen
    *const u8,              // streamID[32]
    u64,                    // cumulativePixelOffset
    *mut c_void,            // out
    usize,                  // outCap
    *mut usize,             // outLen
    *mut c_int,             // finalFlagOut
) -> c_int;

pub type FnEasyEncryptStreamAuth = unsafe extern "C" fn(
    usize,                  // encryptor handle
    *const c_void,          // plaintext
    usize,                  // ptlen
    *const u8,              // streamID[32]
    u64,                    // cumulativePixelOffset
    c_int,                  // finalFlag
    *mut c_void,            // out
    usize,                  // outCap
    *mut usize,             // outLen
) -> c_int;
pub type FnEasyDecryptStreamAuth = unsafe extern "C" fn(
    usize,                  // encryptor handle
    *const c_void,          // ciphertext
    usize,                  // ctlen
    *const u8,              // streamID[32]
    u64,                    // cumulativePixelOffset
    *mut c_void,            // out
    usize,                  // outCap
    *mut usize,             // outLen
    *mut c_int,             // finalFlagOut
) -> c_int;

pub type FnSetBitSoup = unsafe extern "C" fn(c_int) -> c_int;
pub type FnGetBitSoup = unsafe extern "C" fn() -> c_int;
pub type FnSetLockSoup = unsafe extern "C" fn(c_int) -> c_int;
pub type FnGetLockSoup = unsafe extern "C" fn() -> c_int;
pub type FnSetMaxWorkers = unsafe extern "C" fn(c_int) -> c_int;
pub type FnGetMaxWorkers = unsafe extern "C" fn() -> c_int;
pub type FnSetNonceBits = unsafe extern "C" fn(c_int) -> c_int;
pub type FnGetNonceBits = unsafe extern "C" fn() -> c_int;
pub type FnSetBarrierFill = unsafe extern "C" fn(c_int) -> c_int;
pub type FnGetBarrierFill = unsafe extern "C" fn() -> c_int;

pub type FnParseChunkLen =
    unsafe extern "C" fn(*const c_void, usize, *mut usize) -> c_int;
pub type FnMaxKeyBits = unsafe extern "C" fn() -> c_int;
pub type FnChannels = unsafe extern "C" fn() -> c_int;
pub type FnHeaderSize = unsafe extern "C" fn() -> c_int;

pub type FnAttachLockSeed = unsafe extern "C" fn(usize, usize) -> c_int;

// Easy encryptor surface — wraps github.com/everanium/itb/easy.

pub type FnEasyNew = unsafe extern "C" fn(
    *const c_char,
    c_int,
    *const c_char,
    c_int,
    *mut usize,
) -> c_int;
pub type FnEasyNewMixed = unsafe extern "C" fn(
    *const c_char,
    *const c_char,
    *const c_char,
    *const c_char,
    c_int,
    *const c_char,
    *mut usize,
) -> c_int;
pub type FnEasyNewMixed3 = unsafe extern "C" fn(
    *const c_char,
    *const c_char,
    *const c_char,
    *const c_char,
    *const c_char,
    *const c_char,
    *const c_char,
    *const c_char,
    c_int,
    *const c_char,
    *mut usize,
) -> c_int;
pub type FnEasyFree = unsafe extern "C" fn(usize) -> c_int;
pub type FnEasyPrimitiveAt =
    unsafe extern "C" fn(usize, c_int, *mut c_char, usize, *mut usize) -> c_int;
pub type FnEasyIsMixed = unsafe extern "C" fn(usize, *mut c_int) -> c_int;
pub type FnEasyEncrypt = unsafe extern "C" fn(
    usize,
    *const c_void,
    usize,
    *mut c_void,
    usize,
    *mut usize,
) -> c_int;
pub type FnEasyDecrypt = FnEasyEncrypt;
pub type FnEasyEncryptAuth = FnEasyEncrypt;
pub type FnEasyDecryptAuth = FnEasyEncrypt;
pub type FnEasySetNonceBits = unsafe extern "C" fn(usize, c_int) -> c_int;
pub type FnEasySetBarrierFill = unsafe extern "C" fn(usize, c_int) -> c_int;
pub type FnEasySetBitSoup = unsafe extern "C" fn(usize, c_int) -> c_int;
pub type FnEasySetLockSoup = unsafe extern "C" fn(usize, c_int) -> c_int;
pub type FnEasySetLockSeed = unsafe extern "C" fn(usize, c_int) -> c_int;
pub type FnEasySetChunkSize = unsafe extern "C" fn(usize, c_int) -> c_int;
pub type FnEasyPrimitive = unsafe extern "C" fn(usize, *mut c_char, usize, *mut usize) -> c_int;
pub type FnEasyKeyBits = unsafe extern "C" fn(usize, *mut c_int) -> c_int;
pub type FnEasyMode = unsafe extern "C" fn(usize, *mut c_int) -> c_int;
pub type FnEasyMACName = unsafe extern "C" fn(usize, *mut c_char, usize, *mut usize) -> c_int;
pub type FnEasySeedCount = unsafe extern "C" fn(usize, *mut c_int) -> c_int;
pub type FnEasySeedComponents =
    unsafe extern "C" fn(usize, c_int, *mut u64, c_int, *mut c_int) -> c_int;
pub type FnEasyHasPRFKeys = unsafe extern "C" fn(usize, *mut c_int) -> c_int;
pub type FnEasyPRFKey = unsafe extern "C" fn(usize, c_int, *mut u8, usize, *mut usize) -> c_int;
pub type FnEasyMACKey = unsafe extern "C" fn(usize, *mut u8, usize, *mut usize) -> c_int;
pub type FnEasyClose = unsafe extern "C" fn(usize) -> c_int;
pub type FnEasyExport =
    unsafe extern "C" fn(usize, *mut c_void, usize, *mut usize) -> c_int;
pub type FnEasyImport = unsafe extern "C" fn(usize, *const c_void, usize) -> c_int;
pub type FnEasyPeekConfig = unsafe extern "C" fn(
    *const c_void,
    usize,
    *mut c_char,
    usize,
    *mut usize,
    *mut c_int,
    *mut c_int,
    *mut c_char,
    usize,
    *mut usize,
) -> c_int;
pub type FnEasyLastMismatchField =
    unsafe extern "C" fn(*mut c_char, usize, *mut usize) -> c_int;
pub type FnEasyNonceBits = unsafe extern "C" fn(usize, *mut c_int) -> c_int;
pub type FnEasyHeaderSize = unsafe extern "C" fn(usize, *mut c_int) -> c_int;
pub type FnEasyParseChunkLen =
    unsafe extern "C" fn(usize, *const c_void, usize, *mut usize) -> c_int;

// Native Blob — low-level state persistence (itb.Blob128 / 256 / 512).

pub type FnBlob128New = unsafe extern "C" fn(*mut usize) -> c_int;
pub type FnBlob256New = unsafe extern "C" fn(*mut usize) -> c_int;
pub type FnBlob512New = unsafe extern "C" fn(*mut usize) -> c_int;
pub type FnBlobFree = unsafe extern "C" fn(usize) -> c_int;
pub type FnBlobWidth = unsafe extern "C" fn(usize, *mut c_int) -> c_int;
pub type FnBlobMode = unsafe extern "C" fn(usize, *mut c_int) -> c_int;
pub type FnBlobSetKey =
    unsafe extern "C" fn(usize, c_int, *const c_void, usize) -> c_int;
pub type FnBlobGetKey =
    unsafe extern "C" fn(usize, c_int, *mut c_void, usize, *mut usize) -> c_int;
pub type FnBlobSetComponents =
    unsafe extern "C" fn(usize, c_int, *const u64, usize) -> c_int;
pub type FnBlobGetComponents =
    unsafe extern "C" fn(usize, c_int, *mut u64, usize, *mut usize) -> c_int;
pub type FnBlobSetMACKey = unsafe extern "C" fn(usize, *const c_void, usize) -> c_int;
pub type FnBlobGetMACKey = unsafe extern "C" fn(usize, *mut c_void, usize, *mut usize) -> c_int;
pub type FnBlobSetMACName = unsafe extern "C" fn(usize, *const c_char, usize) -> c_int;
pub type FnBlobGetMACName = unsafe extern "C" fn(usize, *mut c_char, usize, *mut usize) -> c_int;
pub type FnBlobExport =
    unsafe extern "C" fn(usize, c_int, *mut c_void, usize, *mut usize) -> c_int;
pub type FnBlobExport3 =
    unsafe extern "C" fn(usize, c_int, *mut c_void, usize, *mut usize) -> c_int;
pub type FnBlobImport = unsafe extern "C" fn(usize, *const c_void, usize) -> c_int;
pub type FnBlobImport3 = unsafe extern "C" fn(usize, *const c_void, usize) -> c_int;

// --------------------------------------------------------------------
// Library handle — process-wide singleton holding cached fn pointers.
// --------------------------------------------------------------------
//
// The Library is held inside this struct and dropped together with it
// on process exit (the OnceLock never explicitly drops, but Library is
// safe to leave loaded — dlclose is implicit at program exit). The fn
// pointers are extracted via dereferencing libloading::Symbol once at
// load time and stored as raw extern fn types; this is sound as long
// as the Library remains alive in the same struct.

pub(crate) struct LibItb {
    pub(crate) ITB_Version: FnVersion,
    pub(crate) ITB_HashCount: FnHashCount,
    pub(crate) ITB_HashName: FnHashName,
    pub(crate) ITB_HashWidth: FnHashWidth,
    pub(crate) ITB_LastError: FnLastError,

    pub(crate) ITB_NewSeed: FnNewSeed,
    pub(crate) ITB_FreeSeed: FnFreeSeed,
    pub(crate) ITB_SeedWidth: FnSeedWidth,
    pub(crate) ITB_SeedHashName: FnSeedHashName,
    pub(crate) ITB_NewSeedFromComponents: FnNewSeedFromComponents,
    pub(crate) ITB_GetSeedHashKey: FnGetSeedHashKey,
    pub(crate) ITB_GetSeedComponents: FnGetSeedComponents,

    pub(crate) ITB_Encrypt: FnEncrypt,
    pub(crate) ITB_Decrypt: FnDecrypt,
    pub(crate) ITB_Encrypt3: FnEncrypt3,
    pub(crate) ITB_Decrypt3: FnDecrypt3,

    pub(crate) ITB_MACCount: FnMACCount,
    pub(crate) ITB_MACName: FnMACName,
    pub(crate) ITB_MACKeySize: FnMACKeySize,
    pub(crate) ITB_MACTagSize: FnMACTagSize,
    pub(crate) ITB_MACMinKeyBytes: FnMACMinKeyBytes,
    pub(crate) ITB_NewMAC: FnNewMAC,
    pub(crate) ITB_FreeMAC: FnFreeMAC,

    pub(crate) ITB_EncryptAuth: FnEncryptAuth,
    pub(crate) ITB_DecryptAuth: FnDecryptAuth,
    pub(crate) ITB_EncryptAuth3: FnEncryptAuth3,
    pub(crate) ITB_DecryptAuth3: FnDecryptAuth3,

    // Streaming AEAD per-chunk ABI — three native hash widths
    // (128 / 256 / 512) for Single Ouroboros and Triple Ouroboros,
    // both encrypt and decrypt. Plus the Easy Mode counterparts that
    // route per-chunk dispatch through the encryptor's bound config.
    pub(crate) ITB_EncryptStreamAuthenticated128: FnEncryptStreamAuth,
    pub(crate) ITB_EncryptStreamAuthenticated256: FnEncryptStreamAuth,
    pub(crate) ITB_EncryptStreamAuthenticated512: FnEncryptStreamAuth,
    pub(crate) ITB_DecryptStreamAuthenticated128: FnDecryptStreamAuth,
    pub(crate) ITB_DecryptStreamAuthenticated256: FnDecryptStreamAuth,
    pub(crate) ITB_DecryptStreamAuthenticated512: FnDecryptStreamAuth,
    pub(crate) ITB_EncryptStreamAuthenticated3x128: FnEncryptStreamAuth3,
    pub(crate) ITB_EncryptStreamAuthenticated3x256: FnEncryptStreamAuth3,
    pub(crate) ITB_EncryptStreamAuthenticated3x512: FnEncryptStreamAuth3,
    pub(crate) ITB_DecryptStreamAuthenticated3x128: FnDecryptStreamAuth3,
    pub(crate) ITB_DecryptStreamAuthenticated3x256: FnDecryptStreamAuth3,
    pub(crate) ITB_DecryptStreamAuthenticated3x512: FnDecryptStreamAuth3,
    pub(crate) ITB_Easy_EncryptStreamAuth: FnEasyEncryptStreamAuth,
    pub(crate) ITB_Easy_DecryptStreamAuth: FnEasyDecryptStreamAuth,

    pub(crate) ITB_SetBitSoup: FnSetBitSoup,
    pub(crate) ITB_GetBitSoup: FnGetBitSoup,
    pub(crate) ITB_SetLockSoup: FnSetLockSoup,
    pub(crate) ITB_GetLockSoup: FnGetLockSoup,
    pub(crate) ITB_SetMaxWorkers: FnSetMaxWorkers,
    pub(crate) ITB_GetMaxWorkers: FnGetMaxWorkers,
    pub(crate) ITB_SetNonceBits: FnSetNonceBits,
    pub(crate) ITB_GetNonceBits: FnGetNonceBits,
    pub(crate) ITB_SetBarrierFill: FnSetBarrierFill,
    pub(crate) ITB_GetBarrierFill: FnGetBarrierFill,

    pub(crate) ITB_ParseChunkLen: FnParseChunkLen,
    pub(crate) ITB_MaxKeyBits: FnMaxKeyBits,
    pub(crate) ITB_Channels: FnChannels,
    pub(crate) ITB_HeaderSize: FnHeaderSize,

    pub(crate) ITB_AttachLockSeed: FnAttachLockSeed,

    pub(crate) ITB_Easy_New: FnEasyNew,
    pub(crate) ITB_Easy_NewMixed: FnEasyNewMixed,
    pub(crate) ITB_Easy_NewMixed3: FnEasyNewMixed3,
    pub(crate) ITB_Easy_Free: FnEasyFree,
    pub(crate) ITB_Easy_PrimitiveAt: FnEasyPrimitiveAt,
    pub(crate) ITB_Easy_IsMixed: FnEasyIsMixed,
    pub(crate) ITB_Easy_Encrypt: FnEasyEncrypt,
    pub(crate) ITB_Easy_Decrypt: FnEasyDecrypt,
    pub(crate) ITB_Easy_EncryptAuth: FnEasyEncryptAuth,
    pub(crate) ITB_Easy_DecryptAuth: FnEasyDecryptAuth,
    pub(crate) ITB_Easy_SetNonceBits: FnEasySetNonceBits,
    pub(crate) ITB_Easy_SetBarrierFill: FnEasySetBarrierFill,
    pub(crate) ITB_Easy_SetBitSoup: FnEasySetBitSoup,
    pub(crate) ITB_Easy_SetLockSoup: FnEasySetLockSoup,
    pub(crate) ITB_Easy_SetLockSeed: FnEasySetLockSeed,
    pub(crate) ITB_Easy_SetChunkSize: FnEasySetChunkSize,
    pub(crate) ITB_Easy_Primitive: FnEasyPrimitive,
    pub(crate) ITB_Easy_KeyBits: FnEasyKeyBits,
    pub(crate) ITB_Easy_Mode: FnEasyMode,
    pub(crate) ITB_Easy_MACName: FnEasyMACName,
    pub(crate) ITB_Easy_SeedCount: FnEasySeedCount,
    pub(crate) ITB_Easy_SeedComponents: FnEasySeedComponents,
    pub(crate) ITB_Easy_HasPRFKeys: FnEasyHasPRFKeys,
    pub(crate) ITB_Easy_PRFKey: FnEasyPRFKey,
    pub(crate) ITB_Easy_MACKey: FnEasyMACKey,
    pub(crate) ITB_Easy_Close: FnEasyClose,
    pub(crate) ITB_Easy_Export: FnEasyExport,
    pub(crate) ITB_Easy_Import: FnEasyImport,
    pub(crate) ITB_Easy_PeekConfig: FnEasyPeekConfig,
    pub(crate) ITB_Easy_LastMismatchField: FnEasyLastMismatchField,
    pub(crate) ITB_Easy_NonceBits: FnEasyNonceBits,
    pub(crate) ITB_Easy_HeaderSize: FnEasyHeaderSize,
    pub(crate) ITB_Easy_ParseChunkLen: FnEasyParseChunkLen,

    pub(crate) ITB_Blob128_New: FnBlob128New,
    pub(crate) ITB_Blob256_New: FnBlob256New,
    pub(crate) ITB_Blob512_New: FnBlob512New,
    pub(crate) ITB_Blob_Free: FnBlobFree,
    pub(crate) ITB_Blob_Width: FnBlobWidth,
    pub(crate) ITB_Blob_Mode: FnBlobMode,
    pub(crate) ITB_Blob_SetKey: FnBlobSetKey,
    pub(crate) ITB_Blob_GetKey: FnBlobGetKey,
    pub(crate) ITB_Blob_SetComponents: FnBlobSetComponents,
    pub(crate) ITB_Blob_GetComponents: FnBlobGetComponents,
    pub(crate) ITB_Blob_SetMACKey: FnBlobSetMACKey,
    pub(crate) ITB_Blob_GetMACKey: FnBlobGetMACKey,
    pub(crate) ITB_Blob_SetMACName: FnBlobSetMACName,
    pub(crate) ITB_Blob_GetMACName: FnBlobGetMACName,
    pub(crate) ITB_Blob_Export: FnBlobExport,
    pub(crate) ITB_Blob_Export3: FnBlobExport3,
    pub(crate) ITB_Blob_Import: FnBlobImport,
    pub(crate) ITB_Blob_Import3: FnBlobImport3,

    // Library kept alive for the lifetime of the singleton so the
    // raw fn pointers above stay valid. Declared LAST so it drops
    // AFTER every fn-pointer field (Rust drops fields in declaration
    // order).
    _lib: Library,
}

// SAFETY: every fn pointer is `unsafe extern "C" fn(...)` — these are
// `Copy` and immutable after load. The underlying Library exposes no
// interior mutability; concurrent reads of the cached fn pointers are
// safe across threads. Status-code returns and process-wide errno-like
// state inside libitb are documented as racy under multi-thread use;
// that race is at the libitb layer, not at the symbol-pointer layer.
unsafe impl Send for LibItb {}
unsafe impl Sync for LibItb {}

static LIB: OnceLock<LibItb> = OnceLock::new();

/// Returns the process-wide library handle, loading it on first call.
///
/// Panics with a descriptive message if the library cannot be located
/// or any expected symbol is missing. The eager-load policy surfaces
/// misconfigured library paths and ABI mismatches at the first use of
/// any FFI entry point rather than at the failing call site.
pub(crate) fn lib() -> &'static LibItb {
    LIB.get_or_init(|| match unsafe { LibItb::load() } {
        Ok(l) => l,
        Err(e) => panic!("itb: failed to load libitb: {e}"),
    })
}

impl LibItb {
    unsafe fn load() -> Result<Self, libloading::Error> {
        let path = resolve_library_path();
        let lib = unsafe { Library::new(&path)? };
        unsafe {
            // Each Symbol borrows from `lib`; dereferencing yields the
            // raw fn pointer, which is `Copy` and remains valid for as
            // long as `lib` itself stays alive. Storing the raw fn
            // pointer alongside the Library inside this struct keeps
            // the contract sound.
            macro_rules! sym {
                ($name:expr) => {{
                    let s: libloading::Symbol<_> = lib.get($name)?;
                    *s
                }};
            }
            Ok(Self {
                ITB_Version: sym!(b"ITB_Version"),
                ITB_HashCount: sym!(b"ITB_HashCount"),
                ITB_HashName: sym!(b"ITB_HashName"),
                ITB_HashWidth: sym!(b"ITB_HashWidth"),
                ITB_LastError: sym!(b"ITB_LastError"),

                ITB_NewSeed: sym!(b"ITB_NewSeed"),
                ITB_FreeSeed: sym!(b"ITB_FreeSeed"),
                ITB_SeedWidth: sym!(b"ITB_SeedWidth"),
                ITB_SeedHashName: sym!(b"ITB_SeedHashName"),
                ITB_NewSeedFromComponents: sym!(b"ITB_NewSeedFromComponents"),
                ITB_GetSeedHashKey: sym!(b"ITB_GetSeedHashKey"),
                ITB_GetSeedComponents: sym!(b"ITB_GetSeedComponents"),

                ITB_Encrypt: sym!(b"ITB_Encrypt"),
                ITB_Decrypt: sym!(b"ITB_Decrypt"),
                ITB_Encrypt3: sym!(b"ITB_Encrypt3"),
                ITB_Decrypt3: sym!(b"ITB_Decrypt3"),

                ITB_MACCount: sym!(b"ITB_MACCount"),
                ITB_MACName: sym!(b"ITB_MACName"),
                ITB_MACKeySize: sym!(b"ITB_MACKeySize"),
                ITB_MACTagSize: sym!(b"ITB_MACTagSize"),
                ITB_MACMinKeyBytes: sym!(b"ITB_MACMinKeyBytes"),
                ITB_NewMAC: sym!(b"ITB_NewMAC"),
                ITB_FreeMAC: sym!(b"ITB_FreeMAC"),

                ITB_EncryptAuth: sym!(b"ITB_EncryptAuth"),
                ITB_DecryptAuth: sym!(b"ITB_DecryptAuth"),
                ITB_EncryptAuth3: sym!(b"ITB_EncryptAuth3"),
                ITB_DecryptAuth3: sym!(b"ITB_DecryptAuth3"),

                ITB_EncryptStreamAuthenticated128: sym!(b"ITB_EncryptStreamAuthenticated128"),
                ITB_EncryptStreamAuthenticated256: sym!(b"ITB_EncryptStreamAuthenticated256"),
                ITB_EncryptStreamAuthenticated512: sym!(b"ITB_EncryptStreamAuthenticated512"),
                ITB_DecryptStreamAuthenticated128: sym!(b"ITB_DecryptStreamAuthenticated128"),
                ITB_DecryptStreamAuthenticated256: sym!(b"ITB_DecryptStreamAuthenticated256"),
                ITB_DecryptStreamAuthenticated512: sym!(b"ITB_DecryptStreamAuthenticated512"),
                ITB_EncryptStreamAuthenticated3x128: sym!(b"ITB_EncryptStreamAuthenticated3x128"),
                ITB_EncryptStreamAuthenticated3x256: sym!(b"ITB_EncryptStreamAuthenticated3x256"),
                ITB_EncryptStreamAuthenticated3x512: sym!(b"ITB_EncryptStreamAuthenticated3x512"),
                ITB_DecryptStreamAuthenticated3x128: sym!(b"ITB_DecryptStreamAuthenticated3x128"),
                ITB_DecryptStreamAuthenticated3x256: sym!(b"ITB_DecryptStreamAuthenticated3x256"),
                ITB_DecryptStreamAuthenticated3x512: sym!(b"ITB_DecryptStreamAuthenticated3x512"),
                ITB_Easy_EncryptStreamAuth: sym!(b"ITB_Easy_EncryptStreamAuth"),
                ITB_Easy_DecryptStreamAuth: sym!(b"ITB_Easy_DecryptStreamAuth"),

                ITB_SetBitSoup: sym!(b"ITB_SetBitSoup"),
                ITB_GetBitSoup: sym!(b"ITB_GetBitSoup"),
                ITB_SetLockSoup: sym!(b"ITB_SetLockSoup"),
                ITB_GetLockSoup: sym!(b"ITB_GetLockSoup"),
                ITB_SetMaxWorkers: sym!(b"ITB_SetMaxWorkers"),
                ITB_GetMaxWorkers: sym!(b"ITB_GetMaxWorkers"),
                ITB_SetNonceBits: sym!(b"ITB_SetNonceBits"),
                ITB_GetNonceBits: sym!(b"ITB_GetNonceBits"),
                ITB_SetBarrierFill: sym!(b"ITB_SetBarrierFill"),
                ITB_GetBarrierFill: sym!(b"ITB_GetBarrierFill"),

                ITB_ParseChunkLen: sym!(b"ITB_ParseChunkLen"),
                ITB_MaxKeyBits: sym!(b"ITB_MaxKeyBits"),
                ITB_Channels: sym!(b"ITB_Channels"),
                ITB_HeaderSize: sym!(b"ITB_HeaderSize"),

                ITB_AttachLockSeed: sym!(b"ITB_AttachLockSeed"),

                ITB_Easy_New: sym!(b"ITB_Easy_New"),
                ITB_Easy_NewMixed: sym!(b"ITB_Easy_NewMixed"),
                ITB_Easy_NewMixed3: sym!(b"ITB_Easy_NewMixed3"),
                ITB_Easy_Free: sym!(b"ITB_Easy_Free"),
                ITB_Easy_PrimitiveAt: sym!(b"ITB_Easy_PrimitiveAt"),
                ITB_Easy_IsMixed: sym!(b"ITB_Easy_IsMixed"),
                ITB_Easy_Encrypt: sym!(b"ITB_Easy_Encrypt"),
                ITB_Easy_Decrypt: sym!(b"ITB_Easy_Decrypt"),
                ITB_Easy_EncryptAuth: sym!(b"ITB_Easy_EncryptAuth"),
                ITB_Easy_DecryptAuth: sym!(b"ITB_Easy_DecryptAuth"),
                ITB_Easy_SetNonceBits: sym!(b"ITB_Easy_SetNonceBits"),
                ITB_Easy_SetBarrierFill: sym!(b"ITB_Easy_SetBarrierFill"),
                ITB_Easy_SetBitSoup: sym!(b"ITB_Easy_SetBitSoup"),
                ITB_Easy_SetLockSoup: sym!(b"ITB_Easy_SetLockSoup"),
                ITB_Easy_SetLockSeed: sym!(b"ITB_Easy_SetLockSeed"),
                ITB_Easy_SetChunkSize: sym!(b"ITB_Easy_SetChunkSize"),
                ITB_Easy_Primitive: sym!(b"ITB_Easy_Primitive"),
                ITB_Easy_KeyBits: sym!(b"ITB_Easy_KeyBits"),
                ITB_Easy_Mode: sym!(b"ITB_Easy_Mode"),
                ITB_Easy_MACName: sym!(b"ITB_Easy_MACName"),
                ITB_Easy_SeedCount: sym!(b"ITB_Easy_SeedCount"),
                ITB_Easy_SeedComponents: sym!(b"ITB_Easy_SeedComponents"),
                ITB_Easy_HasPRFKeys: sym!(b"ITB_Easy_HasPRFKeys"),
                ITB_Easy_PRFKey: sym!(b"ITB_Easy_PRFKey"),
                ITB_Easy_MACKey: sym!(b"ITB_Easy_MACKey"),
                ITB_Easy_Close: sym!(b"ITB_Easy_Close"),
                ITB_Easy_Export: sym!(b"ITB_Easy_Export"),
                ITB_Easy_Import: sym!(b"ITB_Easy_Import"),
                ITB_Easy_PeekConfig: sym!(b"ITB_Easy_PeekConfig"),
                ITB_Easy_LastMismatchField: sym!(b"ITB_Easy_LastMismatchField"),
                ITB_Easy_NonceBits: sym!(b"ITB_Easy_NonceBits"),
                ITB_Easy_HeaderSize: sym!(b"ITB_Easy_HeaderSize"),
                ITB_Easy_ParseChunkLen: sym!(b"ITB_Easy_ParseChunkLen"),

                ITB_Blob128_New: sym!(b"ITB_Blob128_New"),
                ITB_Blob256_New: sym!(b"ITB_Blob256_New"),
                ITB_Blob512_New: sym!(b"ITB_Blob512_New"),
                ITB_Blob_Free: sym!(b"ITB_Blob_Free"),
                ITB_Blob_Width: sym!(b"ITB_Blob_Width"),
                ITB_Blob_Mode: sym!(b"ITB_Blob_Mode"),
                ITB_Blob_SetKey: sym!(b"ITB_Blob_SetKey"),
                ITB_Blob_GetKey: sym!(b"ITB_Blob_GetKey"),
                ITB_Blob_SetComponents: sym!(b"ITB_Blob_SetComponents"),
                ITB_Blob_GetComponents: sym!(b"ITB_Blob_GetComponents"),
                ITB_Blob_SetMACKey: sym!(b"ITB_Blob_SetMACKey"),
                ITB_Blob_GetMACKey: sym!(b"ITB_Blob_GetMACKey"),
                ITB_Blob_SetMACName: sym!(b"ITB_Blob_SetMACName"),
                ITB_Blob_GetMACName: sym!(b"ITB_Blob_GetMACName"),
                ITB_Blob_Export: sym!(b"ITB_Blob_Export"),
                ITB_Blob_Export3: sym!(b"ITB_Blob_Export3"),
                ITB_Blob_Import: sym!(b"ITB_Blob_Import"),
                ITB_Blob_Import3: sym!(b"ITB_Blob_Import3"),

                _lib: lib,
            })
        }
    }
}

// --------------------------------------------------------------------
// Library-path resolution.
// --------------------------------------------------------------------

fn platform_lib_dir() -> &'static str {
    // Maps Rust target_os / target_arch to the dist/ subfolder naming
    // convention used by cmd/cshared builds.
    #[cfg(target_os = "linux")]
    let sysname = "linux";
    #[cfg(target_os = "macos")]
    let sysname = "darwin";
    #[cfg(target_os = "windows")]
    let sysname = "windows";
    #[cfg(target_os = "freebsd")]
    let sysname = "freebsd";
    #[cfg(not(any(
        target_os = "linux",
        target_os = "macos",
        target_os = "windows",
        target_os = "freebsd"
    )))]
    let sysname = "linux";

    #[cfg(target_arch = "x86_64")]
    let arch = "amd64";
    #[cfg(target_arch = "aarch64")]
    let arch = "arm64";
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    let arch = "amd64";

    // Concatenated at compile time per target-tuple combination.
    match (sysname, arch) {
        ("linux", "amd64") => "linux-amd64",
        ("linux", "arm64") => "linux-arm64",
        ("darwin", "amd64") => "darwin-amd64",
        ("darwin", "arm64") => "darwin-arm64",
        ("windows", "amd64") => "windows-amd64",
        ("windows", "arm64") => "windows-arm64",
        ("freebsd", "amd64") => "freebsd-amd64",
        ("freebsd", "arm64") => "freebsd-arm64",
        _ => "linux-amd64",
    }
}

fn lib_filename() -> &'static str {
    #[cfg(target_os = "macos")]
    {
        "libitb.dylib"
    }
    #[cfg(target_os = "windows")]
    {
        "libitb.dll"
    }
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    {
        "libitb.so"
    }
}

fn resolve_library_path() -> PathBuf {
    if let Ok(env) = std::env::var("ITB_LIBRARY_PATH") {
        return PathBuf::from(env);
    }
    // CARGO_MANIFEST_DIR is `<repo>/bindings/rust/`; repo root is two
    // directory levels up.
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    if let Some(repo) = manifest.parent().and_then(|p| p.parent()) {
        let candidate = repo
            .join("dist")
            .join(platform_lib_dir())
            .join(lib_filename());
        if candidate.exists() {
            return candidate;
        }
    }
    // Last resort: hand the bare filename to the system loader.
    PathBuf::from(lib_filename())
}
