//! Low-level encrypt / decrypt entry points.
//!
//! Exposes the libitb encrypt / decrypt surface as free functions:
//! [`encrypt`] / [`decrypt`] over a (noise, data, start) Single
//! Ouroboros seed trio, [`encrypt_triple`] / [`decrypt_triple`] over a
//! seven-seed Triple Ouroboros configuration, and the four
//! authenticated `*_auth` variants that take an additional [`MAC`]
//! handle.
//!
//! Empty plaintext / ciphertext is rejected by libitb itself with
//! [`ffi::STATUS_ENCRYPT_FAILED`](crate::ffi::STATUS_ENCRYPT_FAILED)
//! (the Go-side `Encrypt128` / `Decrypt128` family returns
//! `"itb: empty data"` before any work). The binding propagates the
//! rejection verbatim — pass at least one byte.

use std::ffi::c_void;

use crate::error::{check, ITBError};
use crate::ffi;
use crate::mac::MAC;
use crate::seed::Seed;

// --------------------------------------------------------------------
// Single Ouroboros — three seeds.
// --------------------------------------------------------------------

/// Encrypts `plaintext` under the (noise, data, start) seed trio.
///
/// All three seeds must share the same native hash width.
pub fn encrypt(
    noise: &Seed,
    data: &Seed,
    start: &Seed,
    plaintext: &[u8],
) -> Result<Vec<u8>, ITBError> {
    enc_dec(EncFn::Single(ffi::lib().ITB_Encrypt), noise, data, start, plaintext)
}

/// Decrypts ciphertext produced by [`encrypt`] under the same seed
/// trio.
pub fn decrypt(
    noise: &Seed,
    data: &Seed,
    start: &Seed,
    ciphertext: &[u8],
) -> Result<Vec<u8>, ITBError> {
    enc_dec(EncFn::Single(ffi::lib().ITB_Decrypt), noise, data, start, ciphertext)
}

// --------------------------------------------------------------------
// Triple Ouroboros — seven seeds.
// --------------------------------------------------------------------

/// Triple Ouroboros encrypt over seven seeds.
///
/// Splits plaintext across three interleaved snake payloads. The
/// on-wire ciphertext format is the same shape as [`encrypt`] — only
/// the internal split / interleave differs. All seven seeds must
/// share the same native hash width and be pairwise distinct handles
/// (the underlying ITB API enforces seven-seed isolation).
#[allow(clippy::too_many_arguments)]
pub fn encrypt_triple(
    noise: &Seed,
    data1: &Seed,
    data2: &Seed,
    data3: &Seed,
    start1: &Seed,
    start2: &Seed,
    start3: &Seed,
    plaintext: &[u8],
) -> Result<Vec<u8>, ITBError> {
    enc_dec_triple(
        ffi::lib().ITB_Encrypt3,
        noise, data1, data2, data3, start1, start2, start3, plaintext,
    )
}

/// Inverse of [`encrypt_triple`].
#[allow(clippy::too_many_arguments)]
pub fn decrypt_triple(
    noise: &Seed,
    data1: &Seed,
    data2: &Seed,
    data3: &Seed,
    start1: &Seed,
    start2: &Seed,
    start3: &Seed,
    ciphertext: &[u8],
) -> Result<Vec<u8>, ITBError> {
    enc_dec_triple(
        ffi::lib().ITB_Decrypt3,
        noise, data1, data2, data3, start1, start2, start3, ciphertext,
    )
}

// --------------------------------------------------------------------
// Authenticated Single — three seeds + MAC.
// --------------------------------------------------------------------

/// Authenticated single-Ouroboros encrypt with MAC-Inside-Encrypt.
pub fn encrypt_auth(
    noise: &Seed,
    data: &Seed,
    start: &Seed,
    mac: &MAC,
    plaintext: &[u8],
) -> Result<Vec<u8>, ITBError> {
    enc_dec_auth(
        ffi::lib().ITB_EncryptAuth,
        noise, data, start, mac, plaintext,
    )
}

/// Authenticated single-Ouroboros decrypt. Returns
/// `ITBError(STATUS_MAC_FAILURE)` on tampered ciphertext or wrong MAC
/// key.
pub fn decrypt_auth(
    noise: &Seed,
    data: &Seed,
    start: &Seed,
    mac: &MAC,
    ciphertext: &[u8],
) -> Result<Vec<u8>, ITBError> {
    enc_dec_auth(
        ffi::lib().ITB_DecryptAuth,
        noise, data, start, mac, ciphertext,
    )
}

// --------------------------------------------------------------------
// Authenticated Triple — seven seeds + MAC.
// --------------------------------------------------------------------

/// Authenticated Triple Ouroboros encrypt (7 seeds + MAC).
#[allow(clippy::too_many_arguments)]
pub fn encrypt_auth_triple(
    noise: &Seed,
    data1: &Seed,
    data2: &Seed,
    data3: &Seed,
    start1: &Seed,
    start2: &Seed,
    start3: &Seed,
    mac: &MAC,
    plaintext: &[u8],
) -> Result<Vec<u8>, ITBError> {
    enc_dec_auth_triple(
        ffi::lib().ITB_EncryptAuth3,
        noise, data1, data2, data3, start1, start2, start3, mac, plaintext,
    )
}

/// Authenticated Triple Ouroboros decrypt.
#[allow(clippy::too_many_arguments)]
pub fn decrypt_auth_triple(
    noise: &Seed,
    data1: &Seed,
    data2: &Seed,
    data3: &Seed,
    start1: &Seed,
    start2: &Seed,
    start3: &Seed,
    mac: &MAC,
    ciphertext: &[u8],
) -> Result<Vec<u8>, ITBError> {
    enc_dec_auth_triple(
        ffi::lib().ITB_DecryptAuth3,
        noise, data1, data2, data3, start1, start2, start3, mac, ciphertext,
    )
}

// --------------------------------------------------------------------
// Internal helpers — probe / allocate / write idiom.
// --------------------------------------------------------------------

/// Wraps the Single-Ouroboros encrypt-vs-decrypt fn-pointer choice so
/// the inner helper can be shared.
enum EncFn {
    Single(ffi::FnEncrypt),
}

fn enc_dec(
    f: EncFn,
    noise: &Seed,
    data: &Seed,
    start: &Seed,
    payload: &[u8],
) -> Result<Vec<u8>, ITBError> {
    let EncFn::Single(fn_ptr) = f;
    let payload_len = payload.len();
    let in_ptr = if payload_len == 0 {
        std::ptr::null()
    } else {
        payload.as_ptr() as *const c_void
    };
    // 1.25× + 128 KiB headroom — see Encryptor::cipher_call for the
    // measured-margin rationale. Skips the size-probe round-trip the
    // libitb C ABI charges (the cipher does the full crypto on every
    // call regardless of out-buffer capacity, then returns
    // BUFFER_TOO_SMALL without exposing the work — so probe-then-retry
    // doubles cipher work per call). The retry on BUFFER_TOO_SMALL
    // remains as the safety net for any future barrier-fill /
    // nonce-bits combination outside the measured matrix.
    let cap = std::cmp::max(131072, payload_len.saturating_mul(5) / 4 + 131072);
    let mut out = vec![0u8; cap];
    let mut out_len: usize = 0;
    let mut rc = unsafe {
        fn_ptr(
            noise.handle(),
            data.handle(),
            start.handle(),
            in_ptr,
            payload_len,
            out.as_mut_ptr() as *mut c_void,
            out.len(),
            &mut out_len,
        )
    };
    if rc == ffi::STATUS_BUFFER_TOO_SMALL {
        let need = out_len;
        out = vec![0u8; need];
        rc = unsafe {
            fn_ptr(
                noise.handle(),
                data.handle(),
                start.handle(),
                in_ptr,
                payload_len,
                out.as_mut_ptr() as *mut c_void,
                out.len(),
                &mut out_len,
            )
        };
    }
    check(rc)?;
    out.truncate(out_len);
    Ok(out)
}

#[allow(clippy::too_many_arguments)]
fn enc_dec_triple(
    fn_ptr: ffi::FnEncrypt3,
    noise: &Seed,
    data1: &Seed,
    data2: &Seed,
    data3: &Seed,
    start1: &Seed,
    start2: &Seed,
    start3: &Seed,
    payload: &[u8],
) -> Result<Vec<u8>, ITBError> {
    let payload_len = payload.len();
    let in_ptr = if payload_len == 0 {
        std::ptr::null()
    } else {
        payload.as_ptr() as *const c_void
    };
    // 1.25× + 128 KiB headroom; see Encryptor::cipher_call.
    let cap = std::cmp::max(131072, payload_len.saturating_mul(5) / 4 + 131072);
    let mut out = vec![0u8; cap];
    let mut out_len: usize = 0;
    let mut rc = unsafe {
        fn_ptr(
            noise.handle(),
            data1.handle(),
            data2.handle(),
            data3.handle(),
            start1.handle(),
            start2.handle(),
            start3.handle(),
            in_ptr,
            payload_len,
            out.as_mut_ptr() as *mut c_void,
            out.len(),
            &mut out_len,
        )
    };
    if rc == ffi::STATUS_BUFFER_TOO_SMALL {
        let need = out_len;
        out = vec![0u8; need];
        rc = unsafe {
            fn_ptr(
                noise.handle(),
                data1.handle(),
                data2.handle(),
                data3.handle(),
                start1.handle(),
                start2.handle(),
                start3.handle(),
                in_ptr,
                payload_len,
                out.as_mut_ptr() as *mut c_void,
                out.len(),
                &mut out_len,
            )
        };
    }
    check(rc)?;
    out.truncate(out_len);
    Ok(out)
}

fn enc_dec_auth(
    fn_ptr: ffi::FnEncryptAuth,
    noise: &Seed,
    data: &Seed,
    start: &Seed,
    mac: &MAC,
    payload: &[u8],
) -> Result<Vec<u8>, ITBError> {
    let payload_len = payload.len();
    let in_ptr = if payload_len == 0 {
        std::ptr::null()
    } else {
        payload.as_ptr() as *const c_void
    };
    // 1.25× + 128 KiB headroom; see Encryptor::cipher_call.
    let cap = std::cmp::max(131072, payload_len.saturating_mul(5) / 4 + 131072);
    let mut out = vec![0u8; cap];
    let mut out_len: usize = 0;
    let mut rc = unsafe {
        fn_ptr(
            noise.handle(),
            data.handle(),
            start.handle(),
            mac.handle(),
            in_ptr,
            payload_len,
            out.as_mut_ptr() as *mut c_void,
            out.len(),
            &mut out_len,
        )
    };
    if rc == ffi::STATUS_BUFFER_TOO_SMALL {
        let need = out_len;
        out = vec![0u8; need];
        rc = unsafe {
            fn_ptr(
                noise.handle(),
                data.handle(),
                start.handle(),
                mac.handle(),
                in_ptr,
                payload_len,
                out.as_mut_ptr() as *mut c_void,
                out.len(),
                &mut out_len,
            )
        };
    }
    check(rc)?;
    out.truncate(out_len);
    Ok(out)
}

#[allow(clippy::too_many_arguments)]
fn enc_dec_auth_triple(
    fn_ptr: ffi::FnEncryptAuth3,
    noise: &Seed,
    data1: &Seed,
    data2: &Seed,
    data3: &Seed,
    start1: &Seed,
    start2: &Seed,
    start3: &Seed,
    mac: &MAC,
    payload: &[u8],
) -> Result<Vec<u8>, ITBError> {
    let payload_len = payload.len();
    let in_ptr = if payload_len == 0 {
        std::ptr::null()
    } else {
        payload.as_ptr() as *const c_void
    };
    // 1.25× + 128 KiB headroom; see Encryptor::cipher_call.
    let cap = std::cmp::max(131072, payload_len.saturating_mul(5) / 4 + 131072);
    let mut out = vec![0u8; cap];
    let mut out_len: usize = 0;
    let mut rc = unsafe {
        fn_ptr(
            noise.handle(),
            data1.handle(),
            data2.handle(),
            data3.handle(),
            start1.handle(),
            start2.handle(),
            start3.handle(),
            mac.handle(),
            in_ptr,
            payload_len,
            out.as_mut_ptr() as *mut c_void,
            out.len(),
            &mut out_len,
        )
    };
    if rc == ffi::STATUS_BUFFER_TOO_SMALL {
        let need = out_len;
        out = vec![0u8; need];
        rc = unsafe {
            fn_ptr(
                noise.handle(),
                data1.handle(),
                data2.handle(),
                data3.handle(),
                start1.handle(),
                start2.handle(),
                start3.handle(),
                mac.handle(),
                in_ptr,
                payload_len,
                out.as_mut_ptr() as *mut c_void,
                out.len(),
                &mut out_len,
            )
        };
    }
    check(rc)?;
    out.truncate(out_len);
    Ok(out)
}
