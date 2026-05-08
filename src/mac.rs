//! ITB MAC handle.
//!
//! Provides a thin RAII wrapper over `ITB_NewMAC` / `ITB_FreeMAC`
//! for use with the authenticated encrypt / decrypt entry points.

use std::ffi::{c_void, CString};

use crate::error::{check, ITBError};
use crate::ffi;

/// A handle to one keyed MAC.
///
/// Construct via [`MAC::new`] with a canonical MAC name from
/// [`crate::list_macs`]: `"kmac256"`, `"hmac-sha256"`, or
/// `"hmac-blake3"`.
///
/// Key length must meet the primitive's `min_key_bytes` requirement
/// (16 for `kmac256` / `hmac-sha256`, 32 for `hmac-blake3`).
pub struct MAC {
    handle: usize,
    name: String,
}

impl MAC {
    /// Constructs a fresh MAC handle.
    pub fn new(mac_name: &str, key: &[u8]) -> Result<Self, ITBError> {
        let lib = ffi::lib();
        let cname = CString::new(mac_name).map_err(|_| {
            ITBError::with_message(ffi::STATUS_BAD_INPUT, "mac_name contains NUL")
        })?;
        let mut handle: usize = 0;
        let key_ptr = if key.is_empty() {
            std::ptr::null()
        } else {
            key.as_ptr() as *const c_void
        };
        let rc = unsafe {
            (lib.ITB_NewMAC)(cname.as_ptr(), key_ptr, key.len(), &mut handle)
        };
        check(rc)?;
        Ok(Self {
            handle,
            name: mac_name.to_owned(),
        })
    }

    /// Returns the raw libitb handle.
    pub fn handle(&self) -> usize {
        self.handle
    }

    /// Returns the canonical MAC name this handle was constructed with.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Explicitly releases the underlying handle. Idempotent.
    pub fn free(mut self) -> Result<(), ITBError> {
        if self.handle != 0 {
            let lib = ffi::lib();
            let rc = unsafe { (lib.ITB_FreeMAC)(self.handle) };
            self.handle = 0;
            check(rc)
        } else {
            Ok(())
        }
    }
}

impl Drop for MAC {
    fn drop(&mut self) {
        if self.handle != 0 {
            let lib = ffi::lib();
            unsafe {
                let _ = (lib.ITB_FreeMAC)(self.handle);
            }
            self.handle = 0;
        }
    }
}
