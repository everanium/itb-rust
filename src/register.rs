//! Profile registry access: register / lookup / profiles.

use std::ffi::CString;

use crate::error::{ItbError, ItbResult, check};
use crate::ffi;
use crate::profile::Profile;

/// Floor capacity for the JSON output buffers of lookup / profiles.
const JSON_CAP: usize = 4096;

/// Registers a user-defined Triple profile under `name` so subsequent
/// [`crate::Pipeline::init`] calls resolve it. The record's field
/// rules are validated by libitb3; a duplicate name fails with
/// [`crate::ItbStatus::ProfileExists`]. A non-empty `profile.name`
/// must equal `name`.
pub fn register(name: &str, profile: &Profile) -> ItbResult<()> {
    let s = ffi::syms()?;
    let name_c = CString::new(name).map_err(|_| ItbError::Ffi("profile name contains NUL"))?;
    let json_c = CString::new(profile.to_json())
        .map_err(|_| ItbError::Ffi("profile JSON contains NUL"))?;
    // SAFETY: both pointers are NUL-terminated strings live for the
    // duration of the call.
    check(unsafe { (s.ITB_Triple_Register)(name_c.as_ptr(), json_c.as_ptr()) })
}

/// Returns the profile registered under `name` — a shipped catalogue
/// entry or a prior [`register`] call. An unregistered name fails with
/// [`crate::ItbStatus::UnknownProfile`].
pub fn lookup(name: &str) -> ItbResult<Profile> {
    let s = ffi::syms()?;
    let name_c = CString::new(name).map_err(|_| ItbError::Ffi("profile name contains NUL"))?;
    let json = crate::pipeline::retry_once(JSON_CAP, |buf, len| {
        // SAFETY: name_c is a live NUL-terminated string; buf / len are
        // valid for the duration of the call.
        unsafe { (s.ITB_Triple_Lookup)(name_c.as_ptr(), buf.as_mut_ptr().cast(), buf.len(), len) }
    })?;
    parse_profile(&json)
}

/// Returns the sorted list of every registered profile name.
pub fn profiles() -> ItbResult<Vec<String>> {
    let s = ffi::syms()?;
    let json = crate::pipeline::retry_once(JSON_CAP, |buf, len| {
        // SAFETY: buf / len are valid for the duration of the call.
        unsafe { (s.ITB_Triple_Profiles)(buf.as_mut_ptr().cast(), buf.len(), len) }
    })?;
    let text = std::str::from_utf8(&json).map_err(ItbError::Utf8)?;
    serde_json::from_str(text).map_err(|_| ItbError::Ffi("profile list is not a JSON string array"))
}

pub(crate) fn parse_profile(json: &[u8]) -> ItbResult<Profile> {
    let text = std::str::from_utf8(json).map_err(ItbError::Utf8)?;
    Profile::from_json(text).map_err(|_| ItbError::Ffi("profile record is not valid JSON"))
}
