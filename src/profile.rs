//! The profile record — the JSON object libitb3 accepts in
//! [`crate::register`], returns from [`crate::lookup`] and
//! [`crate::inspect`], and embeds in every blob.
//!
//! The record is a plain data carrier: no field is validated on the
//! Rust side. Field rules (mode / width / hash-width agreement, MAC
//! name, palette contents, …) are enforced by libitb3 at `register`
//! and `load`; a rejected record surfaces as [`crate::ItbError`]
//! carrying the status code plus the `ITB_LastError` diagnostic.

use serde::{Deserialize, Serialize};

/// Resolved shape of a Triple Pipeline. Serialises to the libitb3
/// profile JSON object; optional keys are omitted when empty / zero
/// and decode as their defaults when absent.
///
/// `nonce_bits` and `barrier_fill` are inspection-only: they are not
/// part of the profile recipe, carry `None` on a record from
/// [`crate::lookup`] or built by hand, and are populated only on a
/// record from [`crate::inspect`], where libitb3 reads them from the
/// blob's runtime globals snapshot. libitb3 rejects a `register`
/// payload that carries either key, so clear both before handing an
/// inspected record to [`crate::register`].
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Profile {
    /// Registry label. Empty on a record built by hand; filled by
    /// `lookup` / `inspect`. When non-empty it must equal the `name`
    /// argument of `register`.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub name: String,
    /// Pipeline mode (`singlemsg-mac`, `singlemsg-nomac`,
    /// `streaming-aead`, `streaming-noaead`, `blob-only`).
    #[serde(default)]
    pub mode: String,
    /// Inner hash width in bits (128 / 256 / 512).
    #[serde(default)]
    pub width: i64,
    /// Single inner-hash primitive name; empty on a mixed profile.
    #[serde(default, rename = "hash", skip_serializing_if = "String::is_empty")]
    pub inner_hash: String,
    /// Eight-slot inner-hash constellation for mixed profiles; empty
    /// on a single-primitive profile.
    #[serde(default, rename = "hashes", skip_serializing_if = "Vec::is_empty")]
    pub mixed_hashes: Vec<String>,
    /// Session key width in bits.
    #[serde(default, rename = "keybits")]
    pub key_bits: i64,
    /// On-wire nonce width in bits, read from the blob's runtime
    /// globals. Inspection-only: `Some` on an `inspect` record,
    /// `None` on a `lookup` record and on one built by hand.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nonce_bits: Option<i64>,
    /// DRBG barrier fill margin, read from the blob's runtime
    /// globals. Same inspection-only lifecycle as [`Profile::nonce_bits`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub barrier_fill: Option<i64>,
    /// MAC name; empty for No MAC modes.
    #[serde(default, rename = "mac", skip_serializing_if = "String::is_empty")]
    pub mac_name: String,
    /// MAC tag stub size; 0 for the profile default.
    #[serde(default, rename = "tagstub", skip_serializing_if = "is_zero")]
    pub tag_stub_size: i64,
    /// Streaming chunk size; 0 for the library default.
    #[serde(default, rename = "chunk", skip_serializing_if = "is_zero")]
    pub chunk_size: i64,
    /// Whether the format-deniability wrapper layer is on.
    #[serde(default)]
    pub wrapper: bool,
    /// Outer cipher name; empty when the wrapper layer is off.
    #[serde(default, rename = "outer", skip_serializing_if = "String::is_empty")]
    pub outer_cipher: String,
    /// Whether the parallax layer is on.
    #[serde(default)]
    pub parallax: bool,
    /// Parallax palette; empty when the parallax layer is off.
    #[serde(default, rename = "palette", skip_serializing_if = "Vec::is_empty")]
    pub parallax_palette: Vec<String>,
    /// Parallax segment size; 0 for the library default.
    #[serde(default, rename = "segment", skip_serializing_if = "is_zero")]
    pub parallax_segment_size: i64,
}

fn is_zero(v: &i64) -> bool {
    *v == 0
}

impl Profile {
    /// Decodes a profile JSON object as returned by libitb3.
    pub fn from_json(json: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json)
    }

    /// Encodes the record as the profile JSON object libitb3 accepts.
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).expect("Profile serialises without error")
    }
}
