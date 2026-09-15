//! URL-query builder for the opts pass-through string.
//!
//! The builder performs no validation — every key and value is
//! rendered into a percent-encoded query string and passed through to
//! Go verbatim; libitb3 rejects unknown keys or bad values with a
//! diagnostic surfaced via [`crate::ItbError`]. Primitive / MAC /
//! cipher / palette names are opaque strings.

use std::ffi::CString;

/// Builder producing the URL-query-encoded opts string consumed by
/// [`crate::Pipeline::init`]. Profile registration takes a
/// [`crate::Profile`] record instead (see [`crate::register`]).
#[derive(Debug, Default, Clone)]
pub struct OptsBuilder {
    pairs: Vec<(String, String)>,
}

impl OptsBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    /// Hex-encodes the parallax master override (`pm`).
    pub fn with_perm_master(self, master: &[u8]) -> Self {
        self.with_raw("pm", &hex(master))
    }

    /// Hex-encodes the wrapper master override (`wm`).
    pub fn with_wrap_master(self, master: &[u8]) -> Self {
        self.with_raw("wm", &hex(master))
    }

    pub fn with_parallax(self, on: bool) -> Self {
        self.with_raw("withParallax", bool_str(on))
    }

    pub fn with_wrapper(self, on: bool) -> Self {
        self.with_raw("withWrapper", bool_str(on))
    }

    pub fn with_max_workers(self, n: i64) -> Self {
        self.with_raw("maxWorkers", &n.to_string())
    }

    pub fn with_nonce_bits(self, n: i64) -> Self {
        self.with_raw("nonceBits", &n.to_string())
    }

    pub fn with_barrier_fill(self, n: i64) -> Self {
        self.with_raw("barrierFill", &n.to_string())
    }

    pub fn with_chunk_size(self, n: i64) -> Self {
        self.with_raw("chunkSize", &n.to_string())
    }

    pub fn with_key_bits(self, n: i64) -> Self {
        self.with_raw("keyBits", &n.to_string())
    }

    pub fn with_parallax_segment_size(self, n: i64) -> Self {
        self.with_raw("parallaxSegmentSize", &n.to_string())
    }

    pub fn with_mac_name(self, name: &str) -> Self {
        self.with_raw("macName", name)
    }

    pub fn with_inner_hash(self, name: &str) -> Self {
        self.with_raw("innerHash", name)
    }

    /// Comma-joins an 8-slot per-call inner-hash constellation into
    /// the `innerHashes` opts key. Parallel to the Go-side
    /// `Opts.MixedHashes [8]string` per-call override; slot ordering
    /// is `[noise, lock, data1, data2, data3, start1, start2,
    /// start3]`.
    ///
    /// Fail-fast validation surfaces at Init on the Go side; a typo'd
    /// slot or width mismatch surfaces with an error naming the
    /// offending slot. When both this and [`Self::with_inner_hash`]
    /// are set, the mixed override wins on the Go side.
    pub fn with_inner_hashes(self, names: &[&str]) -> Self {
        self.with_raw("innerHashes", &names.join(","))
    }

    pub fn with_outer_cipher(self, name: &str) -> Self {
        self.with_raw("outerCipher", name)
    }

    /// Comma-joins the palette names (`parallaxPalette`).
    pub fn with_parallax_palette(self, names: &[&str]) -> Self {
        self.with_raw("parallaxPalette", &names.join(","))
    }

    /// Escape hatch appending a raw `key=value` pair. Covers every
    /// key the Go side accepts for Init overrides.
    pub fn with_raw(mut self, key: &str, value: &str) -> Self {
        self.pairs.push((key.to_owned(), value.to_owned()));
        self
    }

    /// Renders the accumulated pairs as a NUL-terminated query string.
    pub fn build(&self) -> CString {
        let query = self
            .pairs
            .iter()
            .map(|(k, v)| format!("{}={}", enc(k), enc(v)))
            .collect::<Vec<_>>()
            .join("&");
        CString::new(query).expect("percent-encoded query carries no NUL")
    }
}

fn bool_str(on: bool) -> &'static str {
    if on { "true" } else { "false" }
}

/// Minimal percent-encoding: the accepted values are ASCII names,
/// decimal integers, `true` / `false`, hex, and comma-separated
/// lists, so everything outside the URL-safe subset (plus `,`) is
/// escaped byte-wise.
fn enc(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' | b',' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::OptsBuilder;

    #[test]
    fn typed_setters_render_expected_keys() {
        let q = OptsBuilder::new()
            .with_perm_master(&[0xab, 0x01])
            .with_wrap_master(&[0xcd, 0xef])
            .with_parallax(true)
            .with_wrapper(false)
            .with_max_workers(4)
            .with_nonce_bits(512)
            .with_barrier_fill(4)
            .with_chunk_size(4096)
            .with_key_bits(1024)
            .with_parallax_segment_size(65536)
            .with_mac_name("hmac-blake3")
            .with_inner_hash("areion512")
            .with_outer_cipher("chacha20")
            .with_parallax_palette(&["aescmac", "chacha20", "blake3"])
            .build();
        assert_eq!(
            q.to_str().unwrap(),
            "pm=ab01&wm=cdef&withParallax=true&withWrapper=false&\
             maxWorkers=4&nonceBits=512&barrierFill=4&chunkSize=4096&\
             keyBits=1024&parallaxSegmentSize=65536&macName=hmac-blake3&\
             innerHash=areion512&outerCipher=chacha20&\
             parallaxPalette=aescmac,chacha20,blake3"
        );
    }

    #[test]
    fn raw_escape_hatch_and_encoding() {
        let q = OptsBuilder::new().with_raw("mode", "a b&c=d%").build();
        assert_eq!(q.to_str().unwrap(), "mode=a%20b%26c%3Dd%25");
    }

    #[test]
    fn empty_builder_renders_empty_query() {
        assert_eq!(OptsBuilder::new().build().to_str().unwrap(), "");
    }
}
