//! ITB — Rust binding over the libitb shared library.
//!
//! The crate wraps the C ABI exported by `cmd/cshared`
//! (libitb.so / .dll / .dylib) through `libloading` (no compile-time
//! linking, no C compiler at install). The public surface is
//! intentionally narrow:
//!
//! ```no_run
//! use itb::Seed;
//!
//! let n = Seed::new("blake3", 1024).unwrap();
//! let d = Seed::new("blake3", 1024).unwrap();
//! let s = Seed::new("blake3", 1024).unwrap();
//! let ct = itb::encrypt(&n, &d, &s, b"hello world").unwrap();
//! let pt = itb::decrypt(&n, &d, &s, &ct).unwrap();
//! assert_eq!(pt, b"hello world");
//! ```
//!
//! Authenticated variants take an additional MAC handle:
//!
//! ```no_run
//! use itb::{Seed, MAC};
//!
//! let n = Seed::new("blake3", 1024).unwrap();
//! let d = Seed::new("blake3", 1024).unwrap();
//! let s = Seed::new("blake3", 1024).unwrap();
//! let mac = MAC::new("hmac-sha256", &[0u8; 32]).unwrap();
//! let ct = itb::encrypt_auth(&n, &d, &s, &mac, b"integrity-protected").unwrap();
//! let pt = itb::decrypt_auth(&n, &d, &s, &mac, &ct).unwrap();
//! ```
//!
//! Hash names match the canonical FFI registry (see `hashes/registry.go`):
//! `areion256`, `areion512`, `siphash24`, `aescmac`, `blake2b256`,
//! `blake2b512`, `blake2s`, `blake3`, `chacha20`.
//!
//! MAC names: `kmac256`, `hmac-sha256`, `hmac-blake3`.

pub(crate) mod ffi;
pub(crate) mod error;
pub mod registry;
pub mod seed;
pub mod mac;
pub mod encrypt;
pub mod encryptor;
pub mod blob;
pub mod streams;

pub use error::{last_error, ITBError};
pub use registry::{
    channels, get_barrier_fill, get_bit_soup, get_lock_soup, get_max_workers,
    get_nonce_bits, header_size, list_hashes, list_macs, max_key_bits,
    parse_chunk_len, set_barrier_fill, set_bit_soup, set_lock_soup,
    set_max_workers, set_nonce_bits, version,
};
pub use seed::Seed;
pub use mac::MAC;
pub use encrypt::{
    decrypt, decrypt_auth, decrypt_auth_triple, decrypt_triple, encrypt,
    encrypt_auth, encrypt_auth_triple, encrypt_triple,
};
pub use encryptor::{last_mismatch_field, peek_config, Encryptor};
pub use blob::{
    raise_blob, slot_from_name, Blob128, Blob256, Blob512, BlobSlot,
    OPT_LOCKSEED, OPT_MAC, SLOT_D, SLOT_D1, SLOT_D2, SLOT_D3, SLOT_L, SLOT_N,
    SLOT_S, SLOT_S1, SLOT_S2, SLOT_S3,
};
pub use streams::{
    decrypt_stream, decrypt_stream_auth, decrypt_stream_auth_triple,
    decrypt_stream_triple, encrypt_stream, encrypt_stream_auth,
    encrypt_stream_auth_triple, encrypt_stream_triple,
    StreamDecryptor, StreamDecryptor3, StreamDecryptorAuth, StreamDecryptorAuth3,
    StreamEncryptor, StreamEncryptor3, StreamEncryptorAuth, StreamEncryptorAuth3,
    DEFAULT_CHUNK_SIZE,
};

// Status-code constants re-exported for consumers that match on
// `err.code()` against well-known error codes.
pub use crate::ffi::{
    STATUS_BAD_HANDLE, STATUS_BAD_HASH, STATUS_BAD_INPUT, STATUS_BAD_KEY_BITS,
    STATUS_BAD_MAC, STATUS_BLOB_MALFORMED, STATUS_BLOB_MODE_MISMATCH,
    STATUS_BLOB_TOO_MANY_OPTS, STATUS_BLOB_VERSION_TOO_NEW,
    STATUS_BUFFER_TOO_SMALL, STATUS_DECRYPT_FAILED,
    STATUS_EASY_BAD_KEY_BITS, STATUS_EASY_CLOSED,
    STATUS_EASY_LOCKSEED_AFTER_ENCRYPT, STATUS_EASY_MALFORMED,
    STATUS_EASY_MISMATCH, STATUS_EASY_UNKNOWN_MAC,
    STATUS_EASY_UNKNOWN_PRIMITIVE, STATUS_EASY_VERSION_TOO_NEW,
    STATUS_ENCRYPT_FAILED, STATUS_INTERNAL, STATUS_MAC_FAILURE, STATUS_OK,
    STATUS_SEED_WIDTH_MIX, STATUS_STREAM_AFTER_FINAL, STATUS_STREAM_TRUNCATED,
};
