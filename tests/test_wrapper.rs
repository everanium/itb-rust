//! Format-deniability wrapper round-trip tests.
//!
//! Covers the 12-export FFI surface:
//!
//!   - key_size / nonce_size lookups against every cipher.
//!   - wrap / unwrap (Single Message, immutable plaintext path).
//!   - wrap_in_place / unwrap_in_place (mutable plaintext path).
//!   - WrapStreamWriter / UnwrapStreamReader (multi-chunk streaming).
//!   - Negative paths: short wire, mis-sized key, mis-sized nonce,
//!     post-close `update`.
//!
//! 22 tests minimum — 12 Single Message + 6 streaming + 4 negative.
//! Mirrors the Python wrapper test coverage shape, translated to
//! Rust idioms.

use itb::wrapper::{
    self, Cipher, UnwrapStreamReader, WrapStreamWriter,
};

const SAMPLE_BLOB: &[u8] =
    b"\x01\x02\x03 ITB-format-deniability wrapper test plaintext blob \xfe\xfd\xfc";

fn long_blob() -> Vec<u8> {
    // Multi-chunk-ish payload that crosses block / refill boundaries
    // for every outer cipher (AES = 16-byte block, ChaCha = 64-byte
    // block, SipHash-CTR = 8-byte refill).
    let mut v = Vec::with_capacity(4 * 1024);
    for i in 0..4096 {
        v.push((i & 0xff) as u8);
    }
    v
}

fn assert_key_nonce_sizes(cipher: Cipher, want_key: usize, want_nonce: usize) {
    let kn = wrapper::key_size(cipher).unwrap();
    let nn = wrapper::nonce_size(cipher).unwrap();
    assert_eq!(kn, want_key, "key_size({cipher})");
    assert_eq!(nn, want_nonce, "nonce_size({cipher})");
}

// --------------------------------------------------------------------
// Cipher metadata
// --------------------------------------------------------------------

#[test]
fn metadata_aes() {
    assert_key_nonce_sizes(Cipher::Aes128Ctr, 16, 16);
}

#[test]
fn metadata_chacha() {
    assert_key_nonce_sizes(Cipher::ChaCha20, 32, 12);
}

#[test]
fn metadata_siphash() {
    assert_key_nonce_sizes(Cipher::SipHash24, 16, 16);
}

#[test]
fn generate_key_size_matches_cipher() {
    for cipher in Cipher::all() {
        let k = wrapper::generate_key(cipher).unwrap();
        let want = wrapper::key_size(cipher).unwrap();
        assert_eq!(k.len(), want, "{cipher}");
    }
}

// --------------------------------------------------------------------
// wrap / unwrap — immutable plaintext path
// --------------------------------------------------------------------

fn roundtrip_wrap(cipher: Cipher) {
    let key = wrapper::generate_key(cipher).unwrap();
    let blob = long_blob();
    let wire = wrapper::wrap(cipher, &key, &blob).unwrap();
    // Wire = nonce || keystream-XOR(blob); length = nonce + blob.
    let nlen = wrapper::nonce_size(cipher).unwrap();
    assert_eq!(wire.len(), nlen + blob.len());
    // Body bytes differ from plaintext (probabilistic — XOR with
    // CSPRNG-derived keystream).
    assert_ne!(&wire[nlen..], blob.as_slice());
    let recovered = wrapper::unwrap(cipher, &key, &wire).unwrap();
    assert_eq!(recovered, blob);
}

#[test]
fn wrap_unwrap_aes() {
    roundtrip_wrap(Cipher::Aes128Ctr);
}

#[test]
fn wrap_unwrap_chacha() {
    roundtrip_wrap(Cipher::ChaCha20);
}

#[test]
fn wrap_unwrap_siphash() {
    roundtrip_wrap(Cipher::SipHash24);
}

#[test]
fn wrap_empty_blob() {
    // Degenerate input — every cipher must handle a zero-length blob
    // gracefully. Wire = nonce only.
    for cipher in Cipher::all() {
        let key = wrapper::generate_key(cipher).unwrap();
        let wire = wrapper::wrap(cipher, &key, &[]).unwrap();
        let nlen = wrapper::nonce_size(cipher).unwrap();
        assert_eq!(wire.len(), nlen, "{cipher} wrap empty");
        let recovered = wrapper::unwrap(cipher, &key, &wire).unwrap();
        assert!(recovered.is_empty(), "{cipher} unwrap empty");
    }
}

// --------------------------------------------------------------------
// wrap_in_place / unwrap_in_place — mutable plaintext path
// --------------------------------------------------------------------

fn roundtrip_wrap_in_place(cipher: Cipher) {
    let key = wrapper::generate_key(cipher).unwrap();
    let blob = long_blob();
    let mut mutable = blob.clone();
    let nonce = wrapper::wrap_in_place(cipher, &key, &mut mutable).unwrap();
    assert_eq!(nonce.len(), wrapper::nonce_size(cipher).unwrap());
    // mutable now carries keystream-XORed bytes, distinct from the
    // original plaintext.
    assert_ne!(mutable.as_slice(), blob.as_slice());

    // Compose wire = nonce || mutated.
    let mut wire = nonce.clone();
    wire.extend_from_slice(&mutable);

    // Receiver — unwrap_in_place returns an aliased slice over the
    // body section.
    let body = wrapper::unwrap_in_place(cipher, &key, &mut wire).unwrap();
    assert_eq!(body, blob.as_slice());
}

#[test]
fn wrap_in_place_aes() {
    roundtrip_wrap_in_place(Cipher::Aes128Ctr);
}

#[test]
fn wrap_in_place_chacha() {
    roundtrip_wrap_in_place(Cipher::ChaCha20);
}

#[test]
fn wrap_in_place_siphash() {
    roundtrip_wrap_in_place(Cipher::SipHash24);
}

// --------------------------------------------------------------------
// Cross-shape parity — wrap_in_place output must equal wrap output
// when both operate under the SAME nonce + key. Direct equality test
// is not possible (the nonce is randomly drawn each call); instead
// every shape must produce a wire that round-trips back to the
// original plaintext under the matching unwrap.
// --------------------------------------------------------------------

#[test]
fn wrap_then_unwrap_in_place_cross_shape() {
    // Wrap with the immutable helper, decrypt with the in-place helper.
    for cipher in Cipher::all() {
        let key = wrapper::generate_key(cipher).unwrap();
        let blob = SAMPLE_BLOB.to_vec();
        let mut wire = wrapper::wrap(cipher, &key, &blob).unwrap();
        let body = wrapper::unwrap_in_place(cipher, &key, &mut wire).unwrap();
        assert_eq!(body, blob.as_slice(), "{cipher}");
    }
}

#[test]
fn wrap_in_place_then_unwrap_cross_shape() {
    // Wrap with the in-place helper, decrypt with the immutable helper.
    for cipher in Cipher::all() {
        let key = wrapper::generate_key(cipher).unwrap();
        let blob = SAMPLE_BLOB.to_vec();
        let mut mutable = blob.clone();
        let nonce = wrapper::wrap_in_place(cipher, &key, &mut mutable).unwrap();
        let mut wire = nonce.clone();
        wire.extend_from_slice(&mutable);
        let recovered = wrapper::unwrap(cipher, &key, &wire).unwrap();
        assert_eq!(recovered, blob, "{cipher}");
    }
}

// --------------------------------------------------------------------
// Streaming wrap / unwrap — multi-chunk
// --------------------------------------------------------------------

fn roundtrip_stream(cipher: Cipher) {
    let key = wrapper::generate_key(cipher).unwrap();
    let chunks: &[&[u8]] = &[
        b"first chunk     ",
        b"second slightly longer chunk to cross any 16-byte block boundary",
        b"3",
        b"",
        b"final chunk after empty mid-stream chunk to verify counter advances",
    ];

    // Sender — emit nonce + per-chunk keystream-XOR.
    let mut writer = WrapStreamWriter::new(cipher, &key).unwrap();
    let mut wire = writer.nonce().to_vec();
    let nlen = wrapper::nonce_size(cipher).unwrap();
    assert_eq!(wire.len(), nlen);
    for ch in chunks {
        let enc = writer.update(ch).unwrap();
        assert_eq!(enc.len(), ch.len());
        wire.extend_from_slice(&enc);
    }
    writer.close().unwrap();

    // Receiver — pull nonce off the wire, decrypt the rest one chunk
    // at a time. Use the same chunk boundaries so the keystream
    // counter aligns.
    let mut reader = UnwrapStreamReader::new(cipher, &key, &wire[..nlen]).unwrap();
    let mut off = nlen;
    for ch in chunks {
        let body = &wire[off..off + ch.len()];
        let dec = reader.update(body).unwrap();
        assert_eq!(dec.as_slice(), *ch);
        off += ch.len();
    }
    assert_eq!(off, wire.len());
    reader.close().unwrap();
}

#[test]
fn stream_aes_multichunk() {
    roundtrip_stream(Cipher::Aes128Ctr);
}

#[test]
fn stream_chacha_multichunk() {
    roundtrip_stream(Cipher::ChaCha20);
}

#[test]
fn stream_siphash_multichunk() {
    roundtrip_stream(Cipher::SipHash24);
}

// --------------------------------------------------------------------
// Streaming — single-chunk shape (verifies stream output equals
// `wrap` output up to the nonce). Decryption splits into multiple
// `update` calls to confirm the keystream is byte-granular.
// --------------------------------------------------------------------

#[test]
fn stream_single_chunk_byte_split_decrypt() {
    for cipher in Cipher::all() {
        let key = wrapper::generate_key(cipher).unwrap();
        let blob = long_blob();

        // Sender — one update covering the whole blob.
        let mut writer = WrapStreamWriter::new(cipher, &key).unwrap();
        let mut wire = writer.nonce().to_vec();
        wire.extend_from_slice(&writer.update(&blob).unwrap());
        writer.close().unwrap();

        // Receiver — split decrypt into 7-byte slices to verify the
        // keystream advances at byte granularity. SipHash-CTR's 8-byte
        // refill straddle is the real stress here; the reader must
        // hand out continuous keystream regardless of caller framing.
        let nlen = wrapper::nonce_size(cipher).unwrap();
        let mut reader = UnwrapStreamReader::new(cipher, &key, &wire[..nlen]).unwrap();
        let mut decrypted = Vec::with_capacity(blob.len());
        let body = &wire[nlen..];
        let chunk = 7;
        let mut off = 0;
        while off < body.len() {
            let take = std::cmp::min(chunk, body.len() - off);
            let dec = reader.update(&body[off..off + take]).unwrap();
            decrypted.extend_from_slice(&dec);
            off += take;
        }
        assert_eq!(decrypted, blob, "{cipher}");
        reader.close().unwrap();
    }
}

// --------------------------------------------------------------------
// update_in_place coverage — single-shape streaming with mutable
// caller buffers, verifying RAII Drop also closes cleanly without an
// explicit close().
// --------------------------------------------------------------------

#[test]
fn stream_update_in_place_drops_cleanly() {
    for cipher in Cipher::all() {
        let key = wrapper::generate_key(cipher).unwrap();
        let blob = long_blob();

        // Sender — update_in_place over a mutable copy of the blob.
        let nonce;
        let mut wire_body;
        {
            let mut writer = WrapStreamWriter::new(cipher, &key).unwrap();
            nonce = writer.nonce().to_vec();
            wire_body = blob.clone();
            writer.update_in_place(&mut wire_body).unwrap();
            // Drop without explicit close — RAII handles release.
        }
        let mut wire = nonce.clone();
        wire.extend_from_slice(&wire_body);

        // Receiver — update_in_place to recover plaintext.
        let nlen = wrapper::nonce_size(cipher).unwrap();
        let mut decrypted_body;
        {
            let mut reader =
                UnwrapStreamReader::new(cipher, &key, &wire[..nlen]).unwrap();
            decrypted_body = wire[nlen..].to_vec();
            reader.update_in_place(&mut decrypted_body).unwrap();
        }
        assert_eq!(decrypted_body, blob, "{cipher}");
    }
}

// --------------------------------------------------------------------
// Negative paths
// --------------------------------------------------------------------

#[test]
fn unwrap_short_wire() {
    for cipher in Cipher::all() {
        let key = wrapper::generate_key(cipher).unwrap();
        // Pass fewer bytes than the cipher's nonce size.
        let nlen = wrapper::nonce_size(cipher).unwrap();
        let too_short = vec![0u8; nlen.saturating_sub(1)];
        let err = wrapper::unwrap(cipher, &key, &too_short).unwrap_err();
        assert_eq!(
            err.code(),
            itb::STATUS_BAD_INPUT,
            "{cipher} expected BAD_INPUT, got {}",
            err.code()
        );
    }
}

#[test]
fn wrap_wrong_key_size() {
    for cipher in Cipher::all() {
        let want = wrapper::key_size(cipher).unwrap();
        let bad_key = vec![0u8; want + 1];
        let err = wrapper::wrap(cipher, &bad_key, b"x").unwrap_err();
        assert_eq!(
            err.code(),
            itb::STATUS_BAD_INPUT,
            "{cipher} expected BAD_INPUT for over-sized key"
        );
    }
}

#[test]
fn unwrap_in_place_wrong_key_size() {
    for cipher in Cipher::all() {
        let want = wrapper::key_size(cipher).unwrap();
        let bad_key = vec![0u8; want.saturating_sub(1)];
        let mut wire = vec![0u8; 64];
        let err = wrapper::unwrap_in_place(cipher, &bad_key, &mut wire).unwrap_err();
        assert_eq!(
            err.code(),
            itb::STATUS_BAD_INPUT,
            "{cipher} expected BAD_INPUT for under-sized key"
        );
    }
}

#[test]
fn stream_reader_wrong_nonce_size() {
    for cipher in Cipher::all() {
        let key = wrapper::generate_key(cipher).unwrap();
        let nlen = wrapper::nonce_size(cipher).unwrap();
        let bad_nonce = vec![0u8; nlen + 1];
        match UnwrapStreamReader::new(cipher, &key, &bad_nonce) {
            Err(e) => assert_eq!(e.code(), itb::STATUS_BAD_INPUT, "{cipher}"),
            Ok(_) => panic!("{cipher}: expected BAD_INPUT for mis-sized nonce"),
        }
    }
}

#[test]
fn stream_writer_update_after_close_fails() {
    for cipher in Cipher::all() {
        let key = wrapper::generate_key(cipher).unwrap();
        let mut writer = WrapStreamWriter::new(cipher, &key).unwrap();
        writer.close().unwrap();
        let err = writer.update(b"oops").unwrap_err();
        assert_eq!(
            err.code(),
            itb::STATUS_BAD_HANDLE,
            "{cipher}: expected BAD_HANDLE post-close"
        );
    }
}

#[test]
fn handle_lifecycle_stress() {
    // Allocate + drop 256 stream-writer / stream-reader handle pairs
    // without explicit close, verifying RAII cleanup releases the
    // underlying libitb slot. A leak would either exhaust the
    // libitb-side handle pool (causing a later allocation to fail)
    // or surface a memory-pressure error in valgrind / sanitizers
    // run against this test target.
    for _ in 0..256 {
        let key = wrapper::generate_key(Cipher::Aes128Ctr).unwrap();
        let writer = WrapStreamWriter::new(Cipher::Aes128Ctr, &key).unwrap();
        let nonce = writer.nonce().to_vec();
        drop(writer);
        let reader =
            UnwrapStreamReader::new(Cipher::Aes128Ctr, &key, &nonce).unwrap();
        drop(reader);
    }
    // Final allocation must still succeed — proves the handle pool
    // is not exhausted.
    let key = wrapper::generate_key(Cipher::Aes128Ctr).unwrap();
    let _w = WrapStreamWriter::new(Cipher::Aes128Ctr, &key).unwrap();
}

#[test]
fn handle_double_close_idempotent() {
    // Calling close() twice should be a no-op; the first call
    // releases, the second short-circuits without surfacing an error.
    for cipher in Cipher::all() {
        let key = wrapper::generate_key(cipher).unwrap();
        let mut writer = WrapStreamWriter::new(cipher, &key).unwrap();
        writer.close().expect("first close ok");
        writer.close().expect("second close idempotent");

        let mut reader =
            UnwrapStreamReader::new(cipher, &key, writer.nonce()).unwrap();
        reader.close().expect("first close ok");
        reader.close().expect("second close idempotent");
    }
}
