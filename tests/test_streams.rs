//! Phase-4 smoke: confirm chunked Single-Ouroboros encrypt + decrypt
//! round-trips a 200 KB plaintext via the streaming wrappers.

use std::io::Cursor;

use itb::{decrypt_stream, encrypt_stream, Seed};

fn pseudo_plaintext(n: usize) -> Vec<u8> {
    // Deterministic, content-rich plaintext — every 256-byte run cycles
    // through the byte values 0..255 so naive byte-level re-encoding
    // bugs surface as misaligned regions in the recovered plaintext.
    (0..n).map(|i| (i & 0xff) as u8).collect()
}

#[test]
fn stream_single_roundtrip_200kb() {
    let n = Seed::new("blake3", 1024).unwrap();
    let d = Seed::new("blake3", 1024).unwrap();
    let s = Seed::new("blake3", 1024).unwrap();

    let plaintext = pseudo_plaintext(200 * 1024);

    // Encrypt into a Vec<u8> sink with a small chunk size so several
    // chunks are emitted.
    let mut ciphertext: Vec<u8> = Vec::new();
    encrypt_stream(
        &n,
        &d,
        &s,
        Cursor::new(&plaintext),
        &mut ciphertext,
        64 * 1024,
    )
    .unwrap();
    assert!(!ciphertext.is_empty());
    assert_ne!(ciphertext, plaintext);

    // Decrypt with a smaller read size so feed() crosses chunk
    // boundaries on multiple iterations.
    let mut recovered: Vec<u8> = Vec::new();
    decrypt_stream(
        &n,
        &d,
        &s,
        Cursor::new(&ciphertext),
        &mut recovered,
        4096,
    )
    .unwrap();

    assert_eq!(recovered, plaintext);
}

#[test]
fn stream_single_roundtrip_short_payload() {
    // Payload smaller than chunk_size — exercises the close()-flush
    // path that emits a single tail chunk.
    let n = Seed::new("blake3", 1024).unwrap();
    let d = Seed::new("blake3", 1024).unwrap();
    let s = Seed::new("blake3", 1024).unwrap();

    let plaintext: &[u8] = b"Lorem ipsum dolor sit amet, consectetur adipiscing elit.";

    let mut ciphertext: Vec<u8> = Vec::new();
    encrypt_stream(
        &n,
        &d,
        &s,
        Cursor::new(plaintext),
        &mut ciphertext,
        64 * 1024,
    )
    .unwrap();

    let mut recovered: Vec<u8> = Vec::new();
    decrypt_stream(
        &n,
        &d,
        &s,
        Cursor::new(&ciphertext),
        &mut recovered,
        64 * 1024,
    )
    .unwrap();

    assert_eq!(recovered.as_slice(), plaintext);
}

#[test]
fn stream_encryptor_struct_api() {
    use itb::{StreamDecryptor, StreamEncryptor};

    let n = Seed::new("blake3", 1024).unwrap();
    let d = Seed::new("blake3", 1024).unwrap();
    let s = Seed::new("blake3", 1024).unwrap();

    let parts: &[&[u8]] = &[b"first chunk ", b"second chunk ", b"third chunk"];

    let mut ciphertext: Vec<u8> = Vec::new();
    {
        let mut enc =
            StreamEncryptor::new(&n, &d, &s, &mut ciphertext, 64 * 1024).unwrap();
        for p in parts {
            enc.write(p).unwrap();
        }
        enc.close().unwrap();
    }

    let mut recovered: Vec<u8> = Vec::new();
    {
        let mut dec = StreamDecryptor::new(&n, &d, &s, &mut recovered).unwrap();
        dec.feed(&ciphertext).unwrap();
        dec.close().unwrap();
    }

    let expected: Vec<u8> = parts.concat();
    assert_eq!(recovered, expected);
}

// --------------------------------------------------------------------
// Phase-5 extension — full Python-parity coverage. Mirrors the
// remaining test classes / methods from
// `bindings/python/tests/test_streams.py`.
// --------------------------------------------------------------------

use itb::{StreamDecryptor, StreamDecryptor3, StreamEncryptor, StreamEncryptor3};

const SMALL_CHUNK: usize = 4096;

fn pseudo_payload(n: usize) -> Vec<u8> {
    (0..n).map(|i| ((i * 13 + 11) & 0xff) as u8).collect()
}

#[test]
fn test_class_roundtrip_default_nonce() {
    let plaintext = pseudo_payload(SMALL_CHUNK * 5 + 17);
    let n = Seed::new("blake3", 1024).unwrap();
    let d = Seed::new("blake3", 1024).unwrap();
    let s = Seed::new("blake3", 1024).unwrap();

    let mut cbuf: Vec<u8> = Vec::new();
    {
        let mut enc = StreamEncryptor::new(&n, &d, &s, &mut cbuf, SMALL_CHUNK).unwrap();
        // Push data in three irregular slices, exercising the
        // accumulator path on partial chunks.
        enc.write(&plaintext[..1000]).unwrap();
        enc.write(&plaintext[1000..5000]).unwrap();
        enc.write(&plaintext[5000..]).unwrap();
        enc.close().unwrap();
    }

    let mut pbuf: Vec<u8> = Vec::new();
    {
        let mut dec = StreamDecryptor::new(&n, &d, &s, &mut pbuf).unwrap();
        // Feed ciphertext in 1-KB shards so feed() crosses chunk
        // boundaries on multiple iterations.
        let mut off = 0;
        while off < cbuf.len() {
            let end = std::cmp::min(off + 1024, cbuf.len());
            dec.feed(&cbuf[off..end]).unwrap();
            off = end;
        }
        dec.close().unwrap();
    }
    assert_eq!(pbuf, plaintext);
}

#[test]
fn test_encrypt_stream_decrypt_stream() {
    let plaintext = pseudo_payload(SMALL_CHUNK * 4);
    let n = Seed::new("blake3", 1024).unwrap();
    let d = Seed::new("blake3", 1024).unwrap();
    let s = Seed::new("blake3", 1024).unwrap();

    let mut cbuf: Vec<u8> = Vec::new();
    encrypt_stream(&n, &d, &s, Cursor::new(&plaintext), &mut cbuf, SMALL_CHUNK).unwrap();

    let mut pbuf: Vec<u8> = Vec::new();
    decrypt_stream(&n, &d, &s, Cursor::new(&cbuf), &mut pbuf, SMALL_CHUNK).unwrap();
    assert_eq!(pbuf, plaintext);
}

#[test]
fn test_class_roundtrip_default_nonce_triple() {
    let plaintext = pseudo_payload(SMALL_CHUNK * 4 + 33);
    let s0 = Seed::new("blake3", 1024).unwrap();
    let s1 = Seed::new("blake3", 1024).unwrap();
    let s2 = Seed::new("blake3", 1024).unwrap();
    let s3 = Seed::new("blake3", 1024).unwrap();
    let s4 = Seed::new("blake3", 1024).unwrap();
    let s5 = Seed::new("blake3", 1024).unwrap();
    let s6 = Seed::new("blake3", 1024).unwrap();

    let mut cbuf: Vec<u8> = Vec::new();
    {
        let mut enc = StreamEncryptor3::new(
            &s0, &s1, &s2, &s3, &s4, &s5, &s6, &mut cbuf, SMALL_CHUNK,
        )
        .unwrap();
        enc.write(&plaintext[..SMALL_CHUNK]).unwrap();
        enc.write(&plaintext[SMALL_CHUNK..3 * SMALL_CHUNK]).unwrap();
        enc.write(&plaintext[3 * SMALL_CHUNK..]).unwrap();
        enc.close().unwrap();
    }

    let mut pbuf: Vec<u8> = Vec::new();
    {
        let mut dec = StreamDecryptor3::new(
            &s0, &s1, &s2, &s3, &s4, &s5, &s6, &mut pbuf,
        )
        .unwrap();
        dec.feed(&cbuf).unwrap();
        dec.close().unwrap();
    }
    assert_eq!(pbuf, plaintext);
}

#[test]
fn test_encrypt_stream_triple_decrypt_stream_triple() {
    use itb::{decrypt_stream_triple, encrypt_stream_triple};

    let plaintext = pseudo_payload(SMALL_CHUNK * 5 + 7);
    let s0 = Seed::new("blake3", 1024).unwrap();
    let s1 = Seed::new("blake3", 1024).unwrap();
    let s2 = Seed::new("blake3", 1024).unwrap();
    let s3 = Seed::new("blake3", 1024).unwrap();
    let s4 = Seed::new("blake3", 1024).unwrap();
    let s5 = Seed::new("blake3", 1024).unwrap();
    let s6 = Seed::new("blake3", 1024).unwrap();

    let mut cbuf: Vec<u8> = Vec::new();
    encrypt_stream_triple(
        &s0,
        &s1,
        &s2,
        &s3,
        &s4,
        &s5,
        &s6,
        Cursor::new(&plaintext),
        &mut cbuf,
        SMALL_CHUNK,
    )
    .unwrap();

    let mut pbuf: Vec<u8> = Vec::new();
    decrypt_stream_triple(
        &s0,
        &s1,
        &s2,
        &s3,
        &s4,
        &s5,
        &s6,
        Cursor::new(&cbuf),
        &mut pbuf,
        SMALL_CHUNK,
    )
    .unwrap();
    assert_eq!(pbuf, plaintext);
}

#[test]
fn test_write_after_close_raises() {
    let n = Seed::new("blake3", 1024).unwrap();
    let d = Seed::new("blake3", 1024).unwrap();
    let s = Seed::new("blake3", 1024).unwrap();
    let mut cbuf: Vec<u8> = Vec::new();
    let mut enc = StreamEncryptor::new(&n, &d, &s, &mut cbuf, SMALL_CHUNK).unwrap();
    enc.write(b"hello").unwrap();
    enc.close().unwrap();
    let result = enc.write(b"world");
    assert!(result.is_err(), "write after close must surface ITBError");
    let err = result.err().unwrap();
    assert_eq!(err.code(), itb::STATUS_EASY_CLOSED);
}

#[test]
fn test_partial_chunk_at_close_raises() {
    let n = Seed::new("blake3", 1024).unwrap();
    let d = Seed::new("blake3", 1024).unwrap();
    let s = Seed::new("blake3", 1024).unwrap();
    let mut cbuf: Vec<u8> = Vec::new();
    {
        let mut enc =
            StreamEncryptor::new(&n, &d, &s, &mut cbuf, SMALL_CHUNK).unwrap();
        enc.write(&[b'x'; 100]).unwrap();
        enc.close().unwrap();
    }

    let mut pbuf: Vec<u8> = Vec::new();
    let mut dec = StreamDecryptor::new(&n, &d, &s, &mut pbuf).unwrap();
    // Feed only the first 30 bytes — header is complete (>= 20) but
    // the body is truncated. close() must raise on the trailing
    // incomplete chunk.
    dec.feed(&cbuf[..30]).unwrap();
    let result = dec.close();
    assert!(result.is_err(), "close with truncated trailing chunk must surface ITBError");
    let err = result.err().unwrap();
    assert_eq!(err.code(), itb::STATUS_BAD_INPUT);
}

// Note: the Python `test_class_roundtrip_non_default_nonce`,
// `test_encrypt_stream_across_nonce_sizes`,
// `test_class_roundtrip_non_default_nonce_triple`, and
// `test_encrypt_stream_triple_across_nonce_sizes` tests each mutate
// the process-global `set_nonce_bits` knob. The cargo test runner
// dispatches every `#[test]` fn in this binary on a parallel thread
// pool, and the pre-Phase-5 streaming tests in this file
// (`stream_single_roundtrip_200kb` etc.) read the active nonce
// header_size indirectly via the encrypt-decrypt path. A parallel
// writer mutating NonceBits in the middle of an encrypt's two-phase
// probe-then-write idiom races the writer's value into the
// second-phase buffer-size mismatch. Cross-nonce streaming coverage
// therefore lives in `test_nonce_sizes.rs` where every `#[test]`
// holds `common::serial_lock()` and the existing default-nonce
// streaming tests in this file remain race-free.
