//! Streaming-style use of the high-level [`itb::Encryptor`] surface —
//! Rust mirror of `bindings/python/tests/easy/test_streams.py`.
//!
//! Streaming over the Encryptor surface lives entirely on the binding
//! side (no separate StreamEncryptor / StreamDecryptor classes for
//! the Easy API): the consumer slices the plaintext into chunks of
//! the desired size and calls [`Encryptor::encrypt`] per chunk; the
//! decrypt side walks the concatenated chunk stream by reading
//! [`Encryptor::header_size`] bytes, calling
//! [`Encryptor::parse_chunk_len`], reading the remaining body, and
//! feeding the full chunk to [`Encryptor::decrypt`].
//!
//! Triple-Ouroboros (mode=3) and non-default nonce-bits configurations
//! are covered explicitly so a regression in the per-instance
//! [`Encryptor::header_size`] / [`Encryptor::parse_chunk_len`] path or
//! in the seed plumbing surfaces here.

#[path = "common/mod.rs"]
#[allow(dead_code)]
mod common;

use itb::Encryptor;

const SMALL_CHUNK: usize = 4096;

fn token_bytes(n: usize) -> Vec<u8> {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::Instant;
    static CTR: AtomicU64 = AtomicU64::new(0x12345678_9ABCDEF0);
    let c = CTR.fetch_add(0x9E37_79B9_7F4A_7C15, Ordering::Relaxed);
    let t = Instant::now().elapsed().as_nanos() as u64;
    let mut state = c ^ t.rotate_left(19);
    let mut out = Vec::with_capacity(n);
    for _ in 0..n {
        state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        out.push((state >> 33) as u8);
    }
    out
}

/// Encrypts `plaintext` chunk-by-chunk through `enc.encrypt` and
/// returns the concatenated ciphertext stream. Mirrors the Python
/// `_stream_encrypt` helper.
fn stream_encrypt(enc: &mut Encryptor, plaintext: &[u8], chunk_size: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(plaintext.len() + plaintext.len() / 4 + 64);
    let mut i = 0;
    while i < plaintext.len() {
        let end = std::cmp::min(i + chunk_size, plaintext.len());
        let ct = enc.encrypt(&plaintext[i..end]).unwrap();
        out.extend_from_slice(&ct);
        i = end;
    }
    out
}

/// Drains the concatenated ciphertext stream chunk-by-chunk and
/// returns the recovered plaintext. Returns `Err` on a trailing
/// incomplete chunk so the test harness can assert the
/// plausible-failure contract from `TestEasyStreamErrors`. Mirrors
/// the Python `_stream_decrypt` helper.
fn stream_decrypt(enc: &mut Encryptor, ciphertext: &[u8]) -> Result<Vec<u8>, String> {
    let mut out = Vec::with_capacity(ciphertext.len());
    let mut accumulator: Vec<u8> = Vec::new();
    let mut feed_off = 0usize;
    let header_size = enc.header_size().unwrap() as usize;

    while feed_off < ciphertext.len() {
        let end = std::cmp::min(feed_off + SMALL_CHUNK, ciphertext.len());
        accumulator.extend_from_slice(&ciphertext[feed_off..end]);
        feed_off = end;
        // Drain any complete chunks already in the accumulator.
        loop {
            if accumulator.len() < header_size {
                break;
            }
            let chunk_len = enc.parse_chunk_len(&accumulator[..header_size]).unwrap();
            if accumulator.len() < chunk_len {
                break;
            }
            let chunk = &accumulator[..chunk_len];
            let pt = enc.decrypt(chunk).unwrap();
            out.extend_from_slice(&pt);
            accumulator.drain(..chunk_len);
        }
    }
    if !accumulator.is_empty() {
        return Err(format!(
            "trailing {} bytes do not form a complete chunk",
            accumulator.len()
        ));
    }
    Ok(out)
}

#[test]
fn stream_roundtrip_default_nonce_single() {
    let plaintext = token_bytes(SMALL_CHUNK * 5 + 17);
    let mut enc = Encryptor::new(Some("blake3"), Some(1024), Some("kmac256"), 1).unwrap();
    let ct = stream_encrypt(&mut enc, &plaintext, SMALL_CHUNK);
    let pt = stream_decrypt(&mut enc, &ct).unwrap();
    assert_eq!(pt.as_slice(), plaintext.as_slice());
}

#[test]
fn stream_roundtrip_non_default_nonce_single() {
    let plaintext = token_bytes(SMALL_CHUNK * 3 + 100);
    for &n in &[256, 512] {
        let mut enc = Encryptor::new(Some("blake3"), Some(1024), Some("kmac256"), 1)
            .unwrap();
        enc.set_nonce_bits(n).unwrap();
        let ct = stream_encrypt(&mut enc, &plaintext, SMALL_CHUNK);
        let pt = stream_decrypt(&mut enc, &ct).unwrap();
        assert_eq!(pt.as_slice(), plaintext.as_slice(), "nonce={n}");
    }
}

#[test]
fn stream_triple_roundtrip_default_nonce() {
    let plaintext = token_bytes(SMALL_CHUNK * 4 + 33);
    let mut enc = Encryptor::new(Some("blake3"), Some(1024), Some("kmac256"), 3).unwrap();
    let ct = stream_encrypt(&mut enc, &plaintext, SMALL_CHUNK);
    let pt = stream_decrypt(&mut enc, &ct).unwrap();
    assert_eq!(pt.as_slice(), plaintext.as_slice());
}

#[test]
fn stream_triple_roundtrip_non_default_nonce() {
    let plaintext = token_bytes(SMALL_CHUNK * 3);
    for &n in &[256, 512] {
        let mut enc = Encryptor::new(Some("blake3"), Some(1024), Some("kmac256"), 3)
            .unwrap();
        enc.set_nonce_bits(n).unwrap();
        let ct = stream_encrypt(&mut enc, &plaintext, SMALL_CHUNK);
        let pt = stream_decrypt(&mut enc, &ct).unwrap();
        assert_eq!(pt.as_slice(), plaintext.as_slice(), "nonce={n}");
    }
}

#[test]
fn stream_partial_chunk_raises() {
    // Feeding only a partial chunk to the streaming decoder surfaces
    // a `Err` on close — same plausible-failure contract as the
    // lower-level StreamDecryptor.
    let plaintext = vec![b'x'; 100];
    let mut enc = Encryptor::new(Some("blake3"), Some(1024), Some("kmac256"), 1).unwrap();
    let ct = stream_encrypt(&mut enc, &plaintext, SMALL_CHUNK);
    // Feed only 30 bytes — header complete (>= 20) but body
    // truncated. The drain loop must reject the trailing incomplete
    // chunk on close.
    let err = stream_decrypt(&mut enc, &ct[..30]).unwrap_err();
    assert!(err.contains("trailing"));
}

#[test]
fn parse_chunk_len_short_buffer() {
    let enc = Encryptor::new(Some("blake3"), Some(1024), Some("kmac256"), 1).unwrap();
    let h = enc.header_size().unwrap() as usize;
    let buf = vec![0u8; h - 1];
    let err = enc.parse_chunk_len(&buf).unwrap_err();
    assert_eq!(err.code(), itb::STATUS_BAD_INPUT);
}

#[test]
fn parse_chunk_len_zero_dim() {
    let enc = Encryptor::new(Some("blake3"), Some(1024), Some("kmac256"), 1).unwrap();
    let h = enc.header_size().unwrap() as usize;
    // header_size bytes, but width == 0.
    let hdr = vec![0u8; h];
    assert!(enc.parse_chunk_len(&hdr).is_err());
}
