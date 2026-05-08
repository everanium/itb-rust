//! Streaming roundtrips across non-default nonce sizes.
//!
//! Mirror of `test_class_roundtrip_non_default_nonce` and
//! `test_encrypt_stream_across_nonce_sizes` (Single + Triple) from
//! `bindings/python/tests/test_streams.py`. These tests mutate the
//! process-global `nonce_bits` atomic; they live in their own
//! integration-test binary so they are isolated from
//! `tests/test_streams.rs` (which exercises default-nonce streaming
//! and cannot acquire `serial_lock` without modifying its
//! pre-existing tests). Inside this binary every `#[test]` holds
//! `common::serial_lock()`.

use itb::{StreamDecryptor, StreamDecryptor3, StreamEncryptor, StreamEncryptor3, Seed};

#[path = "common/mod.rs"]
mod common;

const SMALL_CHUNK: usize = 4096;

fn pseudo_payload(n: usize) -> Vec<u8> {
    (0..n).map(|i| ((i * 31 + 11) & 0xff) as u8).collect()
}

fn restore_nonce_bits(orig: i32) {
    itb::set_nonce_bits(orig).expect("restore nonce bits");
}

#[test]
fn class_roundtrip_non_default_nonce_single() {
    let _g = common::serial_lock();
    let orig = itb::get_nonce_bits();
    let plaintext = pseudo_payload(SMALL_CHUNK * 3 + 100);
    for n in [256, 512] {
        itb::set_nonce_bits(n).unwrap();
        let noise = Seed::new("blake3", 1024).unwrap();
        let data = Seed::new("blake3", 1024).unwrap();
        let start = Seed::new("blake3", 1024).unwrap();

        let mut cbuf: Vec<u8> = Vec::new();
        {
            let mut enc =
                StreamEncryptor::new(&noise, &data, &start, &mut cbuf, SMALL_CHUNK).unwrap();
            enc.write(&plaintext).unwrap();
            enc.close().unwrap();
        }

        let mut pbuf: Vec<u8> = Vec::new();
        {
            let mut dec = StreamDecryptor::new(&noise, &data, &start, &mut pbuf).unwrap();
            dec.feed(&cbuf).unwrap();
            dec.close().unwrap();
        }
        assert_eq!(pbuf, plaintext, "nonce={n} mismatch");
    }
    restore_nonce_bits(orig);
}

#[test]
fn encrypt_stream_across_nonce_sizes_single() {
    let _g = common::serial_lock();
    let orig = itb::get_nonce_bits();
    let plaintext = pseudo_payload(SMALL_CHUNK * 3 + 256);
    for n in [128, 256, 512] {
        itb::set_nonce_bits(n).unwrap();
        let noise = Seed::new("blake3", 1024).unwrap();
        let data = Seed::new("blake3", 1024).unwrap();
        let start = Seed::new("blake3", 1024).unwrap();

        let mut cbuf: Vec<u8> = Vec::new();
        itb::encrypt_stream(&noise, &data, &start, &plaintext[..], &mut cbuf, SMALL_CHUNK)
            .unwrap();

        let mut pbuf: Vec<u8> = Vec::new();
        itb::decrypt_stream(&noise, &data, &start, &cbuf[..], &mut pbuf, SMALL_CHUNK)
            .unwrap();
        assert_eq!(pbuf, plaintext, "nonce={n} mismatch");
    }
    restore_nonce_bits(orig);
}

#[test]
fn class_roundtrip_non_default_nonce_triple() {
    let _g = common::serial_lock();
    let orig = itb::get_nonce_bits();
    let plaintext = pseudo_payload(SMALL_CHUNK * 3);
    for n in [256, 512] {
        itb::set_nonce_bits(n).unwrap();
        let noise = Seed::new("blake3", 1024).unwrap();
        let d1 = Seed::new("blake3", 1024).unwrap();
        let d2 = Seed::new("blake3", 1024).unwrap();
        let d3 = Seed::new("blake3", 1024).unwrap();
        let s1 = Seed::new("blake3", 1024).unwrap();
        let s2 = Seed::new("blake3", 1024).unwrap();
        let s3 = Seed::new("blake3", 1024).unwrap();

        let mut cbuf: Vec<u8> = Vec::new();
        {
            let mut enc = StreamEncryptor3::new(
                &noise, &d1, &d2, &d3, &s1, &s2, &s3, &mut cbuf, SMALL_CHUNK,
            )
            .unwrap();
            enc.write(&plaintext).unwrap();
            enc.close().unwrap();
        }

        let mut pbuf: Vec<u8> = Vec::new();
        {
            let mut dec = StreamDecryptor3::new(
                &noise, &d1, &d2, &d3, &s1, &s2, &s3, &mut pbuf,
            )
            .unwrap();
            dec.feed(&cbuf).unwrap();
            dec.close().unwrap();
        }
        assert_eq!(pbuf, plaintext, "nonce={n} mismatch");
    }
    restore_nonce_bits(orig);
}

#[test]
fn encrypt_stream_triple_across_nonce_sizes() {
    let _g = common::serial_lock();
    let orig = itb::get_nonce_bits();
    let plaintext = pseudo_payload(SMALL_CHUNK * 3 + 100);
    for n in [128, 256, 512] {
        itb::set_nonce_bits(n).unwrap();
        let noise = Seed::new("blake3", 1024).unwrap();
        let d1 = Seed::new("blake3", 1024).unwrap();
        let d2 = Seed::new("blake3", 1024).unwrap();
        let d3 = Seed::new("blake3", 1024).unwrap();
        let s1 = Seed::new("blake3", 1024).unwrap();
        let s2 = Seed::new("blake3", 1024).unwrap();
        let s3 = Seed::new("blake3", 1024).unwrap();

        let mut cbuf: Vec<u8> = Vec::new();
        itb::encrypt_stream_triple(
            &noise, &d1, &d2, &d3, &s1, &s2, &s3, &plaintext[..], &mut cbuf, SMALL_CHUNK,
        )
        .unwrap();

        let mut pbuf: Vec<u8> = Vec::new();
        itb::decrypt_stream_triple(
            &noise, &d1, &d2, &d3, &s1, &s2, &s3, &cbuf[..], &mut pbuf, SMALL_CHUNK,
        )
        .unwrap();
        assert_eq!(pbuf, plaintext, "nonce={n} mismatch");
    }
    restore_nonce_bits(orig);
}
