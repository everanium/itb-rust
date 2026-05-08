//! Authenticated Streaming AEAD tests for the Easy Mode encryptor
//! (`Encryptor::encrypt_stream_auth` / `Encryptor::decrypt_stream_auth`).
//! Mirrors the seed-based suite in `test_streams_auth.rs` at the
//! Encryptor abstraction level.

use std::io::Cursor;

use itb::{
    Encryptor, STATUS_BAD_INPUT, STATUS_EASY_CLOSED, STATUS_MAC_FAILURE,
    STATUS_STREAM_AFTER_FINAL, STATUS_STREAM_TRUNCATED,
};

const SMALL_CHUNK: usize = 4096;

fn pseudo_plaintext(n: usize) -> Vec<u8> {
    (0..n).map(|i| ((i * 17 + 3) & 0xff) as u8).collect()
}

fn mk_encryptor(prim: &str, mac: &str, mode: i32) -> Encryptor {
    Encryptor::new(Some(prim), Some(1024), Some(mac), mode).unwrap()
}

fn primitives() -> &'static [&'static str] {
    &["siphash24", "blake3", "areion512"]
}

fn mac_names() -> &'static [&'static str] {
    &["kmac256", "hmac-sha256", "hmac-blake3"]
}

#[test]
fn easy_auth_stream_single_roundtrip_matrix() {
    for &prim in primitives() {
        for &mn in mac_names() {
            let plaintext = pseudo_plaintext(SMALL_CHUNK * 2 + 11);
            let mut enc = mk_encryptor(prim, mn, 1);
            let mut ct: Vec<u8> = Vec::new();
            enc.encrypt_stream_auth(
                Cursor::new(&plaintext),
                &mut ct,
                SMALL_CHUNK,
            )
            .unwrap_or_else(|e| panic!("encrypt {prim}/{mn}: {e}"));
            assert!(ct.len() > 32);
            let mut recovered: Vec<u8> = Vec::new();
            enc.decrypt_stream_auth(
                Cursor::new(&ct),
                &mut recovered,
                4096,
            )
            .unwrap_or_else(|e| panic!("decrypt {prim}/{mn}: {e}"));
            assert_eq!(recovered, plaintext, "{prim}/{mn}");
        }
    }
}

#[test]
fn easy_auth_stream_triple_roundtrip_matrix() {
    for &prim in primitives() {
        for &mn in mac_names() {
            let plaintext = pseudo_plaintext(SMALL_CHUNK * 2 + 7);
            let mut enc = mk_encryptor(prim, mn, 3);
            let mut ct: Vec<u8> = Vec::new();
            enc.encrypt_stream_auth(
                Cursor::new(&plaintext),
                &mut ct,
                SMALL_CHUNK,
            )
            .unwrap_or_else(|e| panic!("triple encrypt {prim}/{mn}: {e}"));
            let mut recovered: Vec<u8> = Vec::new();
            enc.decrypt_stream_auth(
                Cursor::new(&ct),
                &mut recovered,
                4096,
            )
            .unwrap_or_else(|e| panic!("triple decrypt {prim}/{mn}: {e}"));
            assert_eq!(recovered, plaintext, "{prim}/{mn}");
        }
    }
}

#[test]
fn easy_auth_stream_empty() {
    let mut enc = mk_encryptor("blake3", "hmac-blake3", 1);
    let mut ct: Vec<u8> = Vec::new();
    enc.encrypt_stream_auth(Cursor::new(&[][..]), &mut ct, SMALL_CHUNK)
        .unwrap();
    assert!(ct.len() > 32);
    let mut recovered: Vec<u8> = Vec::new();
    enc.decrypt_stream_auth(Cursor::new(&ct), &mut recovered, 4096)
        .unwrap();
    assert_eq!(recovered, b"");
}

#[test]
fn easy_auth_stream_single_chunk() {
    let mut enc = mk_encryptor("blake3", "kmac256", 1);
    let pt = b"single short stream payload";
    let mut ct: Vec<u8> = Vec::new();
    enc.encrypt_stream_auth(Cursor::new(&pt[..]), &mut ct, SMALL_CHUNK)
        .unwrap();
    let mut recovered: Vec<u8> = Vec::new();
    enc.decrypt_stream_auth(Cursor::new(&ct), &mut recovered, 4096)
        .unwrap();
    assert_eq!(recovered, pt);
}

fn split_chunks_easy(enc: &Encryptor, ct: &[u8]) -> (Vec<u8>, Vec<Vec<u8>>) {
    let prefix = ct[..32].to_vec();
    let header_size = enc.header_size().unwrap() as usize;
    let mut chunks = Vec::new();
    let mut off = 32;
    while off < ct.len() {
        let chunk_len = enc.parse_chunk_len(&ct[off..off + header_size]).unwrap();
        chunks.push(ct[off..off + chunk_len].to_vec());
        off += chunk_len;
    }
    (prefix, chunks)
}

#[test]
fn easy_auth_stream_reorder_detected() {
    let mut enc = mk_encryptor("blake3", "hmac-blake3", 1);
    let plaintext = pseudo_plaintext(SMALL_CHUNK * 2 + 5);
    let mut ct: Vec<u8> = Vec::new();
    enc.encrypt_stream_auth(
        Cursor::new(&plaintext),
        &mut ct,
        SMALL_CHUNK,
    )
    .unwrap();
    let (prefix, mut chunks) = split_chunks_easy(&enc, &ct);
    assert!(chunks.len() >= 3);
    chunks.swap(0, 1);
    let mut tampered = prefix;
    for c in &chunks {
        tampered.extend_from_slice(c);
    }
    let mut recovered: Vec<u8> = Vec::new();
    let err = enc
        .decrypt_stream_auth(Cursor::new(&tampered), &mut recovered, 4096)
        .expect_err("reorder must surface MAC failure");
    assert_eq!(err.code(), STATUS_MAC_FAILURE);
}

#[test]
fn easy_auth_stream_truncate_tail_detected() {
    let mut enc = mk_encryptor("blake3", "hmac-blake3", 1);
    let plaintext = pseudo_plaintext(SMALL_CHUNK * 2 + 1);
    let mut ct: Vec<u8> = Vec::new();
    enc.encrypt_stream_auth(
        Cursor::new(&plaintext),
        &mut ct,
        SMALL_CHUNK,
    )
    .unwrap();
    let (prefix, chunks) = split_chunks_easy(&enc, &ct);
    let mut truncated = prefix;
    for c in &chunks[..chunks.len() - 1] {
        truncated.extend_from_slice(c);
    }
    let mut recovered: Vec<u8> = Vec::new();
    let err = enc
        .decrypt_stream_auth(Cursor::new(&truncated), &mut recovered, 4096)
        .expect_err("truncate must surface TRUNCATED");
    assert_eq!(err.code(), STATUS_STREAM_TRUNCATED);
}

#[test]
fn easy_auth_stream_after_final_detected() {
    let mut enc = mk_encryptor("blake3", "hmac-blake3", 1);
    let pa = pseudo_plaintext(64);
    let pb = pseudo_plaintext(SMALL_CHUNK * 2);
    let mut ct_a: Vec<u8> = Vec::new();
    enc.encrypt_stream_auth(Cursor::new(&pa), &mut ct_a, SMALL_CHUNK)
        .unwrap();
    let mut ct_b: Vec<u8> = Vec::new();
    enc.encrypt_stream_auth(Cursor::new(&pb), &mut ct_b, SMALL_CHUNK)
        .unwrap();
    let (_, chunks_b) = split_chunks_easy(&enc, &ct_b);
    ct_a.extend_from_slice(&chunks_b[0]);
    let mut recovered: Vec<u8> = Vec::new();
    let err = enc
        .decrypt_stream_auth(Cursor::new(&ct_a), &mut recovered, 4096)
        .expect_err("after-final must surface AFTER_FINAL");
    assert_eq!(err.code(), STATUS_STREAM_AFTER_FINAL);
}

#[test]
fn easy_auth_stream_cross_stream_replay_detected() {
    let mut enc = mk_encryptor("blake3", "hmac-blake3", 1);
    let pa = pseudo_plaintext(SMALL_CHUNK * 2);
    let pb = pseudo_plaintext(SMALL_CHUNK * 2);
    let mut ct_a: Vec<u8> = Vec::new();
    enc.encrypt_stream_auth(Cursor::new(&pa), &mut ct_a, SMALL_CHUNK)
        .unwrap();
    let mut ct_b: Vec<u8> = Vec::new();
    enc.encrypt_stream_auth(Cursor::new(&pb), &mut ct_b, SMALL_CHUNK)
        .unwrap();
    let (prefix_a, chunks_a) = split_chunks_easy(&enc, &ct_a);
    let (_, chunks_b) = split_chunks_easy(&enc, &ct_b);
    let mut spliced = prefix_a;
    spliced.extend_from_slice(&chunks_b[0]);
    for c in &chunks_a[1..] {
        spliced.extend_from_slice(c);
    }
    let mut recovered: Vec<u8> = Vec::new();
    let err = enc
        .decrypt_stream_auth(Cursor::new(&spliced), &mut recovered, 4096)
        .expect_err("cross-stream replay must surface MAC failure");
    assert_eq!(err.code(), STATUS_MAC_FAILURE);
}

#[test]
fn easy_auth_stream_prefix_tamper_detected() {
    let mut enc = mk_encryptor("blake3", "hmac-blake3", 1);
    let plaintext = pseudo_plaintext(SMALL_CHUNK * 2);
    let mut ct: Vec<u8> = Vec::new();
    enc.encrypt_stream_auth(Cursor::new(&plaintext), &mut ct, SMALL_CHUNK)
        .unwrap();
    ct[5] ^= 0x80;
    let mut recovered: Vec<u8> = Vec::new();
    let res = enc.decrypt_stream_auth(Cursor::new(&ct), &mut recovered, 4096);
    let err = res.expect_err("prefix tamper must surface MAC failure");
    assert_eq!(err.code(), STATUS_MAC_FAILURE);
}

#[test]
fn easy_auth_stream_closed_preflight() {
    let mut enc = mk_encryptor("blake3", "hmac-blake3", 1);
    enc.close().unwrap();
    let mut ct: Vec<u8> = Vec::new();
    let err = enc
        .encrypt_stream_auth(Cursor::new(b"data"), &mut ct, SMALL_CHUNK)
        .expect_err("closed encryptor must reject encrypt_stream_auth");
    assert_eq!(err.code(), STATUS_EASY_CLOSED);
    let mut recovered: Vec<u8> = Vec::new();
    let err = enc
        .decrypt_stream_auth(Cursor::new(&[][..]), &mut recovered, 4096)
        .expect_err("closed encryptor must reject decrypt_stream_auth");
    assert_eq!(err.code(), STATUS_EASY_CLOSED);
}

#[test]
fn easy_auth_stream_truncate_below_prefix() {
    let mut enc = mk_encryptor("blake3", "hmac-blake3", 1);
    let mut ct: Vec<u8> = Vec::new();
    enc.encrypt_stream_auth(Cursor::new(b"abc"), &mut ct, SMALL_CHUNK)
        .unwrap();
    let head = &ct[..10];
    let mut recovered: Vec<u8> = Vec::new();
    let err = enc
        .decrypt_stream_auth(Cursor::new(head), &mut recovered, 4096)
        .expect_err("partial prefix must surface BAD_INPUT");
    assert_eq!(err.code(), STATUS_BAD_INPUT);
}
