//! Authenticated Streaming AEAD tests for the seed-based
//! `StreamEncryptorAuth` / `StreamDecryptorAuth` classes and their
//! free-function `encrypt_stream_auth` / `decrypt_stream_auth`
//! counterparts (Single + Triple Ouroboros at every native hash
//! width and across the three shipped MAC primitives).
//!
//! Coverage: per-(width × Single/Triple × MAC) round-trip;
//! reorder; truncate-tail; cross-stream replay; stream-prefix
//! tamper; empty stream; single-chunk; closed-encryptor preflight;
//! Drop lifetime.

use std::io::Cursor;

use itb::{
    decrypt_stream_auth, decrypt_stream_auth_triple, encrypt_stream_auth,
    encrypt_stream_auth_triple, Seed, StreamDecryptorAuth, StreamDecryptorAuth3,
    StreamEncryptorAuth, StreamEncryptorAuth3, MAC, STATUS_BAD_INPUT,
    STATUS_BAD_MAC, STATUS_EASY_CLOSED, STATUS_MAC_FAILURE,
    STATUS_STREAM_AFTER_FINAL, STATUS_STREAM_TRUNCATED,
};

const SMALL_CHUNK: usize = 4096;

fn pseudo_plaintext(n: usize) -> Vec<u8> {
    (0..n).map(|i| ((i * 31 + 7) & 0xff) as u8).collect()
}

fn mk_single(prim: &str) -> (Seed, Seed, Seed) {
    let n = Seed::new(prim, 1024).unwrap();
    let d = Seed::new(prim, 1024).unwrap();
    let s = Seed::new(prim, 1024).unwrap();
    (n, d, s)
}

#[allow(clippy::type_complexity)]
fn mk_triple(prim: &str) -> (Seed, Seed, Seed, Seed, Seed, Seed, Seed) {
    (
        Seed::new(prim, 1024).unwrap(),
        Seed::new(prim, 1024).unwrap(),
        Seed::new(prim, 1024).unwrap(),
        Seed::new(prim, 1024).unwrap(),
        Seed::new(prim, 1024).unwrap(),
        Seed::new(prim, 1024).unwrap(),
        Seed::new(prim, 1024).unwrap(),
    )
}

fn mac_for(name: &str) -> MAC {
    let key = vec![0x5Au8; 32];
    MAC::new(name, &key).unwrap()
}

fn mac_names() -> &'static [&'static str] {
    &["kmac256", "hmac-sha256", "hmac-blake3"]
}

fn primitives() -> &'static [&'static str] {
    // One PRF-grade primitive per width: 128-bit (siphash24),
    // 256-bit (blake3), 512-bit (areion512).
    &["siphash24", "blake3", "areion512"]
}

#[test]
fn auth_stream_single_roundtrip_matrix() {
    for &prim in primitives() {
        for &mn in mac_names() {
            let (n, d, s) = mk_single(prim);
            let mac = mac_for(mn);
            let plaintext = pseudo_plaintext(SMALL_CHUNK * 3 + 17);
            let mut ct: Vec<u8> = Vec::new();
            encrypt_stream_auth(
                &n, &d, &s, &mac,
                Cursor::new(&plaintext),
                &mut ct,
                SMALL_CHUNK,
            )
            .unwrap_or_else(|e| panic!("encrypt {prim}/{mn}: {e}"));
            assert!(ct.len() > 32, "{prim}/{mn}: ciphertext too short");
            let mut recovered: Vec<u8> = Vec::new();
            decrypt_stream_auth(
                &n, &d, &s, &mac,
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
fn auth_stream_triple_roundtrip_matrix() {
    for &prim in primitives() {
        for &mn in mac_names() {
            let (n, d1, d2, d3, s1, s2, s3) = mk_triple(prim);
            let mac = mac_for(mn);
            let plaintext = pseudo_plaintext(SMALL_CHUNK * 2 + 1);
            let mut ct: Vec<u8> = Vec::new();
            encrypt_stream_auth_triple(
                &n, &d1, &d2, &d3, &s1, &s2, &s3, &mac,
                Cursor::new(&plaintext),
                &mut ct,
                SMALL_CHUNK,
            )
            .unwrap_or_else(|e| panic!("triple encrypt {prim}/{mn}: {e}"));
            let mut recovered: Vec<u8> = Vec::new();
            decrypt_stream_auth_triple(
                &n, &d1, &d2, &d3, &s1, &s2, &s3, &mac,
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
fn auth_stream_empty() {
    let (n, d, s) = mk_single("blake3");
    let mac = mac_for("hmac-blake3");
    let mut ct: Vec<u8> = Vec::new();
    encrypt_stream_auth(
        &n, &d, &s, &mac,
        Cursor::new(&[][..]),
        &mut ct,
        SMALL_CHUNK,
    )
    .unwrap();
    assert!(ct.len() > 32, "empty stream still emits prefix + 1 chunk");
    let mut recovered: Vec<u8> = Vec::new();
    decrypt_stream_auth(
        &n, &d, &s, &mac,
        Cursor::new(&ct),
        &mut recovered,
        4096,
    )
    .unwrap();
    assert_eq!(recovered, b"");
}

#[test]
fn auth_stream_single_chunk() {
    let (n, d, s) = mk_single("blake3");
    let mac = mac_for("hmac-blake3");
    let plaintext = b"single short payload";
    let mut ct: Vec<u8> = Vec::new();
    encrypt_stream_auth(
        &n, &d, &s, &mac,
        Cursor::new(&plaintext[..]),
        &mut ct,
        SMALL_CHUNK,
    )
    .unwrap();
    let mut recovered: Vec<u8> = Vec::new();
    decrypt_stream_auth(
        &n, &d, &s, &mac,
        Cursor::new(&ct),
        &mut recovered,
        4096,
    )
    .unwrap();
    assert_eq!(recovered, plaintext);
}

/// Splits the auth-stream wire transcript into (32-byte prefix,
/// chunk-by-chunk vector). Read each chunk's length via
/// `parse_chunk_len` to walk the boundaries.
fn split_chunks(ct: &[u8]) -> (Vec<u8>, Vec<Vec<u8>>) {
    let prefix = ct[..32].to_vec();
    let header_size = itb::header_size() as usize;
    let mut chunks = Vec::new();
    let mut off = 32;
    while off < ct.len() {
        let chunk_len = itb::parse_chunk_len(&ct[off..off + header_size]).unwrap();
        chunks.push(ct[off..off + chunk_len].to_vec());
        off += chunk_len;
    }
    (prefix, chunks)
}

#[test]
fn auth_stream_reorder_detected() {
    // A 3-chunk stream — swap chunks 0 and 1 on the wire.
    let (n, d, s) = mk_single("blake3");
    let mac = mac_for("hmac-blake3");
    let plaintext = pseudo_plaintext(SMALL_CHUNK * 2 + 1);
    let mut ct: Vec<u8> = Vec::new();
    encrypt_stream_auth(
        &n, &d, &s, &mac,
        Cursor::new(&plaintext),
        &mut ct,
        SMALL_CHUNK,
    )
    .unwrap();
    let (prefix, mut chunks) = split_chunks(&ct);
    assert!(chunks.len() >= 3, "need ≥ 3 chunks for reorder test");
    chunks.swap(0, 1);
    let mut tampered = prefix;
    for c in &chunks {
        tampered.extend_from_slice(c);
    }
    let mut recovered: Vec<u8> = Vec::new();
    let res = decrypt_stream_auth(
        &n, &d, &s, &mac,
        Cursor::new(&tampered),
        &mut recovered,
        4096,
    );
    let err = res.expect_err("reorder must surface MAC failure");
    assert_eq!(err.code(), STATUS_MAC_FAILURE);
}

#[test]
fn auth_stream_truncate_tail_detected() {
    let (n, d, s) = mk_single("blake3");
    let mac = mac_for("hmac-blake3");
    let plaintext = pseudo_plaintext(SMALL_CHUNK * 2 + 1);
    let mut ct: Vec<u8> = Vec::new();
    encrypt_stream_auth(
        &n, &d, &s, &mac,
        Cursor::new(&plaintext),
        &mut ct,
        SMALL_CHUNK,
    )
    .unwrap();
    let (prefix, chunks) = split_chunks(&ct);
    assert!(chunks.len() >= 2);
    // Drop the last chunk.
    let mut truncated = prefix;
    for c in &chunks[..chunks.len() - 1] {
        truncated.extend_from_slice(c);
    }
    let mut recovered: Vec<u8> = Vec::new();
    let err = decrypt_stream_auth(
        &n, &d, &s, &mac,
        Cursor::new(&truncated),
        &mut recovered,
        4096,
    )
    .expect_err("truncate must surface STREAM_TRUNCATED");
    assert_eq!(err.code(), STATUS_STREAM_TRUNCATED);
}

#[test]
fn auth_stream_after_final_detected() {
    let (n, d, s) = mk_single("blake3");
    let mac = mac_for("hmac-blake3");
    // Encrypt two streams, splice the first chunk of stream B onto
    // the tail of stream A so trailing bytes follow the terminator.
    let pa = pseudo_plaintext(64);
    let pb = pseudo_plaintext(SMALL_CHUNK * 2);
    let mut ct_a: Vec<u8> = Vec::new();
    encrypt_stream_auth(&n, &d, &s, &mac, Cursor::new(&pa), &mut ct_a, SMALL_CHUNK).unwrap();
    let mut ct_b: Vec<u8> = Vec::new();
    encrypt_stream_auth(&n, &d, &s, &mac, Cursor::new(&pb), &mut ct_b, SMALL_CHUNK).unwrap();
    // Append the first chunk of B to A.
    let (_, chunks_b) = split_chunks(&ct_b);
    ct_a.extend_from_slice(&chunks_b[0]);
    let mut recovered: Vec<u8> = Vec::new();
    let err = decrypt_stream_auth(
        &n, &d, &s, &mac,
        Cursor::new(&ct_a),
        &mut recovered,
        4096,
    )
    .expect_err("trailing chunk must surface AFTER_FINAL");
    assert_eq!(err.code(), STATUS_STREAM_AFTER_FINAL);
}

#[test]
fn auth_stream_cross_stream_replay_detected() {
    let (n, d, s) = mk_single("blake3");
    let mac = mac_for("hmac-blake3");
    // Two streams under the same seeds + MAC key but different
    // helper-generated stream_id.
    let pa = pseudo_plaintext(SMALL_CHUNK * 2);
    let pb = pseudo_plaintext(SMALL_CHUNK * 2);
    let mut ct_a: Vec<u8> = Vec::new();
    encrypt_stream_auth(&n, &d, &s, &mac, Cursor::new(&pa), &mut ct_a, SMALL_CHUNK).unwrap();
    let mut ct_b: Vec<u8> = Vec::new();
    encrypt_stream_auth(&n, &d, &s, &mac, Cursor::new(&pb), &mut ct_b, SMALL_CHUNK).unwrap();
    let (prefix_a, chunks_a) = split_chunks(&ct_a);
    let (_, chunks_b) = split_chunks(&ct_b);
    // Splice stream-B's chunk 0 into stream-A's position 0 under
    // stream-A's prefix.
    let mut spliced = prefix_a;
    spliced.extend_from_slice(&chunks_b[0]);
    for c in &chunks_a[1..] {
        spliced.extend_from_slice(c);
    }
    let mut recovered: Vec<u8> = Vec::new();
    let err = decrypt_stream_auth(
        &n, &d, &s, &mac,
        Cursor::new(&spliced),
        &mut recovered,
        4096,
    )
    .expect_err("cross-stream replay must surface MAC failure");
    assert_eq!(err.code(), STATUS_MAC_FAILURE);
}

#[test]
fn auth_stream_prefix_tamper_detected() {
    let (n, d, s) = mk_single("blake3");
    let mac = mac_for("hmac-blake3");
    let plaintext = pseudo_plaintext(SMALL_CHUNK * 2);
    let mut ct: Vec<u8> = Vec::new();
    encrypt_stream_auth(
        &n, &d, &s, &mac,
        Cursor::new(&plaintext),
        &mut ct,
        SMALL_CHUNK,
    )
    .unwrap();
    // Flip a byte in the 32-byte prefix.
    ct[5] ^= 0x80;
    let mut recovered: Vec<u8> = Vec::new();
    let err = decrypt_stream_auth(
        &n, &d, &s, &mac,
        Cursor::new(&ct),
        &mut recovered,
        4096,
    )
    .expect_err("prefix tamper must surface MAC failure");
    assert!(
        err.code() == STATUS_MAC_FAILURE || err.code() == STATUS_BAD_MAC,
        "expected MAC failure-class code, got {}",
        err.code()
    );
}

#[test]
fn auth_stream_class_lifecycle() {
    // Closed-state preflight: write / close after close = error.
    let (n, d, s) = mk_single("blake3");
    let mac = mac_for("hmac-blake3");
    let mut sink: Vec<u8> = Vec::new();
    {
        let mut enc =
            StreamEncryptorAuth::new(&n, &d, &s, &mac, &mut sink, SMALL_CHUNK).unwrap();
        enc.write(b"hello").unwrap();
        enc.close().unwrap();
        let err = enc.write(b"after close").expect_err("write after close");
        assert_eq!(err.code(), STATUS_EASY_CLOSED);
    }
    // Drop without close still flushes (best-effort) — round-trip.
    let mut sink: Vec<u8> = Vec::new();
    {
        let mut enc =
            StreamEncryptorAuth::new(&n, &d, &s, &mac, &mut sink, SMALL_CHUNK).unwrap();
        enc.write(b"drop-flush").unwrap();
        // Drop here triggers close().
    }
    let mut recovered: Vec<u8> = Vec::new();
    decrypt_stream_auth(
        &n, &d, &s, &mac,
        Cursor::new(&sink),
        &mut recovered,
        4096,
    )
    .unwrap();
    assert_eq!(recovered, b"drop-flush");
}

#[test]
fn auth_stream_class_decrypt_lifecycle() {
    let (n, d, s) = mk_single("blake3");
    let mac = mac_for("hmac-blake3");
    let plaintext = b"decrypt-class round trip";
    let mut ct: Vec<u8> = Vec::new();
    encrypt_stream_auth(
        &n, &d, &s, &mac,
        Cursor::new(&plaintext[..]),
        &mut ct,
        SMALL_CHUNK,
    )
    .unwrap();
    let mut sink: Vec<u8> = Vec::new();
    {
        let mut dec = StreamDecryptorAuth::new(&n, &d, &s, &mac, &mut sink).unwrap();
        dec.feed(&ct).unwrap();
        dec.close().unwrap();
        let err = dec.feed(b"after close").expect_err("feed after close");
        assert_eq!(err.code(), STATUS_EASY_CLOSED);
    }
    assert_eq!(sink, plaintext);
}

#[test]
fn auth_stream_triple_class_roundtrip() {
    let (n, d1, d2, d3, s1, s2, s3) = mk_triple("blake3");
    let mac = mac_for("kmac256");
    let plaintext = pseudo_plaintext(SMALL_CHUNK * 2 + 5);
    let mut sink: Vec<u8> = Vec::new();
    {
        let mut enc = StreamEncryptorAuth3::new(
            &n, &d1, &d2, &d3, &s1, &s2, &s3, &mac, &mut sink, SMALL_CHUNK,
        )
        .unwrap();
        enc.write(&plaintext[..1024]).unwrap();
        enc.write(&plaintext[1024..]).unwrap();
        enc.close().unwrap();
    }
    let mut recovered: Vec<u8> = Vec::new();
    {
        let mut dec = StreamDecryptorAuth3::new(
            &n, &d1, &d2, &d3, &s1, &s2, &s3, &mac, &mut recovered,
        )
        .unwrap();
        dec.feed(&sink).unwrap();
        dec.close().unwrap();
    }
    assert_eq!(recovered, plaintext);
}

#[test]
fn auth_stream_truncate_below_prefix() {
    // Truncate the stream below the 32-byte prefix.
    let (n, d, s) = mk_single("blake3");
    let mac = mac_for("hmac-blake3");
    let mut ct: Vec<u8> = Vec::new();
    encrypt_stream_auth(
        &n, &d, &s, &mac,
        Cursor::new(b"some text"),
        &mut ct,
        SMALL_CHUNK,
    )
    .unwrap();
    let head = &ct[..16]; // less than 32 bytes
    let mut recovered: Vec<u8> = Vec::new();
    let err = decrypt_stream_auth(
        &n, &d, &s, &mac,
        Cursor::new(head),
        &mut recovered,
        4096,
    )
    .expect_err("partial prefix must surface BAD_INPUT");
    assert_eq!(err.code(), STATUS_BAD_INPUT);
}
