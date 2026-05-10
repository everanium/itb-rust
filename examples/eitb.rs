//! Rust eitb — runs every wrapper × ITB example end-to-end.
//!
//! Mirrors `cmd/eitb/main.go` adapted to the Rust binding asymmetry:
//! the binding has no `std::io::Write` / `std::io::Read` adapter pair
//! for Non-AEAD streaming wrap surfaces (Streaming AEAD does have
//! file-like helpers, but the wrap layer still goes through the
//! `WrapStreamWriter::update` / `UnwrapStreamReader::update` byte
//! pump). The Non-AEAD streaming arm covers the User-Driven Loop
//! variant only — caller produces an ITB ciphertext per chunk via
//! `Encryptor::encrypt(chunk)` (or the low-level [`itb::encrypt`]),
//! frames `u32_LE_len || ct`, and pushes through the wrap-stream
//! writer.
//!
//! Matrix: 8 examples × 3 outer ciphers (aes / chacha / siphash) =
//! 24 PASS/FAIL cells.
//!
//! Examples covered:
//!
//!   - aead-easy-io               Streaming AEAD Easy   (MAC Authenticated, IO-Driven)
//!   - aead-lowlevel-io           Streaming AEAD Low-Level (MAC Authenticated, IO-Driven)
//!   - noaead-easy-userloop       Streaming Easy        (No MAC, User-Driven Loop)
//!   - noaead-lowlevel-userloop   Streaming Low-Level   (No MAC, User-Driven Loop)
//!   - message-easy-nomac         Easy Single Message      (No MAC)
//!   - message-easy-auth          Easy Single Message      (MAC Authenticated)
//!   - message-lowlevel-nomac     Low-Level Single Message (No MAC)
//!   - message-lowlevel-auth      Low-Level Single Message (MAC Authenticated)
//!
//! Single-message examples encrypt 1024 bytes; streaming examples
//! encrypt 64 KiB through 16 KiB chunks. Each example runs sender +
//! receiver in the same process, wraps the ITB ciphertext under the
//! chosen outer cipher, hands the wrapped bytes to the receiver path,
//! and verifies sha256 byte-equality of the recovered plaintext
//! against the original.
//!
//! Usage:
//!
//!     cargo run --release --example eitb
//!     cargo run --release --example eitb -- --example aead
//!     cargo run --release --example eitb -- --cipher aes -v

use std::env;
use std::io::Cursor;
use std::process::ExitCode;

use itb::wrapper::{self, Cipher, UnwrapStreamReader, WrapStreamWriter};
use itb::{Encryptor, Seed, MAC};

const SINGLE_MESSAGE_BYTES: usize = 1024;
const STREAM_BYTES: usize = 64 * 1024;
const STREAM_CHUNK_SIZE: usize = 16 * 1024;

// --------------------------------------------------------------------
// Random fill — cryptographic via OS CSPRNG. Mirrors the wrapper
// module's internal helper but kept local so the example does not
// need to expose the wrapper's private function.
// --------------------------------------------------------------------

fn rand_bytes(n: usize) -> Vec<u8> {
    let mut buf = vec![0u8; n];
    #[cfg(unix)]
    {
        use std::fs::File;
        use std::io::Read;
        let mut f = File::open("/dev/urandom").expect("open /dev/urandom");
        f.read_exact(&mut buf).expect("/dev/urandom read");
    }
    #[cfg(not(unix))]
    {
        // Best-effort fallback for non-Unix targets — deterministic
        // mixing only suitable for self-test fixtures, NOT a CSPRNG.
        let salt = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);
        let mut state = salt;
        for b in buf.iter_mut() {
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            *b = (state >> 33) as u8;
        }
    }
    buf
}

fn sha256_short(b: &[u8]) -> String {
    // Lightweight inline SHA-256 — mirrors what `cmd/eitb` prints. To
    // avoid pulling a new dependency, use an FFI-free hashing path:
    // since `libitb` itself does not export SHA-256, fall back to a
    // simple FNV-1a 64-bit fingerprint that is sufficient for the
    // diagnostic "they don't match" line at the matrix tail. The
    // verification itself uses byte-equality, not the fingerprint.
    let mut h: u64 = 0xcbf29ce484222325;
    for &x in b {
        h ^= x as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    format!("{:016x}", h)
}

// --------------------------------------------------------------------
// Common helpers
// --------------------------------------------------------------------

fn build_easy(mac: Option<&str>, key_bits: i32) -> Encryptor {
    let enc = Encryptor::new(Some("areion512"), Some(key_bits), mac, 1)
        .expect("Encryptor::new(areion512)");
    enc.set_nonce_bits(512).expect("set_nonce_bits");
    enc.set_barrier_fill(4).expect("set_barrier_fill");
    enc.set_bit_soup(1).expect("set_bit_soup");
    enc.set_lock_soup(1).expect("set_lock_soup");
    enc
}

fn build_three_seeds(key_bits: i32) -> [Seed; 3] {
    [
        Seed::new("areion512", key_bits).expect("Seed::new noise"),
        Seed::new("areion512", key_bits).expect("Seed::new data"),
        Seed::new("areion512", key_bits).expect("Seed::new start"),
    ]
}

fn apply_lowlevel_config() {
    itb::set_nonce_bits(512).expect("set_nonce_bits");
    itb::set_barrier_fill(4).expect("set_barrier_fill");
    itb::set_bit_soup(1).expect("set_bit_soup");
    itb::set_lock_soup(1).expect("set_lock_soup");
}

// --------------------------------------------------------------------
// Streaming AEAD Easy (MAC Authenticated, IO-Driven)
// --------------------------------------------------------------------

fn run_aead_easy_io(cipher: Cipher, plaintext: &[u8]) -> Result<(Vec<u8>, usize), String> {
    let mut enc = build_easy(Some("hmac-blake3"), 1024);
    let outer_key = wrapper::generate_key(cipher).map_err(|e| format!("generate_key: {e}"))?;

    // Sender — encrypt the bytestream into an in-memory buffer, then
    // wrap the entire bytestream in one keystream session.
    let mut inner: Vec<u8> = Vec::new();
    enc.encrypt_stream_auth(Cursor::new(plaintext), &mut inner, STREAM_CHUNK_SIZE)
        .map_err(|e| format!("encrypt_stream_auth: {e}"))?;
    let mut writer = WrapStreamWriter::new(cipher, &outer_key)
        .map_err(|e| format!("WrapStreamWriter::new: {e}"))?;
    let mut wire = writer.nonce().to_vec();
    wire.extend_from_slice(
        &writer
            .update(&inner)
            .map_err(|e| format!("wrap update: {e}"))?,
    );
    writer.close().map_err(|e| format!("wrap close: {e}"))?;
    let wire_n = wire.len();

    // Receiver — strip the leading nonce, unwrap the body, decrypt.
    let nlen = wrapper::nonce_size(cipher).map_err(|e| format!("nonce_size: {e}"))?;
    let mut reader = UnwrapStreamReader::new(cipher, &outer_key, &wire[..nlen])
        .map_err(|e| format!("UnwrapStreamReader::new: {e}"))?;
    let inner_wire = reader
        .update(&wire[nlen..])
        .map_err(|e| format!("unwrap update: {e}"))?;
    reader.close().map_err(|e| format!("unwrap close: {e}"))?;

    let mut out: Vec<u8> = Vec::new();
    enc.decrypt_stream_auth(Cursor::new(inner_wire), &mut out, STREAM_CHUNK_SIZE)
        .map_err(|e| format!("decrypt_stream_auth: {e}"))?;
    Ok((out, wire_n))
}

// --------------------------------------------------------------------
// Streaming AEAD Low-Level (MAC Authenticated, IO-Driven)
// --------------------------------------------------------------------

fn run_aead_lowlevel_io(cipher: Cipher, plaintext: &[u8]) -> Result<(Vec<u8>, usize), String> {
    apply_lowlevel_config();
    let seeds = build_three_seeds(1024);
    let mac_key = rand_bytes(32);
    let mac = MAC::new("hmac-blake3", &mac_key).map_err(|e| format!("MAC::new: {e}"))?;
    let outer_key = wrapper::generate_key(cipher).map_err(|e| format!("generate_key: {e}"))?;

    let mut inner: Vec<u8> = Vec::new();
    itb::encrypt_stream_auth(
        &seeds[0],
        &seeds[1],
        &seeds[2],
        &mac,
        Cursor::new(plaintext),
        &mut inner,
        STREAM_CHUNK_SIZE,
    )
    .map_err(|e| format!("encrypt_stream_auth: {e}"))?;

    let mut writer = WrapStreamWriter::new(cipher, &outer_key)
        .map_err(|e| format!("WrapStreamWriter::new: {e}"))?;
    let mut wire = writer.nonce().to_vec();
    wire.extend_from_slice(
        &writer
            .update(&inner)
            .map_err(|e| format!("wrap update: {e}"))?,
    );
    writer.close().map_err(|e| format!("wrap close: {e}"))?;
    let wire_n = wire.len();

    let nlen = wrapper::nonce_size(cipher).map_err(|e| format!("nonce_size: {e}"))?;
    let mut reader = UnwrapStreamReader::new(cipher, &outer_key, &wire[..nlen])
        .map_err(|e| format!("UnwrapStreamReader::new: {e}"))?;
    let inner_wire = reader
        .update(&wire[nlen..])
        .map_err(|e| format!("unwrap update: {e}"))?;
    reader.close().map_err(|e| format!("unwrap close: {e}"))?;

    let mut out: Vec<u8> = Vec::new();
    itb::decrypt_stream_auth(
        &seeds[0],
        &seeds[1],
        &seeds[2],
        &mac,
        Cursor::new(inner_wire),
        &mut out,
        STREAM_CHUNK_SIZE,
    )
    .map_err(|e| format!("decrypt_stream_auth: {e}"))?;
    Ok((out, wire_n))
}

// --------------------------------------------------------------------
// Streaming Easy (No MAC, User-Driven Loop)
//
// Per-chunk encrypt + caller-side u32_LE framing emitted through one
// wrap-stream session — both the length prefix and each chunk body
// pass through the same keystream so neither shows in cleartext.
// --------------------------------------------------------------------

fn run_noaead_easy_userloop(cipher: Cipher, plaintext: &[u8]) -> Result<(Vec<u8>, usize), String> {
    let mut enc = build_easy(None, 1024);
    let outer_key = wrapper::generate_key(cipher).map_err(|e| format!("generate_key: {e}"))?;

    // Sender
    let mut writer = WrapStreamWriter::new(cipher, &outer_key)
        .map_err(|e| format!("WrapStreamWriter::new: {e}"))?;
    let mut wire = writer.nonce().to_vec();
    let mut off = 0;
    while off < plaintext.len() {
        let take = std::cmp::min(STREAM_CHUNK_SIZE, plaintext.len() - off);
        let ct = enc
            .encrypt(&plaintext[off..off + take])
            .map_err(|e| format!("Encryptor::encrypt: {e}"))?;
        let len_le = (ct.len() as u32).to_le_bytes();
        wire.extend_from_slice(
            &writer
                .update(&len_le)
                .map_err(|e| format!("wrap update len: {e}"))?,
        );
        wire.extend_from_slice(
            &writer
                .update(&ct)
                .map_err(|e| format!("wrap update ct: {e}"))?,
        );
        off += take;
    }
    writer.close().map_err(|e| format!("wrap close: {e}"))?;
    let wire_n = wire.len();

    // Receiver — pull the entire decrypted bytestream then walk
    // length-prefixed chunks.
    let nlen = wrapper::nonce_size(cipher).map_err(|e| format!("nonce_size: {e}"))?;
    let mut reader = UnwrapStreamReader::new(cipher, &outer_key, &wire[..nlen])
        .map_err(|e| format!("UnwrapStreamReader::new: {e}"))?;
    let decrypted = reader
        .update(&wire[nlen..])
        .map_err(|e| format!("unwrap update: {e}"))?;
    reader.close().map_err(|e| format!("unwrap close: {e}"))?;

    let mut out: Vec<u8> = Vec::with_capacity(plaintext.len());
    let mut pos = 0;
    while pos < decrypted.len() {
        if pos + 4 > decrypted.len() {
            return Err(format!("truncated length prefix at pos {pos}"));
        }
        let clen = u32::from_le_bytes(decrypted[pos..pos + 4].try_into().unwrap()) as usize;
        pos += 4;
        if pos + clen > decrypted.len() {
            return Err(format!("truncated body at pos {pos}: need {clen}"));
        }
        let ct = &decrypted[pos..pos + clen];
        pos += clen;
        let pt = enc
            .decrypt(ct)
            .map_err(|e| format!("Encryptor::decrypt: {e}"))?;
        out.extend_from_slice(&pt);
    }
    Ok((out, wire_n))
}

// --------------------------------------------------------------------
// Streaming Low-Level (No MAC, User-Driven Loop)
// --------------------------------------------------------------------

fn run_noaead_lowlevel_userloop(
    cipher: Cipher,
    plaintext: &[u8],
) -> Result<(Vec<u8>, usize), String> {
    apply_lowlevel_config();
    let seeds = build_three_seeds(1024);
    let outer_key = wrapper::generate_key(cipher).map_err(|e| format!("generate_key: {e}"))?;

    let mut writer = WrapStreamWriter::new(cipher, &outer_key)
        .map_err(|e| format!("WrapStreamWriter::new: {e}"))?;
    let mut wire = writer.nonce().to_vec();
    let mut off = 0;
    while off < plaintext.len() {
        let take = std::cmp::min(STREAM_CHUNK_SIZE, plaintext.len() - off);
        let ct = itb::encrypt(
            &seeds[0], &seeds[1], &seeds[2], &plaintext[off..off + take],
        )
        .map_err(|e| format!("itb::encrypt: {e}"))?;
        let len_le = (ct.len() as u32).to_le_bytes();
        wire.extend_from_slice(
            &writer
                .update(&len_le)
                .map_err(|e| format!("wrap update len: {e}"))?,
        );
        wire.extend_from_slice(
            &writer
                .update(&ct)
                .map_err(|e| format!("wrap update ct: {e}"))?,
        );
        off += take;
    }
    writer.close().map_err(|e| format!("wrap close: {e}"))?;
    let wire_n = wire.len();

    let nlen = wrapper::nonce_size(cipher).map_err(|e| format!("nonce_size: {e}"))?;
    let mut reader = UnwrapStreamReader::new(cipher, &outer_key, &wire[..nlen])
        .map_err(|e| format!("UnwrapStreamReader::new: {e}"))?;
    let decrypted = reader
        .update(&wire[nlen..])
        .map_err(|e| format!("unwrap update: {e}"))?;
    reader.close().map_err(|e| format!("unwrap close: {e}"))?;

    let mut out: Vec<u8> = Vec::with_capacity(plaintext.len());
    let mut pos = 0;
    while pos < decrypted.len() {
        if pos + 4 > decrypted.len() {
            return Err(format!("truncated length prefix at pos {pos}"));
        }
        let clen = u32::from_le_bytes(decrypted[pos..pos + 4].try_into().unwrap()) as usize;
        pos += 4;
        if pos + clen > decrypted.len() {
            return Err(format!("truncated body at pos {pos}: need {clen}"));
        }
        let ct = &decrypted[pos..pos + clen];
        pos += clen;
        let pt = itb::decrypt(&seeds[0], &seeds[1], &seeds[2], ct)
            .map_err(|e| format!("itb::decrypt: {e}"))?;
        out.extend_from_slice(&pt);
    }
    Ok((out, wire_n))
}

// --------------------------------------------------------------------
// Single Message — Easy: Areion-SoEM-512 (No MAC)
//
// One enc.encrypt() call → one ITB blob. WrapInPlace mutates the
// blob and returns the per-stream nonce; the caller composes
// nonce || mutated-blob to produce the wire. UnwrapInPlace mutates
// the wire and returns an aliased view over the recovered blob.
// --------------------------------------------------------------------

fn run_message_easy_nomac(cipher: Cipher, plaintext: &[u8]) -> Result<(Vec<u8>, usize), String> {
    let mut enc = build_easy(None, 2048);
    let outer_key = wrapper::generate_key(cipher).map_err(|e| format!("generate_key: {e}"))?;

    let mut encrypted = enc
        .encrypt(plaintext)
        .map_err(|e| format!("Encryptor::encrypt: {e}"))?;
    // wrap respects immutability of `encrypted` (allocates a fresh wire buffer):
    // let wire = wrapper::wrap(cipher, &outer_key, &encrypted)?;
    let nonce = wrapper::wrap_in_place(cipher, &outer_key, &mut encrypted)
        .map_err(|e| format!("wrap_in_place: {e}"))?;
    let mut wire = nonce;
    wire.extend_from_slice(&encrypted);
    let wire_n = wire.len();

    // unwrap respects immutability of `wire` (allocates a fresh recovered buffer):
    // let recovered = wrapper::unwrap(cipher, &outer_key, &wire)?;
    let mut wire_buf = wire;
    let recovered = wrapper::unwrap_in_place(cipher, &outer_key, &mut wire_buf)
        .map_err(|e| format!("unwrap_in_place: {e}"))?;
    let pt = enc
        .decrypt(recovered)
        .map_err(|e| format!("Encryptor::decrypt: {e}"))?;
    Ok((pt, wire_n))
}

// --------------------------------------------------------------------
// Single Message — Easy: Areion-SoEM-512 + HMAC-BLAKE3 (MAC Authenticated)
// --------------------------------------------------------------------

fn run_message_easy_auth(cipher: Cipher, plaintext: &[u8]) -> Result<(Vec<u8>, usize), String> {
    let mut enc = build_easy(Some("hmac-blake3"), 2048);
    let outer_key = wrapper::generate_key(cipher).map_err(|e| format!("generate_key: {e}"))?;

    let mut encrypted = enc
        .encrypt_auth(plaintext)
        .map_err(|e| format!("Encryptor::encrypt_auth: {e}"))?;
    // wrap respects immutability of `encrypted` (allocates a fresh wire buffer):
    // let wire = wrapper::wrap(cipher, &outer_key, &encrypted)?;
    let nonce = wrapper::wrap_in_place(cipher, &outer_key, &mut encrypted)
        .map_err(|e| format!("wrap_in_place: {e}"))?;
    let mut wire = nonce;
    wire.extend_from_slice(&encrypted);
    let wire_n = wire.len();

    // unwrap respects immutability of `wire` (allocates a fresh recovered buffer):
    // let recovered = wrapper::unwrap(cipher, &outer_key, &wire)?;
    let mut wire_buf = wire;
    let recovered = wrapper::unwrap_in_place(cipher, &outer_key, &mut wire_buf)
        .map_err(|e| format!("unwrap_in_place: {e}"))?;
    let pt = enc
        .decrypt_auth(recovered)
        .map_err(|e| format!("Encryptor::decrypt_auth: {e}"))?;
    Ok((pt, wire_n))
}

// --------------------------------------------------------------------
// Single Message — Low-Level: Areion-SoEM-512 (No MAC)
// --------------------------------------------------------------------

fn run_message_lowlevel_nomac(cipher: Cipher, plaintext: &[u8]) -> Result<(Vec<u8>, usize), String> {
    apply_lowlevel_config();
    let seeds = build_three_seeds(2048);
    let outer_key = wrapper::generate_key(cipher).map_err(|e| format!("generate_key: {e}"))?;

    let mut encrypted = itb::encrypt(&seeds[0], &seeds[1], &seeds[2], plaintext)
        .map_err(|e| format!("itb::encrypt: {e}"))?;
    // wrap respects immutability of `encrypted` (allocates a fresh wire buffer):
    // let wire = wrapper::wrap(cipher, &outer_key, &encrypted)?;
    let nonce = wrapper::wrap_in_place(cipher, &outer_key, &mut encrypted)
        .map_err(|e| format!("wrap_in_place: {e}"))?;
    let mut wire = nonce;
    wire.extend_from_slice(&encrypted);
    let wire_n = wire.len();

    // unwrap respects immutability of `wire` (allocates a fresh recovered buffer):
    // let recovered = wrapper::unwrap(cipher, &outer_key, &wire)?;
    let mut wire_buf = wire;
    let recovered = wrapper::unwrap_in_place(cipher, &outer_key, &mut wire_buf)
        .map_err(|e| format!("unwrap_in_place: {e}"))?;
    let pt = itb::decrypt(&seeds[0], &seeds[1], &seeds[2], recovered)
        .map_err(|e| format!("itb::decrypt: {e}"))?;
    Ok((pt, wire_n))
}

// --------------------------------------------------------------------
// Single Message — Low-Level: Areion-SoEM-512 + HMAC-BLAKE3 (MAC Authenticated)
// --------------------------------------------------------------------

fn run_message_lowlevel_auth(cipher: Cipher, plaintext: &[u8]) -> Result<(Vec<u8>, usize), String> {
    apply_lowlevel_config();
    let seeds = build_three_seeds(2048);
    let mac_key = rand_bytes(32);
    let mac = MAC::new("hmac-blake3", &mac_key).map_err(|e| format!("MAC::new: {e}"))?;
    let outer_key = wrapper::generate_key(cipher).map_err(|e| format!("generate_key: {e}"))?;

    let mut encrypted = itb::encrypt_auth(&seeds[0], &seeds[1], &seeds[2], &mac, plaintext)
        .map_err(|e| format!("itb::encrypt_auth: {e}"))?;
    // wrap respects immutability of `encrypted` (allocates a fresh wire buffer):
    // let wire = wrapper::wrap(cipher, &outer_key, &encrypted)?;
    let nonce = wrapper::wrap_in_place(cipher, &outer_key, &mut encrypted)
        .map_err(|e| format!("wrap_in_place: {e}"))?;
    let mut wire = nonce;
    wire.extend_from_slice(&encrypted);
    let wire_n = wire.len();

    // unwrap respects immutability of `wire` (allocates a fresh recovered buffer):
    // let recovered = wrapper::unwrap(cipher, &outer_key, &wire)?;
    let mut wire_buf = wire;
    let recovered = wrapper::unwrap_in_place(cipher, &outer_key, &mut wire_buf)
        .map_err(|e| format!("unwrap_in_place: {e}"))?;
    let pt = itb::decrypt_auth(&seeds[0], &seeds[1], &seeds[2], &mac, recovered)
        .map_err(|e| format!("itb::decrypt_auth: {e}"))?;
    Ok((pt, wire_n))
}

// --------------------------------------------------------------------
// Matrix runner
// --------------------------------------------------------------------

type ExampleFn = fn(Cipher, &[u8]) -> Result<(Vec<u8>, usize), String>;

struct Example {
    name: &'static str,
    plaintext_n: usize,
    run: ExampleFn,
}

fn examples() -> [Example; 8] {
    [
        Example {
            name: "aead-easy-io",
            plaintext_n: STREAM_BYTES,
            run: run_aead_easy_io,
        },
        Example {
            name: "aead-lowlevel-io",
            plaintext_n: STREAM_BYTES,
            run: run_aead_lowlevel_io,
        },
        Example {
            name: "noaead-easy-userloop",
            plaintext_n: STREAM_BYTES,
            run: run_noaead_easy_userloop,
        },
        Example {
            name: "noaead-lowlevel-userloop",
            plaintext_n: STREAM_BYTES,
            run: run_noaead_lowlevel_userloop,
        },
        Example {
            name: "message-easy-nomac",
            plaintext_n: SINGLE_MESSAGE_BYTES,
            run: run_message_easy_nomac,
        },
        Example {
            name: "message-easy-auth",
            plaintext_n: SINGLE_MESSAGE_BYTES,
            run: run_message_easy_auth,
        },
        Example {
            name: "message-lowlevel-nomac",
            plaintext_n: SINGLE_MESSAGE_BYTES,
            run: run_message_lowlevel_nomac,
        },
        Example {
            name: "message-lowlevel-auth",
            plaintext_n: SINGLE_MESSAGE_BYTES,
            run: run_message_lowlevel_auth,
        },
    ]
}

fn parse_args() -> (String, String, bool) {
    // Minimal arg parser; mirrors `cmd/eitb` flag shape without
    // pulling clap as a dev dep.
    let mut example_filter = String::new();
    let mut cipher_filter = String::new();
    let mut verbose = false;
    let mut args = env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--example" => {
                example_filter = args.next().unwrap_or_default();
            }
            "--cipher" => {
                cipher_filter = args.next().unwrap_or_default();
            }
            "-v" | "--verbose" => {
                verbose = true;
            }
            "-h" | "--help" => {
                eprintln!("Usage: eitb [--example NAME] [--cipher aes|chacha|siphash] [-v]");
                std::process::exit(0);
            }
            other if other.starts_with("--example=") => {
                example_filter = other["--example=".len()..].to_string();
            }
            other if other.starts_with("--cipher=") => {
                cipher_filter = other["--cipher=".len()..].to_string();
            }
            _ => {
                eprintln!("eitb: unknown argument: {a}");
                std::process::exit(2);
            }
        }
    }
    (example_filter, cipher_filter, verbose)
}

fn main() -> ExitCode {
    let (example_filter, cipher_filter, verbose) = parse_args();

    itb::set_max_workers(0).expect("set_max_workers");

    let mut pass = 0usize;
    let mut fail = 0usize;
    let exs = examples();

    for ex in exs.iter() {
        if !example_filter.is_empty() && !ex.name.contains(&example_filter) {
            continue;
        }
        for cipher in Cipher::all() {
            if !cipher_filter.is_empty() && cipher.as_str() != cipher_filter {
                continue;
            }
            let plaintext = rand_bytes(ex.plaintext_n);
            let result = (ex.run)(cipher, &plaintext);
            let (recovered, wire_n, err) = match result {
                Ok((rec, n)) => (rec, n, None),
                Err(e) => (Vec::new(), 0, Some(e)),
            };
            let ok = err.is_none() && recovered == plaintext;
            let tag = if ok { "PASS" } else { "FAIL" };
            let mut line = format!(
                "[{tag}] {:<26} + {:<8}   pt={} wire={}",
                ex.name,
                cipher.as_str(),
                ex.plaintext_n,
                wire_n,
            );
            if !ok {
                if let Some(e) = &err {
                    line.push_str(&format!("  err: {e}"));
                } else {
                    line.push_str(&format!(
                        "  err: plaintext mismatch (pt={} rcv={})",
                        sha256_short(&plaintext),
                        sha256_short(&recovered),
                    ));
                }
            }
            println!("{line}");
            if verbose && ok {
                println!("       pt fingerprint:  {}", sha256_short(&plaintext));
                println!("       rcv fingerprint: {}", sha256_short(&recovered));
            }
            if ok {
                pass += 1;
            } else {
                fail += 1;
            }
        }
    }

    println!();
    println!("=== Summary: {pass} PASS, {fail} FAIL ===");

    if fail > 0 {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    }
}
