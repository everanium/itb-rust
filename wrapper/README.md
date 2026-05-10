# ITB Rust Binding — Format-Deniability Wrapper

Rust-idiomatic surface over the format-deniability wrapper exposed by libitb. Mirrors `github.com/everanium/itb/wrapper` structurally; the wire bytes produced by the Rust helpers are byte-identical to the Go-native helpers under the same `(cipher, key, nonce)` tuple.

The runtime module lives at `itb::wrapper`; this directory carries the wrapper-side documentation (`README.md` + `BENCH.md`). The example utility lives at `bindings/rust/examples/eitb.rs` and the benchmark binary at `bindings/rust/benches/bench_wrapper.rs`.

## Threat model

ITB encrypts content into RGBWYOPA pixel containers. The construction provides **content-deniability** unconditionally — no plaintext bit can be extracted from the wire. The wire pattern itself, however, is parseable by an observer who knows the ITB format:

- Non-AEAD path: per-chunk header carries width / height / container layout.
- Streaming AEAD path: a once per-stream 32-byte streamID prefix plus per-chunk `nonce || W || H || container || flag_byte`.

A passive observer who knows ITB ships with an 8-channel pixel container and a 32-byte streamID prefix can pattern-match the bytes. The format-deniability wrap hides that surface under a generic outer cipher: AES-128-CTR, ChaCha20 (RFC 8439), or SipHash-2-4 in CTR mode. After wrapping, the wire is `nonce || keystream-XOR(bytestream)` — the same shape used by countless other protocols. An observer sees a small leading nonce followed by pseudorandom-looking bytes; pattern-matching does not distinguish ITB from any other stream cipher payload.

This is **not** a random-oracle indistinguishability claim. It is a "looks like a different well-known cipher" claim. The wrap exists for format-deniability ONLY; ITB already provides confidentiality (content-deniability) and the AEAD path already provides per-stream and per-chunk integrity. The Non-AEAD streaming path has no integrity by design and the wrap does not add any.

## Wrapper API

The Rust module exposes Single Message helpers (immutable + in-place mutation) and a streaming struct pair:

| Helper | Wire format | Use case |
|---|---|---|
| `wrap` / `unwrap` | `nonce \|\| keystream-XOR(blob)` | Single Message Encrypt / EncryptAuth output, immutable plaintext path. |
| `wrap_in_place` / `unwrap_in_place` | same as `wrap` / `unwrap` | Single Message, zero-allocation steady state. Mutates the caller's `&mut [u8]`. |
| `WrapStreamWriter` / `UnwrapStreamReader` | `nonce` + keystream-XOR(continuous bytestream) | streaming use — Streaming AEAD wraps the entire bytestream end-to-end; User-Driven Loop emits per-chunk caller-side framing (`u32_LE` length prefix) through the wrap-writer so the framing bytes also pass through the keystream XOR. |

The single keystream advances monotonically across all bytes within one wrap session. A fresh CSPRNG nonce is generated per session; emitted once at stream start; never reused across sessions. This is standard CTR mode usage — within one stream, one nonce + counter is correct.

No length-prefix or other framing byte appears in cleartext on the wire in any wrap shape. The User-Driven Loop emits length prefixes through the wrap-writer so they get XORed into the keystream alongside the chunk bodies.

The streaming structs are RAII — dropping them releases the underlying libitb stream handle best-effort. `close()` is the explicit release path that surfaces release-time errors to the caller.

### Binding asymmetry

The Rust binding exposes Streaming AEAD as a `Read` / `Write` pair (`Encryptor::encrypt_stream_auth` / `decrypt_stream_auth`, plus the free-function `itb::encrypt_stream_auth` / `itb::decrypt_stream_auth`). The Streaming No MAC path has **no** equivalent `std::io::Read` / `std::io::Write` adapter pair for Non-AEAD streaming. This asymmetry is intentional. The Non-AEAD streaming arm in the Rust wrapper covers the **User-Driven Loop** variant only — caller produces an ITB ciphertext per chunk via `enc.encrypt(chunk)` (or `itb::encrypt(...)`), frames `u32_LE_len || ct`, and pushes through the streaming wrap handle. See CLAUDE.md.

## Outer ciphers

| Cipher | Constant | Key | Nonce | Notes |
|---|---|---|---|---|
| AES-128-CTR | `Cipher::Aes128Ctr` (`"aes"`) | 16 B | 16 B | libitb-side stdlib path with AES-NI. |
| ChaCha20 (RFC 8439) | `Cipher::ChaCha20` (`"chacha"`) | 32 B | 12 B | `golang.org/x/crypto/chacha20`. No AES-NI dependency. |
| SipHash-2-4 in CTR mode | `Cipher::SipHash24` (`"siphash"`) | 16 B | 16 B | `github.com/dchest/siphash` PRF. Custom CTR construction; sound under standard PRF assumption. |

The SipHash-CTR construction:
- 16-byte SipHash key = wrapper key.
- 16-byte nonce split into `(nonce_hi, nonce_lo)` 64-bit halves.
- Each keystream block: `siphash.Hash(key, nonce_hi || (nonce_lo XOR counter_LE))` — 8-byte output, XORed with plaintext.
- Counter increments per block; nonce stays fixed for the stream.

## Quick Start

Code paths under `bindings/rust/examples/eitb.rs`. Run the matrix:

```sh
cd bindings/rust
cargo run --release --example eitb
cargo run --release --example eitb -- --help
```

### 1. Streaming AEAD Easy (MAC Authenticated, IO-Driven)

ITB Call: `Encryptor::encrypt_stream_auth` / `decrypt_stream_auth`. Wrap shape: `WrapStreamWriter` / `UnwrapStreamReader` over the continuous bytestream ITB emits.

```rust
use std::io::Cursor;
use itb::Encryptor;
use itb::wrapper::{self, Cipher, UnwrapStreamReader, WrapStreamWriter};

let mut enc = Encryptor::new(Some("areion512"), Some(1024), Some("hmac-blake3"), 1)?;
enc.set_nonce_bits(512)?; enc.set_barrier_fill(4)?;
enc.set_bit_soup(1)?; enc.set_lock_soup(1)?;

let outer_key = wrapper::generate_key(cipher)?;

// Sender — wrap the entire AEAD bytestream in one keystream session.
let mut inner: Vec<u8> = Vec::new();
enc.encrypt_stream_auth(Cursor::new(&plaintext), &mut inner, 16 * 1024)?;
let mut writer = WrapStreamWriter::new(cipher, &outer_key)?;
let mut wire = writer.nonce().to_vec();
wire.extend_from_slice(&writer.update(&inner)?);
writer.close()?;

// Receiver
let nlen = wrapper::nonce_size(cipher)?;
let mut reader = UnwrapStreamReader::new(cipher, &outer_key, &wire[..nlen])?;
let inner_wire = reader.update(&wire[nlen..])?;
reader.close()?;
let mut out: Vec<u8> = Vec::new();
enc.decrypt_stream_auth(Cursor::new(inner_wire), &mut out, 16 * 1024)?;
```

### 2. Streaming AEAD Low-Level (MAC Authenticated, IO-Driven)

ITB Call: `itb::encrypt_stream_auth` / `itb::decrypt_stream_auth` with three explicit `Seed` handles plus a `MAC::new("hmac-blake3", &key)`. Wrap shape: `WrapStreamWriter` / `UnwrapStreamReader`.

```rust
let seeds = [Seed::new("areion512", 1024)?, Seed::new("areion512", 1024)?, Seed::new("areion512", 1024)?];
let mac = MAC::new("hmac-blake3", &mac_key_32)?;
let outer_key = wrapper::generate_key(cipher)?;

let mut inner: Vec<u8> = Vec::new();
itb::encrypt_stream_auth(&seeds[0], &seeds[1], &seeds[2], &mac,
                         Cursor::new(&plaintext), &mut inner, 16 * 1024)?;
let mut writer = WrapStreamWriter::new(cipher, &outer_key)?;
let mut wire = writer.nonce().to_vec();
wire.extend_from_slice(&writer.update(&inner)?);
writer.close()?;

// Receiver mirrors example 1.
```

### 3. Streaming Easy (No MAC, User-Driven Loop)

The "Alternative — User-Driven Loop" pattern: each chunk is one independent `enc.encrypt(chunk)` call. Wrap shape: `WrapStreamWriter` / `UnwrapStreamReader` driven by a caller loop that emits `u32_LE_len || ct` per chunk through the wrapped writer. Length prefix and chunk body both pass through the keystream XOR — no length appears in cleartext on the wire.

```rust
let mut enc = Encryptor::new(Some("areion512"), Some(1024), None, 1)?;
enc.set_nonce_bits(512)?; enc.set_barrier_fill(4)?;
enc.set_bit_soup(1)?; enc.set_lock_soup(1)?;

let outer_key = wrapper::generate_key(cipher)?;
let mut writer = WrapStreamWriter::new(cipher, &outer_key)?;
let mut wire = writer.nonce().to_vec();
let mut off = 0;
while off < plaintext.len() {
    let take = std::cmp::min(16 * 1024, plaintext.len() - off);
    let ct = enc.encrypt(&plaintext[off..off + take])?;
    let len_le = (ct.len() as u32).to_le_bytes();
    wire.extend_from_slice(&writer.update(&len_le)?);
    wire.extend_from_slice(&writer.update(&ct)?);
    off += take;
}
writer.close()?;

// Receiver — pull entire decrypted bytestream then walk u32_LE-prefixed chunks.
let nlen = wrapper::nonce_size(cipher)?;
let mut reader = UnwrapStreamReader::new(cipher, &outer_key, &wire[..nlen])?;
let decrypted = reader.update(&wire[nlen..])?;
reader.close()?;
let mut out: Vec<u8> = Vec::new();
let mut pos = 0;
while pos < decrypted.len() {
    let clen = u32::from_le_bytes(decrypted[pos..pos + 4].try_into()?) as usize;
    pos += 4;
    let pt = enc.decrypt(&decrypted[pos..pos + clen])?;
    pos += clen;
    out.extend_from_slice(&pt);
}
```

### 4. Streaming Low-Level (No MAC, User-Driven Loop)

Per-chunk `itb::encrypt` / `itb::decrypt` with caller-side framing. Wrap shape: `WrapStreamWriter` / `UnwrapStreamReader`. Each chunk is emitted as `u32_LE_len || ct` through the wrap-writer; the length and the body both pass through the keystream XOR.

```rust
let seeds = [Seed::new("areion512", 1024)?, Seed::new("areion512", 1024)?, Seed::new("areion512", 1024)?];
let outer_key = wrapper::generate_key(cipher)?;
let mut writer = WrapStreamWriter::new(cipher, &outer_key)?;
let mut wire = writer.nonce().to_vec();
let mut off = 0;
while off < plaintext.len() {
    let take = std::cmp::min(16 * 1024, plaintext.len() - off);
    let ct = itb::encrypt(&seeds[0], &seeds[1], &seeds[2], &plaintext[off..off + take])?;
    let len_le = (ct.len() as u32).to_le_bytes();
    wire.extend_from_slice(&writer.update(&len_le)?);
    wire.extend_from_slice(&writer.update(&ct)?);
    off += take;
}
writer.close()?;

// Receiver mirrors example 3 with itb::decrypt(&seeds[0], &seeds[1], &seeds[2], ct).
```

### 5. Easy: Areion-SoEM-512 (No MAC, Single Message)

ITB Call: `enc.encrypt(plaintext)` returns one ITB blob. Wrap shape: `wrap` — `nonce || ks-XOR(blob)`. The `wrap_in_place` / `unwrap_in_place` variant is shown — mutates the caller's `Vec<u8>` in place to skip the steady-state allocation.

```rust
let mut enc = Encryptor::new(Some("areion512"), Some(2048), None, 1)?;
enc.set_nonce_bits(512)?; enc.set_barrier_fill(4)?;
enc.set_bit_soup(1)?; enc.set_lock_soup(1)?;

let mut encrypted = enc.encrypt(&plaintext)?;

let outer_key = wrapper::generate_key(cipher)?;
// wrap respects immutability of `encrypted` (allocates a fresh wire buffer):
// let wire = wrapper::wrap(cipher, &outer_key, &encrypted)?;
let nonce = wrapper::wrap_in_place(cipher, &outer_key, &mut encrypted)?;
let mut wire = nonce;
wire.extend_from_slice(&encrypted);

// Receiver — unwrap respects immutability of `wire` (allocates a fresh recovered buffer):
// let recovered = wrapper::unwrap(cipher, &outer_key, &wire)?;
let mut wire_buf = wire;
let recovered = wrapper::unwrap_in_place(cipher, &outer_key, &mut wire_buf)?;
let pt = enc.decrypt(recovered)?;
```

### 6. Easy: Areion-SoEM-512 + HMAC-BLAKE3 (MAC Authenticated, Single Message)

ITB Call: `enc.encrypt_auth` / `enc.decrypt_auth`. Wrap shape: `wrap` (or `wrap_in_place`). The ITB-internal 32-byte MAC tag remains inside the RGBWYOPA container; outer cipher is format-deniability only.

```rust
let mut enc = Encryptor::new(Some("areion512"), Some(2048), Some("hmac-blake3"), 1)?;
enc.set_nonce_bits(512)?; enc.set_barrier_fill(4)?;
enc.set_bit_soup(1)?; enc.set_lock_soup(1)?;

let mut encrypted = enc.encrypt_auth(&plaintext)?;

let outer_key = wrapper::generate_key(cipher)?;
let nonce = wrapper::wrap_in_place(cipher, &outer_key, &mut encrypted)?;
let mut wire = nonce;
wire.extend_from_slice(&encrypted);

// Receiver
let mut wire_buf = wire;
let recovered = wrapper::unwrap_in_place(cipher, &outer_key, &mut wire_buf)?;
let pt = enc.decrypt_auth(recovered)?;
```

### 7. Low-Level: Areion-SoEM-512 (No MAC, Single Message)

ITB Call: `itb::encrypt(&seeds[0], &seeds[1], &seeds[2], &plaintext)` / `itb::decrypt(...)` with three explicit `Seed` handles. Wrap shape: `wrap` (or `wrap_in_place`). Wire shape matches example 5; the difference is that the seed material is held by caller-side `Seed` handles rather than by an `Encryptor` instance.

```rust
let seeds = [Seed::new("areion512", 2048)?, Seed::new("areion512", 2048)?, Seed::new("areion512", 2048)?];

let mut encrypted = itb::encrypt(&seeds[0], &seeds[1], &seeds[2], &plaintext)?;

let outer_key = wrapper::generate_key(cipher)?;
let nonce = wrapper::wrap_in_place(cipher, &outer_key, &mut encrypted)?;
let mut wire = nonce;
wire.extend_from_slice(&encrypted);

// Receiver
let mut wire_buf = wire;
let recovered = wrapper::unwrap_in_place(cipher, &outer_key, &mut wire_buf)?;
let pt = itb::decrypt(&seeds[0], &seeds[1], &seeds[2], recovered)?;
```

### 8. Low-Level: Areion-SoEM-512 + HMAC-BLAKE3 (MAC Authenticated, Single Message)

ITB Call: `itb::encrypt_auth(&seeds[0], &seeds[1], &seeds[2], &mac, &plaintext)` / `itb::decrypt_auth(...)`. Wrap shape: `wrap` (or `wrap_in_place`). The ITB-internal 32-byte MAC tag remains inside the RGBWYOPA container; outer cipher is format-deniability only.

```rust
let seeds = [Seed::new("areion512", 2048)?, Seed::new("areion512", 2048)?, Seed::new("areion512", 2048)?];
let mac = MAC::new("hmac-blake3", &mac_key_32)?;

let mut encrypted = itb::encrypt_auth(&seeds[0], &seeds[1], &seeds[2], &mac, &plaintext)?;

let outer_key = wrapper::generate_key(cipher)?;
let nonce = wrapper::wrap_in_place(cipher, &outer_key, &mut encrypted)?;
let mut wire = nonce;
wire.extend_from_slice(&encrypted);

// Receiver
let mut wire_buf = wire;
let recovered = wrapper::unwrap_in_place(cipher, &outer_key, &mut wire_buf)?;
let pt = itb::decrypt_auth(&seeds[0], &seeds[1], &seeds[2], &mac, recovered)?;
```

## Verification matrix

Every example × cipher combination round-trips against random plaintext (1 KiB for Single Message, 64 KiB for streaming) with byte-equality. Sample run:

```
[PASS] aead-easy-io               + aes        pt=65536 wire=90208
[PASS] aead-easy-io               + chacha     pt=65536 wire=90204
[PASS] aead-easy-io               + siphash    pt=65536 wire=90208
[PASS] aead-lowlevel-io           + aes        pt=65536 wire=90208
[PASS] aead-lowlevel-io           + chacha     pt=65536 wire=90204
[PASS] aead-lowlevel-io           + siphash    pt=65536 wire=90208
[PASS] noaead-easy-userloop       + aes        pt=65536 wire=90192
[PASS] noaead-easy-userloop       + chacha     pt=65536 wire=90188
[PASS] noaead-easy-userloop       + siphash    pt=65536 wire=90192
[PASS] noaead-lowlevel-userloop   + aes        pt=65536 wire=90192
[PASS] noaead-lowlevel-userloop   + chacha     pt=65536 wire=90188
[PASS] noaead-lowlevel-userloop   + siphash    pt=65536 wire=90192
[PASS] message-easy-nomac         + aes        pt=1024 wire=4316
[PASS] message-easy-nomac         + chacha     pt=1024 wire=4312
[PASS] message-easy-nomac         + siphash    pt=1024 wire=4316
[PASS] message-easy-auth          + aes        pt=1024 wire=8276
[PASS] message-easy-auth          + chacha     pt=1024 wire=8272
[PASS] message-easy-auth          + siphash    pt=1024 wire=8276
[PASS] message-lowlevel-nomac     + aes        pt=1024 wire=4316
[PASS] message-lowlevel-nomac     + chacha     pt=1024 wire=4312
[PASS] message-lowlevel-nomac     + siphash    pt=1024 wire=4316
[PASS] message-lowlevel-auth      + aes        pt=1024 wire=8276
[PASS] message-lowlevel-auth      + chacha     pt=1024 wire=8272
[PASS] message-lowlevel-auth      + siphash    pt=1024 wire=8276

=== Summary: 24 PASS, 0 FAIL ===
```

The wire-byte difference between cipher columns is exactly the per-stream nonce-size delta (16 vs 12 vs 16 bytes); the User-Driven Loop variants additionally include 4 bytes of keystream-XORed length prefix per chunk. The wire byte counts match the Python binding's matrix exactly under the same plaintext sizes.

## Performance

Bench numbers across Single Ouroboros and Triple Ouroboros, message and streaming, encrypt and decrypt (split sub-benches) are tracked in [BENCH.md](BENCH.md).

## Notes on outer cipher key management

The wrapper itself does not address outer key distribution; the example utility generates a fresh CSPRNG outer key per run for self-test purposes. In a real deployment the outer key is shared out-of-band (or derived via a separate key-exchange step) and is independent of the ITB seed material. The ITB state blob already carries the inner cipher's keying material; the outer key is the additional piece both endpoints need.

The outer key MAY be reused across many streams provided each stream uses a fresh CSPRNG nonce — this is the standard CTR mode safety contract. The wrapper helpers always generate a fresh nonce internally, so caller-side discipline is reduced to "do not reuse the same `(key, nonce)` across distinct streams" — a contract the helper enforces by construction.

## What this is not

- Not an integrity layer. The outer cipher is unauthenticated by design — adding a MAC at this layer would defeat the format-deniability goal (the resulting wire would pattern-match an AEAD construction's tag-bearing format, not a generic stream cipher). Use the ITB AEAD path when integrity is required.
- Not a substitute for ITB's content-deniability. ITB still provides the unconditional content-deniability; the wrap adds format-deniability on top.
