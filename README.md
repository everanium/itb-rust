# ITB Rust Binding

`libloading`-based Rust wrapper over the libitb shared library
(`cmd/cshared`). Runtime FFI — no C compiler at install time, no
compile-time link against libitb; the `.so` / `.dll` / `.dylib` is
resolved and dispatched at first use through the `libloading`
crate.

**Path placeholder.** `<itb>` denotes the path to the local ITB
repository checkout (or this binding's mirror clone) — for example,
`/home/you/go/src/itb` or `~/projects/itb-rust`. Substitute the
literal token in the recipes below; `cargo` does not expand `~`,
so an absolute path (or one resolved by the shell before invocation)
is required in `Cargo.toml`'s `path = ...` entries.

## Prerequisites (Arch Linux)

```bash
sudo pacman -S go go-tools rustup cargo cargo-all-features
```

## Build the shared library

The convenience driver `bindings/rust/build.sh` builds `libitb.so`
plus the Rust crate's release artefact in one step. Run it from
anywhere:

```bash
./bindings/rust/build.sh
```

The driver expands to two underlying steps — building libitb from
the repo root, then `cargo build --release` on the binding side.
Equivalent manual invocation:

```bash
go build -trimpath -buildmode=c-shared \
    -o dist/linux-amd64/libitb.so ./cmd/cshared
cd bindings/rust && cargo build --release
```

(macOS produces `libitb.dylib` under `dist/darwin-<arch>/`,
Windows produces `libitb.dll` under `dist/windows-<arch>/`.)

## Add to a Cargo project

The crate is published as `itb`. As a path dependency from inside
this repository:

```toml
[dependencies]
itb = { path = "bindings/rust" }
```

Build once before running tests or examples:

```bash
cd bindings/rust/
cargo build --release
```

Crate metadata: `name = "itb"`, `version = "0.1.0"`, `edition =
"2021"`, `license = "MIT"`. The only runtime dependency is
`libloading = "0.9"`.

## Library lookup order

1. `ITB_LIBRARY_PATH` environment variable (absolute path).
2. `<repo>/dist/<os>-<arch>/libitb.<ext>` resolved by walking up
   from `CARGO_MANIFEST_DIR` (`bindings/rust/` → repo root →
   `dist/<os>-<arch>/`).
3. System loader path (`ld.so.cache`, `DYLD_LIBRARY_PATH`, `PATH`).

## Memory

Two process-wide knobs constrain Go runtime arena pacing. Both readable at libitb load time via env vars:

- `ITB_GOMEMLIMIT=512MiB` — soft memory limit in bytes; supports `B` / `KiB` / `MiB` / `GiB` / `TiB` suffixes.
- `ITB_GOGC=20` — GC trigger percentage; default `100`, lower triggers GC more aggressively.

Programmatic setters override env-set values at any time. Pass `-1` to either setter to query the current value without changing it.

```rust
itb::set_memory_limit(512 << 20);
itb::set_gc_percent(20);
```

## Tests

```bash
./bindings/rust/run_tests.sh
```

The harness verifies `libitb.so` is present, exports
`LD_LIBRARY_PATH`, and invokes `cargo test --release`. Positional
arguments are forwarded straight to cargo (e.g.
`./run_tests.sh --test test_blake3` to scope the run to one
binary). The integration test suite under `bindings/rust/tests/`
mirrors the cross-binding coverage: Single + Triple Ouroboros,
mixed primitives, authenticated paths, blob round-trip, streaming
chunked I/O, error paths, lockSeed lifecycle.

## Benchmarks

A custom Go-bench-style harness lives under `benches/` and covers
the four ops (`encrypt`, `decrypt`, `encrypt_auth`,
`decrypt_auth`) across the nine PRF-grade primitives plus one
mixed-primitive variant for both Single and Triple Ouroboros at
1024-bit ITB key width and 16 MiB payload. See
[`benches/README.md`](benches/README.md) for invocation /
environment variables / output format and
[`benches/BENCH.md`](benches/BENCH.md) for recorded throughput
results across the canonical pass matrix.

The four-pass canonical sweep (Single + Triple × ±LockSeed) that
fills `benches/BENCH.md` is driven by the wrapper script in the
binding root:

```bash
./bindings/rust/run_bench.sh                  # full 4-pass canonical sweep
./bindings/rust/run_bench.sh --lockseed-only  # pass 3 + pass 4 only
```

The harness sets `LD_LIBRARY_PATH` to `dist/linux-amd64/`,
manages `ITB_LOCKSEED` per pass, and forwards `ITB_NONCE_BITS` /
`ITB_BENCH_FILTER` / `ITB_BENCH_MIN_SEC` straight through to the
underlying `cargo bench --bench bench_single` /
`cargo bench --bench bench_triple` invocations.

## Streaming AEAD

**Streaming AEAD** authenticates a chunked stream end-to-end while preserving the deniability of the per-chunk MAC-Inside-Encrypt container. Each chunk's MAC binds the encrypted payload to a 32-byte CSPRNG stream anchor (written as a once-per-stream wire prefix), the cumulative pixel offset of preceding chunks, and a final-flag bit — defending against chunk reorder, replay within or across streams sharing the PRF / MAC key, silent mid-stream drop, and truncate-tail. The wire format adds 32 bytes of stream prefix plus one byte of encrypted trailing flag per chunk; no externally visible MAC tag.

**Easy Mode:**

`Encryptor::encrypt_stream_auth` accepts any `Read`-implementing source and any `Write`-implementing sink. Buffered file readers / writers are the typical choice for production-scale plaintext / ciphertext on disk. The MAC key is allocated CSPRNG-fresh inside the encryptor at construction time.

```rust,no_run
use std::fs::File;
use std::io::{BufReader, BufWriter, Read, Write};
use itb::wrapper::{self, Cipher, UnwrapStreamReader, WrapStreamWriter};

const SRC_PATH: &str = "/tmp/64mb.src";
const ENC_PATH: &str = "/tmp/64mb.enc";
const DST_PATH: &str = "/tmp/64mb.dst";
const CHUNK_SIZE: usize = 16 * 1024 * 1024;

let mut enc = itb::Encryptor::new(Some("areion512"), Some(1024),
                                  Some("hmac-blake3"), 1)?;

// Outer cipher key - preferred surface for HKDF / ML-KEM / key-rotation policy in user-side application. ITB Inner seeds + PRF key keep as CSPRNG derived.
let outer_key = wrapper::generate_key(Cipher::Aes128Ctr)?;

// Sender — encrypt to an intermediate file, then wrap end-to-end
// through one keystream session.
{
    let fin  = BufReader::new(File::open(SRC_PATH)?);
    let fout = BufWriter::new(File::create(format!("{ENC_PATH}.inner"))?);
    enc.encrypt_stream_auth(fin, fout, CHUNK_SIZE)?;
}
// Format-deniability ITB masking via outer-cipher streaming wrapper (AES-128-CTR) - same ~0% overhead in stream mode (Recommended in every case).
{
    let mut writer = WrapStreamWriter::new(Cipher::Aes128Ctr, &outer_key)?;
    let mut fin  = BufReader::new(File::open(format!("{ENC_PATH}.inner"))?);
    let mut fout = BufWriter::new(File::create(ENC_PATH)?);
    fout.write_all(writer.nonce())?;
    let mut buf = vec![0u8; CHUNK_SIZE];
    loop {
        let n = fin.read(&mut buf)?;
        if n == 0 { break; }
        fout.write_all(&writer.update(&buf[..n])?)?;
    }
    writer.close()?;
}
std::fs::remove_file(format!("{ENC_PATH}.inner"))?;

// Receiver — strip the leading nonce, unwrap the body, decrypt.
{
    let nlen = wrapper::nonce_size(Cipher::Aes128Ctr)?;
    let mut fin = BufReader::new(File::open(ENC_PATH)?);
    let mut nonce_buf = vec![0u8; nlen];
    fin.read_exact(&mut nonce_buf)?;
    let mut reader = UnwrapStreamReader::new(Cipher::Aes128Ctr, &outer_key, &nonce_buf)?;
    let mut fout = BufWriter::new(File::create(format!("{ENC_PATH}.inner"))?);
    let mut buf = vec![0u8; CHUNK_SIZE];
    loop {
        let n = fin.read(&mut buf)?;
        if n == 0 { break; }
        fout.write_all(&reader.update(&buf[..n])?)?;
    }
    reader.close()?;
}
{
    let fin  = BufReader::new(File::open(format!("{ENC_PATH}.inner"))?);
    let fout = BufWriter::new(File::create(DST_PATH)?);
    enc.decrypt_stream_auth(fin, fout, CHUNK_SIZE)?;
}
std::fs::remove_file(format!("{ENC_PATH}.inner"))?;
enc.close()?;
```

**Build + run:**

```toml
# <itb>/itb_stream_auth_example/Cargo.toml
[package]
name = "itb_stream_auth_example"
version = "0.0.0"
edition = "2021"

[dependencies]
itb = { path = "<itb>/bindings/rust" }

[[bin]]
name = "main"
path = "main.rs"
```

The `path = ...` entry must be an absolute filesystem path (or a
relative path resolved against the manifest's directory). `cargo`
does not expand `~`, so a literal `~/...` here fails at manifest
resolve time.

```sh
cd <itb>/itb_stream_auth_example && cargo run --release
```

**Output (verified):**

```
Easy Mode src sha256: 7adc82f9bebf205db2a6c8033d7c1fe43d3bf8b3ecb0fbfd6c4c2dff71672425
Easy Mode dst sha256: 7adc82f9bebf205db2a6c8033d7c1fe43d3bf8b3ecb0fbfd6c4c2dff71672425
[OK] Easy Mode: 64 MiB roundtrip via stream-auth verified
```

---

**Low-Level Mode:**

Free functions `itb::encrypt_stream_auth` / `itb::decrypt_stream_auth` take three explicit `Seed` references plus an `itb::MAC` (32-byte key from `/dev/urandom`) and stream through the same chunked-AEAD construction. The seeds and MAC handle are caller-owned and dropped at scope exit.

```rust,no_run
use std::fs::File;
use std::io::{BufReader, BufWriter, Read, Write};
use itb::wrapper::{self, Cipher, UnwrapStreamReader, WrapStreamWriter};

let noise = itb::Seed::new("areion512", 1024)?;
let data  = itb::Seed::new("areion512", 1024)?;
let start = itb::Seed::new("areion512", 1024)?;
let mut mac_key = [0u8; 32];
File::open("/dev/urandom")?.read_exact(&mut mac_key)?;
let mac = itb::MAC::new("hmac-blake3", &mac_key)?;

// Outer cipher key - preferred surface for HKDF / ML-KEM / key-rotation policy in user-side application. ITB Inner seeds + PRF key keep as CSPRNG derived.
let outer_key = wrapper::generate_key(Cipher::Aes128Ctr)?;

// Sender — encrypt to an intermediate file, then wrap end-to-end.
{
    let fin  = BufReader::new(File::open(SRC_PATH)?);
    let fout = BufWriter::new(File::create(format!("{ENC_PATH}.inner"))?);
    itb::encrypt_stream_auth(&noise, &data, &start, &mac, fin, fout, CHUNK_SIZE)?;
}
// Format-deniability ITB masking via outer-cipher streaming wrapper (AES-128-CTR) - same ~0% overhead in stream mode (Recommended in every case).
{
    let mut writer = WrapStreamWriter::new(Cipher::Aes128Ctr, &outer_key)?;
    let mut fin  = BufReader::new(File::open(format!("{ENC_PATH}.inner"))?);
    let mut fout = BufWriter::new(File::create(ENC_PATH)?);
    fout.write_all(writer.nonce())?;
    let mut buf = vec![0u8; CHUNK_SIZE];
    loop {
        let n = fin.read(&mut buf)?;
        if n == 0 { break; }
        fout.write_all(&writer.update(&buf[..n])?)?;
    }
    writer.close()?;
}
std::fs::remove_file(format!("{ENC_PATH}.inner"))?;

// Receiver
{
    let nlen = wrapper::nonce_size(Cipher::Aes128Ctr)?;
    let mut fin = BufReader::new(File::open(ENC_PATH)?);
    let mut nonce_buf = vec![0u8; nlen];
    fin.read_exact(&mut nonce_buf)?;
    let mut reader = UnwrapStreamReader::new(Cipher::Aes128Ctr, &outer_key, &nonce_buf)?;
    let mut fout = BufWriter::new(File::create(format!("{ENC_PATH}.inner"))?);
    let mut buf = vec![0u8; CHUNK_SIZE];
    loop {
        let n = fin.read(&mut buf)?;
        if n == 0 { break; }
        fout.write_all(&reader.update(&buf[..n])?)?;
    }
    reader.close()?;
}
{
    let fin  = BufReader::new(File::open(format!("{ENC_PATH}.inner"))?);
    let fout = BufWriter::new(File::create(DST_PATH)?);
    itb::decrypt_stream_auth(&noise, &data, &start, &mac, fin, fout, CHUNK_SIZE)?;
}
std::fs::remove_file(format!("{ENC_PATH}.inner"))?;
```

**Build + run:**

```sh
cd <itb>/itb_stream_auth_example && cargo run --release
```

**Output (verified):**

```
Low-Level src sha256: 7adc82f9bebf205db2a6c8033d7c1fe43d3bf8b3ecb0fbfd6c4c2dff71672425
Low-Level dst sha256: 7adc82f9bebf205db2a6c8033d7c1fe43d3bf8b3ecb0fbfd6c4c2dff71672425
[OK] Low-Level Mode: 64 MiB roundtrip via stream-auth verified
```

## Quick Start — `itb::Encryptor` + HMAC-BLAKE3 (MAC Authenticated)

The high-level [`Encryptor`] (mirroring the
`github.com/everanium/itb/easy` Go sub-package) replaces the
seven-line setup ceremony of the lower-level
`Seed` / `encrypt` / `decrypt` path with one constructor call: the
encryptor allocates its own three (Single) or seven (Triple) seeds
plus MAC closure, snapshots the global configuration into a
per-instance Config, and exposes setters that mutate only its own
state without touching the process-wide `itb::set_*` accessors.
Two encryptors with different settings can run concurrently
without cross-contamination.

The MAC primitive is bound at construction time — the third
argument selects one of the registry names (`hmac-blake3` —
recommended default, `hmac-sha256`, `kmac256`). The encryptor
allocates a fresh 32-byte CSPRNG MAC key alongside the per-seed
PRF keys; `enc.export()` carries all of them in a single JSON
blob. On the receiver side, `dec.import_state(&blob)` restores the
MAC key together with the seeds, so the encrypt-today /
decrypt-tomorrow flow is one method call per side.

When the `mac` argument is `None` the binding picks `hmac-blake3`
rather than forwarding NULL through to libitb's own default —
HMAC-BLAKE3 measures the lightest authenticated-mode overhead
across the Easy Mode bench surface.

```rust,no_run
// Sender

use itb::{peek_config, Encryptor};
use itb::wrapper::{self, Cipher, UnwrapStreamReader, WrapStreamWriter};

// Outer cipher key - preferred surface for HKDF / ML-KEM / key-rotation policy in user-side application. ITB Inner seeds + PRF key keep as CSPRNG derived.
let outer_key = wrapper::generate_key(Cipher::Aes128Ctr).unwrap();

// Per-instance configuration — mutates only this encryptor's
// Config. Two encryptors built side-by-side carry independent
// settings; process-wide itb::set_* accessors are NOT consulted
// after construction. Mode 1 = Single Ouroboros (3 seeds);
// mode 3 = Triple Ouroboros (7 seeds).
let mut enc = Encryptor::new(
    Some("areion512"),
    Some(2048),
    Some("hmac-blake3"),
    1,
).unwrap();

enc.set_nonce_bits(512).unwrap();   // 512-bit nonce (default: 128-bit)
enc.set_barrier_fill(4).unwrap();   // CSPRNG fill margin (default: 1, valid: 1, 2, 4, 8, 16, 32)
enc.set_bit_soup(1).unwrap();       // optional bit-level split ("bit-soup"; default: 0 = byte-level)
                                    // auto-enabled for Single Ouroboros if set_lock_soup(1) is on
enc.set_lock_soup(1).unwrap();      // optional Insane Interlocked Mode: per-chunk PRF-keyed
                                    // bit-permutation overlay on top of bit-soup;
                                    // auto-enabled for Single Ouroboros if set_bit_soup(1) is on

// enc.set_lock_seed(1).unwrap();   // optional dedicated lockSeed for the bit-permutation
                                    // derivation channel — separates that PRF's keying
                                    // material from the noiseSeed-driven noise-injection
                                    // channel; auto-couples set_lock_soup(1) +
                                    // set_bit_soup(1). Adds one extra seed slot
                                    // (3 → 4 for Single, 7 → 8 for Triple). Must be
                                    // called BEFORE the first encrypt_auth — switching
                                    // mid-session raises ITBError(STATUS_EASY_LOCKSEED_AFTER_ENCRYPT).

// Persistence blob — carries seeds + PRF keys + MAC key (and the
// dedicated lockSeed material when set_lock_seed(1) is active).
let blob = enc.export().unwrap();
println!("state blob: {} bytes", blob.len());
println!(
    "primitive: {}, key_bits: {}, mode: {}, mac: {}",
    enc.primitive().unwrap(),
    enc.key_bits().unwrap(),
    enc.mode().unwrap(),
    enc.mac_name().unwrap(),
);

let plaintext = b"any text or binary data - including 0x00 bytes";
// let chunk_size = 4 * 1024 * 1024;  // 4 MiB - bulk local crypto, not small-frame network streaming
// let read_size  = 64 * 1024;        // app-driven feed granularity (independent of chunk_size)

// Authenticated encrypt — 32-byte tag is computed across the
// entire decrypted capacity and embedded inside the RGBWYOPA
// container, preserving oracle-free deniability.
let mut encrypted = enc.encrypt_auth(plaintext).unwrap();
println!("encrypted: {} bytes", encrypted.len());

// Format-deniability ITB masking through outer cipher AES-128-CTR with ~0% overhead over ITB Encrypt / Decrypt (Recommended in every case).
let nonce = wrapper::wrap_in_place(Cipher::Aes128Ctr, &outer_key, &mut encrypted).unwrap();
let mut wire = nonce;
wire.extend_from_slice(&encrypted);
println!("wire: {} bytes", wire.len());

// Streaming alternative — slice plaintext into chunk_size pieces
// and call enc.encrypt_auth() per chunk; each chunk carries its
// own MAC tag. enc.header_size() + enc.parse_chunk_len() are
// per-instance accessors (track this encryptor's own nonce_bits,
// NOT the process-wide itb::header_size).
//
// let mut writer = WrapStreamWriter::new(Cipher::Aes128Ctr, &outer_key).unwrap();
// let mut wire: Vec<u8> = writer.nonce().to_vec();
// for piece in plaintext.chunks(chunk_size) {
//     let ct = enc.encrypt_auth(piece).unwrap();
//     wire.extend_from_slice(&writer.update(&(ct.len() as u32).to_le_bytes()).unwrap());
//     wire.extend_from_slice(&writer.update(&ct).unwrap());
// }
// writer.close().unwrap();

// Send wire + state blob; Drop releases the handle + zeroes key
// material at scope end. enc.free() is the consuming counterpart
// that surfaces release-time errors.


// Receiver

// Receive wire + state blob
// let wire = ...;
// let blob = ...;

itb::set_max_workers(8).unwrap();   // limit to 8 CPU cores (default: 0 = all CPUs)

// Optional: peek at the blob's metadata before constructing a
// matching encryptor. Useful when the receiver multiplexes blobs
// of different shapes (different primitive / mode / MAC choices).
let (prim, key_bits, mode, mac_name) = peek_config(&blob).unwrap();
println!(
    "peek: primitive={}, key_bits={}, mode={}, mac={}",
    prim, key_bits, mode, mac_name,
);

let mut dec = Encryptor::new(Some(&prim), Some(key_bits), Some(&mac_name), mode).unwrap();

// dec.import_state(&blob) below automatically restores the full
// per-instance configuration (nonce_bits, barrier_fill, bit_soup,
// lock_soup, and the dedicated lockSeed material when sender's
// set_lock_seed(1) was active). The set_*() lines below are kept
// for documentation — they show the knobs available for explicit
// pre-Import override. barrier_fill is asymmetric: a receiver-set
// value > 1 takes priority over the blob's barrier_fill (the
// receiver's heavier CSPRNG margin is preserved across Import).
dec.set_nonce_bits(512).unwrap();
dec.set_barrier_fill(4).unwrap();
dec.set_bit_soup(1).unwrap();
dec.set_lock_soup(1).unwrap();
// dec.set_lock_seed(1).unwrap();   // optional — Import below restores the dedicated
                                    // lockSeed slot from the blob's lock_seed:true.

// Restore PRF keys, seed components, MAC key, and the per-instance
// configuration overrides (nonce_bits / barrier_fill / bit_soup /
// lock_soup / lock_seed) from the saved blob.
dec.import_state(&blob).unwrap();

// Strip the leading nonce, unwrap the body, then decrypt.
let mut wire_buf = wire;
let encrypted = wrapper::unwrap_in_place(Cipher::Aes128Ctr, &outer_key, &mut wire_buf).unwrap();

// Authenticated decrypt — any single-bit tamper triggers MAC
// failure (no oracle leak about which byte was tampered). Mismatch
// surfaces as ITBError(STATUS_MAC_FAILURE), not a corrupted
// plaintext.
match dec.decrypt_auth(encrypted) {
    Ok(plaintext) => {
        println!("decrypted: {}", String::from_utf8_lossy(&plaintext));
    }
    Err(e) if e.code() == itb::STATUS_MAC_FAILURE => {
        println!("MAC verification failed — tampered or wrong key");
    }
    Err(e) => panic!("decrypt error: {e}"),
}

// Streaming alternative — strip the leading nonce, unwrap through
// one keystream session, then walk the chunk stream and decrypt_auth
// each chunk; any tamper inside any chunk surfaces as
// ITBError(STATUS_MAC_FAILURE) on that chunk.
//
// let nlen = wrapper::nonce_size(Cipher::Aes128Ctr).unwrap();
// let mut reader = UnwrapStreamReader::new(Cipher::Aes128Ctr, &outer_key, &wire[..nlen]).unwrap();
// let decrypted_wire = reader.update(&wire[nlen..]).unwrap();
// reader.close().unwrap();
// let header_size = dec.header_size().unwrap() as usize;
// let mut pbuf: Vec<u8> = Vec::new();
// let mut pos = 0;
// while pos < decrypted_wire.len() {
//     let clen = u32::from_le_bytes(decrypted_wire[pos..pos+4].try_into().unwrap()) as usize;
//     pos += 4;
//     pbuf.extend_from_slice(&dec.decrypt_auth(&decrypted_wire[pos..pos+clen]).unwrap());
//     pos += clen;
// }
// let decrypted = pbuf;
```

## Quick Start — Mixed primitives (Different PRF per seed slot)

[`Encryptor::mixed_single`] and [`Encryptor::mixed_triple`]
accept per-slot primitive names — the noise / data / start (and
optional dedicated lockSeed) seed slots can use different PRF
primitives within the same native hash width. The
mix-and-match-PRF freedom of the lower-level path, surfaced
through the high-level [`Encryptor`] without forcing the caller
off the Easy Mode constructor. The state blob carries per-slot
primitives + per-slot PRF keys; the receiver constructs a matching
encryptor with the same arguments and calls `import_state` to
restore.

```rust,no_run
// Sender

use itb::Encryptor;
use itb::wrapper::{self, Cipher};

// Outer cipher key - preferred surface for HKDF / ML-KEM / key-rotation policy in user-side application. ITB Inner seeds + PRF key keep as CSPRNG derived.
let outer_key = wrapper::generate_key(Cipher::Aes128Ctr).unwrap();

// Per-slot primitive selection (Single Ouroboros, 3 + 1 slots).
// Every name must share the same native hash width — mixing widths
// raises ITBError at construction time.
// Triple Ouroboros mirror — Encryptor::mixed_triple takes seven
// per-slot names (noise + 3 data + 3 start) plus the optional
// primitive_l lockSeed.
let mut enc = Encryptor::mixed_single(
    "blake3",         // primitive_n: noiseSeed:  BLAKE3
    "blake2s",        // primitive_d: dataSeed:   BLAKE2s
    "areion256",      // primitive_s: startSeed:  Areion-SoEM-256
    Some("blake2b256"), // primitive_l: dedicated lockSeed (None for no lockSeed slot)
    1024,             // key_bits
    "hmac-blake3",    // mac
).unwrap();

// Per-instance configuration applies as for Encryptor::new(...).
enc.set_nonce_bits(512).unwrap();
enc.set_barrier_fill(4).unwrap();
// BitSoup + LockSoup are auto-coupled on the on-direction by
// primitive_l above; explicit calls below are unnecessary but
// harmless if added.
// enc.set_bit_soup(1).unwrap();
// enc.set_lock_soup(1).unwrap();

// Per-slot introspection — primitive() returns "mixed" literal,
// primitive_at(slot) returns each slot's name, is_mixed() is the
// typed predicate. Slot ordering is canonical: 0 = noiseSeed,
// 1 = dataSeed, 2 = startSeed, 3 = lockSeed (Single); Triple
// grows the middle range to 7 slots + lockSeed.
println!(
    "mixed={} primitive={:?}",
    enc.is_mixed().unwrap(),
    enc.primitive().unwrap(),
);
for i in 0..4 {
    println!("  slot {}: {}", i, enc.primitive_at(i).unwrap());
}

let blob = enc.export().unwrap();
println!("state blob: {} bytes", blob.len());

let plaintext = b"mixed-primitive Easy Mode payload";

// Authenticated encrypt — 32-byte tag is computed across the
// entire decrypted capacity and embedded inside the RGBWYOPA
// container, preserving oracle-free deniability.
let mut encrypted = enc.encrypt_auth(plaintext).unwrap();
println!("encrypted: {} bytes", encrypted.len());

// Format-deniability ITB masking through outer cipher AES-128-CTR with ~0% overhead over ITB Encrypt / Decrypt (Recommended in every case).
let nonce = wrapper::wrap_in_place(Cipher::Aes128Ctr, &outer_key, &mut encrypted).unwrap();
let mut wire = nonce;
wire.extend_from_slice(&encrypted);
println!("wire: {} bytes", wire.len());

// Send wire + state blob; Drop releases at scope end.


// Receiver

use itb::wrapper as wrapper_recv;

// Receive wire + state blob
// let wire = ...;
// let blob = ...;

// Receiver constructs a matching mixed encryptor — every per-slot
// primitive name plus key_bits and mac must agree with the sender.
// import_state validates each per-slot primitive against the
// receiver's bound spec; mismatches raise ITBError with the
// "primitive" field tag.
let mut dec = Encryptor::mixed_single(
    "blake3",
    "blake2s",
    "areion256",
    Some("blake2b256"),
    1024,
    "hmac-blake3",
).unwrap();

// Restore PRF keys, seed components, MAC key, and the per-instance
// configuration overrides from the saved blob. Mixed blobs carry
// mixed:true plus a primitives array; import_state on a single-
// primitive receiver (or vice versa) is rejected as a primitive
// mismatch.
dec.import_state(&blob).unwrap();

// Strip the leading nonce, unwrap the body, then decrypt.
let mut wire_buf = wire;
let encrypted = wrapper_recv::unwrap_in_place(wrapper_recv::Cipher::Aes128Ctr, &outer_key, &mut wire_buf).unwrap();

let decrypted = dec.decrypt_auth(encrypted).unwrap();
println!("decrypted: {}", String::from_utf8_lossy(&decrypted));
```

## Quick Start — Triple Ouroboros

Triple Ouroboros (3× security: P × 2^(3×key_bits)) takes seven
seeds (one shared `noiseSeed` plus three `dataSeed` and three
`startSeed`) on the low-level path, all wrapped behind a single
[`Encryptor`] call when `mode = 3` is passed to the constructor.

```rust,no_run
use itb::Encryptor;
use itb::wrapper::{self, Cipher};

// Outer cipher key - preferred surface for HKDF / ML-KEM / key-rotation policy in user-side application. ITB Inner seeds + PRF key keep as CSPRNG derived.
let outer_key = wrapper::generate_key(Cipher::Aes128Ctr).unwrap();

// mode=3 selects Triple Ouroboros. All other constructor arguments
// behave identically to the Single (mode=1) case shown above.
let mut enc = Encryptor::new(
    Some("areion512"),
    Some(2048),
    Some("hmac-blake3"),
    3,
).unwrap();

let plaintext = b"Triple Ouroboros payload";
let mut encrypted = enc.encrypt_auth(plaintext).unwrap();

// Format-deniability ITB masking through outer cipher AES-128-CTR with ~0% overhead over ITB Encrypt / Decrypt (Recommended in every case).
let nonce = wrapper::wrap_in_place(Cipher::Aes128Ctr, &outer_key, &mut encrypted).unwrap();
let mut wire = nonce;
wire.extend_from_slice(&encrypted);

// Receiver — strip the leading nonce, unwrap the body, then decrypt.
let mut wire_buf = wire;
let recovered = wrapper::unwrap_in_place(Cipher::Aes128Ctr, &outer_key, &mut wire_buf).unwrap();
let decrypted = enc.decrypt_auth(recovered).unwrap();
assert_eq!(decrypted, plaintext);
```

The seven-seed split is internal to the encryptor; the on-wire
ciphertext format is identical in shape to Single Ouroboros — only
the internal payload split / interleave differs. Mixed-primitive
Triple is reachable via [`Encryptor::mixed_triple`].

## Quick Start — Areion-SoEM-512 + HMAC-BLAKE3 (Low-Level, MAC Authenticated)

The lower-level path uses explicit [`Seed`] handles for the
noise / data / start trio plus an optional dedicated
[`Seed`] wired in through [`Seed::attach_lock_seed`]. Useful when
the caller needs full control over per-slot keying (e.g. PRF
material stored in an HSM) or when slotting into the existing Go
`itb.Encrypt` / `itb.Decrypt` call surface from a Rust client. The
high-level [`Encryptor`] above wraps this same path with one
constructor call.

```rust,no_run
// Sender

use itb::{decrypt_auth, encrypt_auth, Blob512, Seed, MAC};
use itb::wrapper::{self, Cipher};

// Optional: global configuration (all process-wide, atomic)
itb::set_max_workers(8).unwrap();    // limit to 8 CPU cores (default: 0 = all CPUs)
itb::set_nonce_bits(512).unwrap();   // 512-bit nonce (default: 128-bit)
itb::set_barrier_fill(4).unwrap();   // CSPRNG fill margin (default: 1, valid: 1,2,4,8,16,32)

itb::set_bit_soup(1).unwrap();       // optional bit-level split ("bit-soup"; default: 0 = byte-level)
                                     // automatically enabled for Single Ouroboros if
                                     // itb::set_lock_soup(1) is enabled or vice versa

itb::set_lock_soup(1).unwrap();      // optional Insane Interlocked Mode: per-chunk PRF-keyed
                                     // bit-permutation overlay on top of bit-soup;
                                     // automatically enabled for Single Ouroboros if
                                     // itb::set_bit_soup(1) is enabled or vice versa

// Three independent CSPRNG-keyed Areion-SoEM-512 seeds. Each Seed
// pre-keys its primitive once at construction; the C ABI / FFI
// layer auto-wires the AVX-512 + VAES + ILP + ZMM-batched chain-
// absorb dispatch through Seed::BatchHash — no manual batched-arm
// attachment is required on the Rust side.
let ns = Seed::new("areion512", 2048).unwrap();   // random noise CSPRNG seeds + hash key generated
let ds = Seed::new("areion512", 2048).unwrap();   // random data  CSPRNG seeds + hash key generated
let ss = Seed::new("areion512", 2048).unwrap();   // random start CSPRNG seeds + hash key generated

// Optional: dedicated lockSeed for the bit-permutation derivation
// channel. Separates that PRF's keying material from the noiseSeed-
// driven noise-injection channel without changing the public encrypt
// / decrypt signatures. The bit-permutation overlay must be engaged
// (itb::set_bit_soup(1) or itb::set_lock_soup(1) — both already on
// above) before the first encrypt; the build-PRF guard panics on
// encrypt-time when an attach is present without either flag.
let ls = Seed::new("areion512", 2048).unwrap();   // random lock CSPRNG seeds + hash key generated
ns.attach_lock_seed(&ls).unwrap();

// HMAC-BLAKE3 — 32-byte CSPRNG key, 32-byte tag. Real code should
// pull the key bytes from a CSPRNG (e.g. `getrandom` crate); the
// zero key here is for example purposes only.
let mac_key = [0u8; 32];
let mac = MAC::new("hmac-blake3", &mac_key).unwrap();

// Outer cipher key - preferred surface for HKDF / ML-KEM / key-rotation policy in user-side application. ITB Inner seeds + PRF key keep as CSPRNG derived.
let outer_key = wrapper::generate_key(Cipher::Aes128Ctr).unwrap();

let plaintext = b"any text or binary data - including 0x00 bytes";

// Authenticated encrypt — 32-byte tag is computed across the
// entire decrypted capacity and embedded inside the RGBWYOPA
// container, preserving oracle-free deniability.
let mut encrypted = encrypt_auth(&ns, &ds, &ss, &mac, plaintext).unwrap();
println!("encrypted: {} bytes", encrypted.len());

// Format-deniability ITB masking through outer cipher AES-128-CTR with ~0% overhead over ITB Encrypt / Decrypt (Recommended in every case).
let nonce = wrapper::wrap_in_place(Cipher::Aes128Ctr, &outer_key, &mut encrypted).unwrap();
let mut wire = nonce;
wire.extend_from_slice(&encrypted);
println!("wire: {} bytes", wire.len());

// Cross-process persistence: itb::Blob512 packs every seed's hash
// key + components, the optional dedicated lockSeed, and the MAC
// key + name into one JSON blob alongside the captured process-
// wide globals. lockseed=true / mac=true opt the corresponding
// sections in.
let blob = Blob512::new().unwrap();
blob.set_key(itb::SLOT_N, &ns.hash_key().unwrap()).unwrap();
blob.set_components(itb::SLOT_N, &ns.components().unwrap()).unwrap();
blob.set_key(itb::SLOT_D, &ds.hash_key().unwrap()).unwrap();
blob.set_components(itb::SLOT_D, &ds.components().unwrap()).unwrap();
blob.set_key(itb::SLOT_S, &ss.hash_key().unwrap()).unwrap();
blob.set_components(itb::SLOT_S, &ss.components().unwrap()).unwrap();
blob.set_key(itb::SLOT_L, &ls.hash_key().unwrap()).unwrap();
blob.set_components(itb::SLOT_L, &ls.components().unwrap()).unwrap();
blob.set_mac_key(Some(&mac_key)).unwrap();
blob.set_mac_name(Some("hmac-blake3")).unwrap();
let blob_bytes = blob.export(true, true).unwrap();   // lockseed=true, mac=true
println!("persistence blob: {} bytes", blob_bytes.len());

// Send wire + blob_bytes; Drop releases the seed, MAC, and blob
// handles at scope end.


// Receiver — same code block, shared `use` from above.

itb::set_max_workers(8).unwrap();   // deployment knob — not serialised by Blob512

// Receive wire + blob_bytes
// let wire = ...;
// let blob_bytes = ...;

// Blob512.import_blob restores per-slot hash keys + components AND
// applies the captured globals (nonce_bits / barrier_fill / bit_soup
// / lock_soup) via the process-wide setters.
let restored = Blob512::new().unwrap();
restored.import_blob(&blob_bytes).unwrap();

let ns = Seed::from_components(
    "areion512",
    &restored.get_components(itb::SLOT_N).unwrap(),
    &restored.get_key(itb::SLOT_N).unwrap(),
).unwrap();
let ds = Seed::from_components(
    "areion512",
    &restored.get_components(itb::SLOT_D).unwrap(),
    &restored.get_key(itb::SLOT_D).unwrap(),
).unwrap();
let ss = Seed::from_components(
    "areion512",
    &restored.get_components(itb::SLOT_S).unwrap(),
    &restored.get_key(itb::SLOT_S).unwrap(),
).unwrap();
let ls = Seed::from_components(
    "areion512",
    &restored.get_components(itb::SLOT_L).unwrap(),
    &restored.get_key(itb::SLOT_L).unwrap(),
).unwrap();
ns.attach_lock_seed(&ls).unwrap();

let mac_name = restored.get_mac_name().unwrap();
let mac_key = restored.get_mac_key().unwrap();
let mac = MAC::new(&mac_name, &mac_key).unwrap();

// Strip the leading nonce, unwrap the body, then decrypt.
let mut wire_buf = wire;
let encrypted = wrapper::unwrap_in_place(Cipher::Aes128Ctr, &outer_key, &mut wire_buf).unwrap();

// Authenticated decrypt — any single-bit tamper triggers MAC
// failure (no oracle leak about which byte was tampered).
let decrypted = decrypt_auth(&ns, &ds, &ss, &mac, encrypted).unwrap();
println!("decrypted: {}", String::from_utf8_lossy(&decrypted));
```

## Streams — chunked I/O over `Read` / `Write`

[`StreamEncryptor`] / [`StreamDecryptor`] (and the seven-seed
counterparts [`StreamEncryptor3`] / [`StreamDecryptor3`]) wrap the
Single Message Encrypt / Decrypt API behind a `Write` / `feed`-driven
chunked I/O surface. ITB ciphertexts cap at ~64 MB plaintext per
chunk; streaming larger payloads slices the input into chunks at
the binding layer, encrypts each chunk through the regular FFI
path, and concatenates the results. Memory peak is bounded by
`chunk_size` (default [`DEFAULT_CHUNK_SIZE`] = 16 MiB) regardless
of the total payload length.

```rust,no_run
use itb::{Seed, StreamDecryptor, StreamEncryptor};

let n = Seed::new("blake3", 1024).unwrap();
let d = Seed::new("blake3", 1024).unwrap();
let s = Seed::new("blake3", 1024).unwrap();

// Encrypt: write plaintext into the encryptor, ciphertext lands in
// the wrapped Vec<u8> sink. close() flushes the trailing partial
// chunk; Drop best-effort-flushes on scope exit.
let mut sink: Vec<u8> = Vec::new();
{
    let mut enc = StreamEncryptor::new(&n, &d, &s, &mut sink, 1 << 16).unwrap();
    enc.write(b"chunk one").unwrap();
    enc.write(b"chunk two").unwrap();
    enc.close().unwrap();
}
let ciphertext = sink;

// Decrypt: feed ciphertext bytes (any granularity, partial chunks
// are buffered until complete), plaintext lands in the sink as
// each chunk completes. close() errors when leftover bytes do not
// form a complete chunk.
let mut psink: Vec<u8> = Vec::new();
{
    let mut dec = StreamDecryptor::new(&n, &d, &s, &mut psink).unwrap();
    dec.feed(&ciphertext).unwrap();
    dec.close().unwrap();
}
assert_eq!(psink, b"chunk onechunk two");
```

For driving an encrypt or decrypt straight off a `Read` / `Write`
pair, the convenience wrappers [`encrypt_stream`] /
[`decrypt_stream`] (plus [`encrypt_stream_triple`] /
[`decrypt_stream_triple`]) loop until EOF internally:

```rust,no_run
use std::io::Cursor;
use itb::{decrypt_stream, encrypt_stream, Seed};

let n = Seed::new("blake3", 1024).unwrap();
let d = Seed::new("blake3", 1024).unwrap();
let s = Seed::new("blake3", 1024).unwrap();

let plaintext = vec![0xABu8; 5 * 1024 * 1024];
let mut ciphertext: Vec<u8> = Vec::new();
encrypt_stream(&n, &d, &s, Cursor::new(&plaintext), &mut ciphertext, 1 << 20).unwrap();

let mut recovered: Vec<u8> = Vec::new();
decrypt_stream(&n, &d, &s, Cursor::new(&ciphertext), &mut recovered, 1 << 16).unwrap();
assert_eq!(recovered, plaintext);
```

Switching [`itb::set_nonce_bits`] mid-stream produces a chunk
header layout the paired decryptor (which snapshots
[`itb::header_size`] at construction) cannot parse — the nonce
size must be stable for the lifetime of one stream pair.

## Native Blob — low-level state persistence

[`Blob128`] / [`Blob256`] / [`Blob512`] wrap the libitb Native
Blob C ABI: a width-specific container that packs the low-level
encryptor material (per-seed hash key + components + optional
dedicated lockSeed + optional MAC key + name) plus the captured
process-wide configuration into one self-describing JSON blob.
Used on the lower-level encrypt / decrypt path where each seed
slot may carry a different primitive — the high-level
[`Encryptor::export`] wraps a narrower one-primitive-per-encryptor
surface that uses the same wire format under the hood.

```rust,no_run
use itb::{Blob512, Seed};

// Sender side — pack a Single-Ouroboros + Areion-SoEM-512 + MAC
// state blob.
let ns = Seed::new("areion512", 2048).unwrap();
let ds = Seed::new("areion512", 2048).unwrap();
let ss = Seed::new("areion512", 2048).unwrap();

let mac_key = [0u8; 32];
let blob = Blob512::new().unwrap();
blob.set_key(itb::SLOT_N, &ns.hash_key().unwrap()).unwrap();
blob.set_components(itb::SLOT_N, &ns.components().unwrap()).unwrap();
blob.set_key(itb::SLOT_D, &ds.hash_key().unwrap()).unwrap();
blob.set_components(itb::SLOT_D, &ds.components().unwrap()).unwrap();
blob.set_key(itb::SLOT_S, &ss.hash_key().unwrap()).unwrap();
blob.set_components(itb::SLOT_S, &ss.components().unwrap()).unwrap();
blob.set_mac_key(Some(&mac_key)).unwrap();
blob.set_mac_name(Some("hmac-blake3")).unwrap();
let blob_bytes = blob.export(false, true).unwrap();   // lockseed=false, mac=true

// Receiver side — round-trip back to working seed material.
let restored = Blob512::new().unwrap();
restored.import_blob(&blob_bytes).unwrap();

let _ns = Seed::from_components(
    "areion512",
    &restored.get_components(itb::SLOT_N).unwrap(),
    &restored.get_key(itb::SLOT_N).unwrap(),
).unwrap();
// ... wire ds, ss the same way; rebuild MAC; decrypt_auth ...
```

The blob is mode-discriminated: [`Blob512::export`] packs Single
material; [`Blob512::export3`] packs Triple material; the matching
[`Blob512::import_blob`] / [`Blob512::import_triple`] receivers
reject the wrong importer with
`ITBError(STATUS_BLOB_MODE_MISMATCH)`.

## Hash primitives (Single / Triple)

Names match the canonical `hashes/` registry. Listed below in the
canonical primitive ordering used across ITB documentation —
`AES-CMAC`, `SipHash-2-4`, `ChaCha20`, `Areion-SoEM-256`,
`BLAKE2s`, `BLAKE3`, `BLAKE2b-256`, `BLAKE2b-512`,
`Areion-SoEM-512` — the FFI names are `aescmac`, `siphash24`,
`chacha20`, `areion256`, `blake2s`, `blake3`, `blake2b256`,
`blake2b512`, `areion512`. Triple Ouroboros (3× security) takes
seven seeds (one shared `noiseSeed` plus three `dataSeed` and three
`startSeed`) via [`encrypt_triple`] / [`decrypt_triple`] and the
authenticated counterparts [`encrypt_auth_triple`] /
[`decrypt_auth_triple`]. Streaming counterparts:
[`StreamEncryptor3`] / [`StreamDecryptor3`] /
[`encrypt_stream_triple`] / [`decrypt_stream_triple`].

All seeds passed to one `encrypt` / `decrypt` call must share the
same native hash width. Mixing widths raises
`ITBError(STATUS_SEED_WIDTH_MIX)`.

## MAC primitives

Names match the libitb MAC registry; ordering matches that registry's declaration order.

| MAC | Key bytes | Tag bytes | Underlying primitive |
|---|---|---|---|
| `kmac256` | 32 | 32 | KMAC256 (Keccak-derived) |
| `hmac-sha256` | 32 | 32 | HMAC over SHA-256 |
| `hmac-blake3` | 32 | 32 | HMAC over BLAKE3 |

`kmac256` and `hmac-sha256` accept keys 16 bytes and longer; the binding fleet's tests and examples use 32 bytes uniformly across primitives for cross-binding consistency. `hmac-blake3` requires exactly 32 bytes by construction.

## Process-wide configuration

Every setter takes effect for all subsequent encrypt / decrypt
calls in the process. Out-of-range values surface as
`ITBError(STATUS_BAD_INPUT)` rather than crashing.

| Function | Accepted values | Default |
|---|---|---|
| `set_max_workers(n)` | non-negative i32 | 0 (auto) |
| `set_nonce_bits(n)` | 128, 256, 512 | 128 |
| `set_barrier_fill(n)` | 1, 2, 4, 8, 16, 32 | 1 |
| `set_bit_soup(mode)` | 0 (off), non-zero (on) | 0 |
| `set_lock_soup(mode)` | 0 (off), non-zero (on) | 0 |

Read-only constants: [`itb::max_key_bits`], [`itb::channels`],
[`itb::header_size`], [`itb::version`].

For low-level chunk parsing (e.g. when implementing custom file
formats around ITB chunks): [`itb::parse_chunk_len`] inspects the
fixed-size chunk header and returns the chunk's total
on-the-wire length; [`itb::header_size`] returns the active
header byte count (20 / 36 / 68 for nonce sizes 128 / 256 / 512
bits).

MAC names available via [`itb::list_macs`]: `kmac256`,
`hmac-sha256`, `hmac-blake3`. Hash names via
[`itb::list_hashes`].

## Concurrency

The libitb shared library exposes process-wide configuration
through a small set of atomics (`set_nonce_bits`,
`set_barrier_fill`, `set_bit_soup`, `set_lock_soup`,
`set_max_workers`). Multiple threads calling these setters
concurrently without external coordination will race for the
final value visible to subsequent encrypt / decrypt calls —
serialise the mutators behind a `std::sync::Mutex` (or set them
once at startup before spawning workers) when multiple Rust
threads need to touch them.

Per-encryptor configuration via [`Encryptor::set_nonce_bits`] /
[`Encryptor::set_barrier_fill`] / [`Encryptor::set_bit_soup`] /
[`Encryptor::set_lock_soup`] mutates only that handle's Config
copy and is safe to call from the owning thread without affecting
other [`Encryptor`] instances. The cipher methods
([`Encryptor::encrypt`] / [`Encryptor::decrypt`] /
[`Encryptor::encrypt_auth`] / [`Encryptor::decrypt_auth`]) take
`&mut self`; sharing one [`Encryptor`] across threads requires
external synchronisation. Distinct [`Encryptor`] handles, each
owned by one thread, run independently against the libitb
worker pool.

By contrast, the low-level cipher free functions ([`itb::encrypt`]
/ [`itb::decrypt`] / [`itb::encrypt_auth`] / [`itb::decrypt_auth`]
plus the Triple counterparts) take `&Seed` and allocate their
output `Vec<u8>` per call — they are **thread-safe** under
concurrent invocation on the same Seed handles, with libitb's
worker pool dispatching them independently. Two exceptions:
[`Seed::attach_lock_seed`] mutates the noise Seed and must not race
against an in-flight cipher call on it, and the process-wide
setters above stay process-global.

The [`Seed`], [`MAC`], [`Encryptor`], [`Blob128`] / [`Blob256`] /
[`Blob512`] handle types are `Send + Sync` (auto-derived). Crossing
a handle to another thread — moving via channel, dropping on a
worker, calling the `&self`-only setters from two threads against
the same handle — is sound: libitb's cgo handle table is internally
mutex-protected, and the binding never holds Rust-side state for
these handles outside the per-call FFI surface (the only Rust-side
state is the [`Encryptor`]'s output-buffer cache, which the cipher
methods serialise via `&mut self`). Sharing a `&Encryptor` across
threads to call `&self` setters concurrently is therefore safe at
the libitb layer; the resulting visible Config is whichever setter
landed last.

## Error model

Every failure surfaces as [`ITBError`] with a status `code()` and
a `message()`:

```rust,no_run
use itb::{ITBError, MAC};

match MAC::new("nonsense", &[0u8; 32]) {
    Ok(_) => unreachable!(),
    Err(e) => {
        // e.code() == itb::STATUS_BAD_MAC
        eprintln!("code={} msg={}", e.code(), e);
    }
}
```

Status codes are documented in `cmd/cshared/internal/capi/errors.go`
and mirrored as `STATUS_*` constants re-exported from the crate
root (e.g. [`itb::STATUS_MAC_FAILURE`],
[`itb::STATUS_EASY_MISMATCH`], [`itb::STATUS_SEED_WIDTH_MIX`]).
The [`Encryptor::import_state`] path additionally folds the
offending JSON field name into the error message on
`STATUS_EASY_MISMATCH`; the field is also retrievable via
[`itb::last_mismatch_field`].

**Note:** empty plaintext / ciphertext is rejected by libitb itself
with `ITBError(STATUS_ENCRYPT_FAILED)` ("itb: empty data") on every
cipher entry point. Pass at least one byte.

### Status codes

| Code | Name | Description |
|---|---|---|
| 0 | `STATUS_OK` | Success — the only non-failure return value |
| 1 | `STATUS_BAD_HASH` | Unknown hash primitive name |
| 2 | `STATUS_BAD_KEY_BITS` | ITB key width invalid for the chosen primitive |
| 3 | `STATUS_BAD_HANDLE` | FFI handle invalid or already freed |
| 4 | `STATUS_BAD_INPUT` | Generic shape / range / domain violation on a call argument |
| 5 | `STATUS_BUFFER_TOO_SMALL` | Output buffer cap below required size; probe-then-allocate idiom |
| 6 | `STATUS_ENCRYPT_FAILED` | Encrypt path raised on the Go side (rare; structural / OOM) |
| 7 | `STATUS_DECRYPT_FAILED` | Decrypt path raised on the Go side (corrupt ciphertext shape) |
| 8 | `STATUS_SEED_WIDTH_MIX` | Seeds passed to one call do not share the same native hash width |
| 9 | `STATUS_BAD_MAC` | Unknown MAC name or key-length violates the primitive's `min_key_bytes` |
| 10 | `STATUS_MAC_FAILURE` | MAC verification failed — tampered ciphertext or wrong MAC key |
| 11 | `STATUS_EASY_CLOSED` | Easy Mode encryptor call after `close()` |
| 12 | `STATUS_EASY_MALFORMED` | Easy Mode `import_state` blob fails JSON parse / structural check |
| 13 | `STATUS_EASY_VERSION_TOO_NEW` | Easy Mode blob version field higher than this build supports |
| 14 | `STATUS_EASY_UNKNOWN_PRIMITIVE` | Easy Mode blob references a primitive this build does not know |
| 15 | `STATUS_EASY_UNKNOWN_MAC` | Easy Mode blob references a MAC this build does not know |
| 16 | `STATUS_EASY_BAD_KEY_BITS` | Easy Mode blob's `key_bits` invalid for its primitive |
| 17 | `STATUS_EASY_MISMATCH` | Easy Mode blob disagrees with the receiver on `primitive` / `key_bits` / `mode` / `mac`; field name retrievable via `itb::last_mismatch_field()` |
| 18 | `STATUS_EASY_LOCKSEED_AFTER_ENCRYPT` | `set_lock_seed(1)` called after the first encrypt — must precede the first ciphertext |
| 19 | `STATUS_BLOB_MODE_MISMATCH` | Native Blob importer received a Single blob into a Triple receiver (or vice versa) |
| 20 | `STATUS_BLOB_MALFORMED` | Native Blob payload fails JSON parse / magic / structural check |
| 21 | `STATUS_BLOB_VERSION_TOO_NEW` | Native Blob version field higher than this libitb build supports |
| 22 | `STATUS_BLOB_TOO_MANY_OPTS` | Native Blob export opts mask carries unsupported bits |
| 23 | `STATUS_STREAM_TRUNCATED` | Streaming AEAD transcript truncated before the terminator chunk; surfaced by the binding's stream loop as `ITBError` carrying this status |
| 24 | `STATUS_STREAM_AFTER_FINAL` | Streaming AEAD transcript carries chunk bytes after the terminator; surfaced by the binding's stream loop as `ITBError` carrying this status |
| 99 | `STATUS_INTERNAL` | Generic "internal" sentinel for paths the caller cannot recover from at the binding layer |

## Constraints

- **Rust 1.70 minimum (edition 2021).** The crate's `Cargo.toml`
  declares `edition = "2021"` and `rust-version = "1.70"`. Earlier
  toolchains lack stabilised `let ... else` and other ergonomics the
  wrapper layer relies on.
- **Single crate.** All consumer-visible declarations live under
  `bindings/rust/src/`; the FFI substrate is the `sys` submodule kept
  separate so audits can read it independently.
- **libitb.so required at runtime.** The crate links against
  `dist/<os>-<arch>/libitb.<ext>` — the shared library must be built
  first and reachable through the loader's search path (compile-time
  `-L` plus runtime `RPATH` or `LD_LIBRARY_PATH`).
- **No external runtime deps beyond libstd + libitb.so.** The crate
  uses only the Rust standard library; no third-party runtime
  dependencies are pulled in.
- **Frozen C ABI.** The `ITB_*` exports declared in the `sys`
  submodule (synced from `dist/<os>-<arch>/libitb.h`) are the
  contract; the binding does not extend or reshape them.
- **No `dlopen`.** Symbols are bound at link time. Consumers wanting
  runtime FFI loading can wrap this crate's `sys` layer in their own
  `libloading` shim.

## API Overview

[`Encryptor`]: src/encryptor.rs
[`Encryptor::new`]: src/encryptor.rs
[`Encryptor::mixed_single`]: src/encryptor.rs
[`Encryptor::mixed_triple`]: src/encryptor.rs
[`Encryptor::set_nonce_bits`]: src/encryptor.rs
[`Encryptor::set_barrier_fill`]: src/encryptor.rs
[`Encryptor::set_bit_soup`]: src/encryptor.rs
[`Encryptor::set_lock_soup`]: src/encryptor.rs
[`Encryptor::encrypt`]: src/encryptor.rs
[`Encryptor::decrypt`]: src/encryptor.rs
[`Encryptor::encrypt_auth`]: src/encryptor.rs
[`Encryptor::decrypt_auth`]: src/encryptor.rs
[`Encryptor::export`]: src/encryptor.rs
[`Encryptor::import_state`]: src/encryptor.rs
[`Seed`]: src/seed.rs
[`Seed::attach_lock_seed`]: src/seed.rs
[`MAC`]: src/mac.rs
[`Blob128`]: src/blob.rs
[`Blob256`]: src/blob.rs
[`Blob512`]: src/blob.rs
[`Blob512::export`]: src/blob.rs
[`Blob512::export3`]: src/blob.rs
[`Blob512::import_blob`]: src/blob.rs
[`Blob512::import_triple`]: src/blob.rs
[`StreamEncryptor`]: src/streams.rs
[`StreamDecryptor`]: src/streams.rs
[`StreamEncryptor3`]: src/streams.rs
[`StreamDecryptor3`]: src/streams.rs
[`encrypt_stream`]: src/streams.rs
[`decrypt_stream`]: src/streams.rs
[`encrypt_stream_triple`]: src/streams.rs
[`decrypt_stream_triple`]: src/streams.rs
[`encrypt_triple`]: src/encrypt.rs
[`decrypt_triple`]: src/encrypt.rs
[`encrypt_auth_triple`]: src/encrypt.rs
[`decrypt_auth_triple`]: src/encrypt.rs
[`DEFAULT_CHUNK_SIZE`]: src/streams.rs
[`ITBError`]: src/error.rs
[`itb::last_mismatch_field`]: src/encryptor.rs
[`itb::set_nonce_bits`]: src/registry.rs
[`itb::header_size`]: src/registry.rs
[`itb::parse_chunk_len`]: src/registry.rs
[`itb::max_key_bits`]: src/registry.rs
[`itb::channels`]: src/registry.rs
[`itb::version`]: src/registry.rs
[`itb::list_macs`]: src/registry.rs
[`itb::list_hashes`]: src/registry.rs
[`itb::set_memory_limit`]: src/registry.rs
[`itb::set_gc_percent`]: src/registry.rs
[`itb::STATUS_MAC_FAILURE`]: src/lib.rs
[`itb::STATUS_EASY_MISMATCH`]: src/lib.rs
[`itb::STATUS_SEED_WIDTH_MIX`]: src/lib.rs
