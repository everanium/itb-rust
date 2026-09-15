## ITB Rust Binding

> **Security notice.** ITB is an experimental symmetric cipher construction without prior peer review, independent cryptanalysis, or formal certification. The construction's security properties have **not been verified** by independent cryptographers or mathematicians.
>
> PRF-grade hash functions are **required**. No warranty is provided.

**No bespoke cryptography.** ITB introduces no cryptographic primitive of its own — no custom S-box, permutation, or round function. It is a construction over existing primitives, much as PGP composes standard ciphers rather than defining one. Such constructions are not the object of algorithm-level cryptographic certification: national regimes (NIST CAVP/FIPS in the US, GOST/FSB in Russia, OSCCA's SM-series in China, IC3S in India, SOG-IS/EUCC and national lists in the EU, ASD's ISM in Australia, CRYPTREC in Japan, KCMVP in South Korea) certify **primitives** and the **modules** built on them, not compositional schemes. Eligibility for regulated use is therefore inherited from the primitives ITB is configured with, not conferred by ITB itself.

Thin proxy over the libitb3 shared library's `ITB_Triple_*` surface
(`cmd/cshared`). Runtime FFI via the `libloading` crate — no C
compiler at install time, no compile-time link; the `.so` / `.dylib`
/ `.dll` is resolved and dispatched at first use. Every hash-name /
MAC-name / cipher-name / profile-name is an opaque string passed
through to Go for validation; the binding carries no ITB construction
logic. The public surface is one `Pipeline` type (Init / Load / Save
/ Rekey / Close, Single Message encrypt / decrypt, buffered and
incremental stream sessions with `io::Read` / `io::Write` pumps), an
`OptsBuilder` query-string builder for Init overrides, the `Profile`
record with `register` / `lookup` / `profiles` / `inspect`, and the Go
runtime knobs.

## Prerequisites (Arch Linux)

```bash
sudo pacman -S go rustup cargo
```

Generic Linux / macOS: a Go toolchain plus a stable Rust toolchain
(rustup). Windows: the same via the MSVC or GNU toolchains; libitb3
builds as `libitb3.dll`.

## Build the shared library

The convenience driver builds `libitb3.so` plus the Rust crate's
release artefact in one step:

```bash
./bindings/rust/build.sh
```

Equivalent manual invocation:

```bash
go build -trimpath -buildmode=c-shared \
    -o dist/linux-amd64/libitb3.so ./cmd/cshared
cd bindings/rust && cargo build --release
```

## Library lookup order

1. `ITB_LIBITB3_PATH` environment variable (path to the shared
   library file).
2. `<repo>/dist/<os>-<arch>/libitb3.<ext>` resolved from the crate
   manifest directory (in-repo builds).
3. The OS default loader path (`LD_LIBRARY_PATH`, `ld.so.cache`,
   `DYLD_LIBRARY_PATH`, `PATH`).

## Usage example

```rust,no_run
use itb3::{OptsBuilder, Pipeline};

let opts = OptsBuilder::new();
let sender = Pipeline::init("singlemsg-triple-mac-v1", &opts)?;
let receiver = Pipeline::load(&sender.save()?, None)?;

let wire = sender.encrypt_message(b"any text or binary data")?;
let plain = receiver.decrypt_message(&wire)?;
assert_eq!(plain, b"any text or binary data");
# Ok::<(), itb3::ItbError>(())
```

`OptsBuilder` overrides the profile default at Init (chunk size,
outer cipher, parallax on/off, wrapper on/off, MAC name, palette,
worker cap). The resolved shape travels inside the blob, so the
receiver needs no options of its own:

```rust,no_run
# use itb3::{OptsBuilder, Pipeline};
let opts = OptsBuilder::new()
    .with_chunk_size(65536)
    .with_wrapper(false)
    .with_max_workers(4);
let sender = Pipeline::init("singlemsg-triple-mac-v1", &opts)?;
let _receiver = Pipeline::load(&sender.save()?, None)?;
# Ok::<(), itb3::ItbError>(())
```

`Pipeline::rekey` rotates the parallax + wrapper masters mid-session
(the eight ITB seeds and MAC key are fixed for the session lifetime
by design) and returns the fresh blob; the receiver picks up the new
masters by loading it:

```rust,no_run
# use itb3::{OptsBuilder, Pipeline};
# let opts = OptsBuilder::new();
# let mut sender = Pipeline::init("singlemsg-triple-mac-v1", &opts)?;
let perm = [0x11u8; 32];
let wrap = [0x22u8; 32];
let rotated = sender.rekey(&perm, &wrap)?;
let _receiver = Pipeline::load(&rotated, None)?;
# Ok::<(), itb3::ItbError>(())
```

The same rotation is available on the receiver side as a master
override pair on `load`: `Pipeline::load(&blob, Some((&perm, &wrap)))`
reopens the blob with fresh masters folded in.

Runnable version: `cargo run --example round_trip --release`. For
bounded-memory streaming, `encrypt_stream_pump` / `decrypt_stream_pump`
move any `io::Read` source into any `io::Write` sink through an
incremental session; the explicit `encrypt_stream` / `decrypt_stream`
sessions expose `write` / `end` / `read` for caller-driven loops.

Profile names, opts keys, and every primitive name are validated by
the Go side; a rejected string surfaces as `ItbError` carrying the
status code plus the `ITB_LastError` diagnostic.

## Persisting sessions

The blob returned by `save` is a self-describing session bundle: it
carries the resolved profile record, the inner key material, and the
parallax / wrapper masters. `load` reconstructs a Pipeline from it
without naming a profile.

```rust,no_run
# use itb3::{inspect, OptsBuilder, Pipeline};
# let sender = Pipeline::init("singlemsg-triple-mac-v1", &OptsBuilder::new())?;
let blob = sender.save()?;                         // current blob bytes
let receiver = Pipeline::load(&blob, None)?;       // reopen from bytes
sender.save_f("session.blob")?;                    // write to a file (mode 0600)
let receiver2 = Pipeline::load_f("session.blob", None)?; // reopen from a file
let profile = inspect(&blob)?;                // metadata only, no Pipeline
assert_eq!(profile.name, "singlemsg-triple-mac-v1");
# Ok::<(), itb3::ItbError>(())
```

`inspect` decodes the embedded `Profile` record without constructing
a Pipeline. `save_f` / `load_f` perform the file access inside libitb3.

Load works for blobs generated with shipped primitives (every entry in
the shipped catalogue). Blobs generated by Go programs that use
`hashes.Register` or `macs.Register` to install custom primitives
cannot be loaded through this binding — the receiver must use the Go
library directly and register the same custom primitive under the
same name before opening. Attempting to `load` such a blob through
this binding surfaces `ItbStatus::RecipePrimitiveUnknown`.

**Runtime tuning.** The worker cap is per-machine and never travels
in the blob; the receiver may pick its own after `load`:

```rust,no_run
# use itb3::{OptsBuilder, Pipeline};
# let receiver = Pipeline::init("singlemsg-triple-mac-v1", &OptsBuilder::new())?;
receiver.max_workers(4)?;   // clamped by libitb3; <= 0 selects auto
# Ok::<(), itb3::ItbError>(())
```

## Profile registry

`register` installs a user-defined profile under a new name from a
`Profile` record; `lookup` reads a registered record back; `profiles`
lists every registered name. The record's field rules are enforced by
libitb3.

```rust,no_run
use itb3::{Profile, lookup, profiles, register};

let mut custom = lookup("singlemsg-triple-nomac-v1")?;
custom.name.clear();               // a non-empty name must equal the register argument
custom.wrapper = false;
custom.outer_cipher.clear();
register("my-nomac-plain", &custom)?;
assert!(profiles()?.iter().any(|n| n == "my-nomac-plain"));
# Ok::<(), itb3::ItbError>(())
```

## Memory

Two process-wide knobs constrain Go runtime arena pacing, readable at
libitb3 load time via env vars (`ITB_GOMEMLIMIT`, `ITB_GOGC`) and
adjustable at any time programmatically. Pass `-1` to query without
changing:

```rust,no_run
use itb3::{set_gc_percent, set_memory_limit};

set_memory_limit(4 << 30)?;
set_gc_percent(100)?;
# Ok::<(), itb3::ItbError>(())
```

## Testing

```bash
./bindings/rust/run_tests.sh
```

The harness builds `libitb3.so`, exports `ITB_LIBITB3_PATH`, and
invokes `cargo test --release`. Positional arguments are forwarded to
cargo (e.g. `./run_tests.sh --test smoke`). The suite covers Single
Message round trips per shipped profile, stream pumps, incremental
sessions with pathological batch sizes, tampered-wire failure
stickiness, mid-flight cancellation, rekey, save / load persistence,
inspect, profile registration, and error mapping — surface parity checks; the deep suite lives in Go
under the shipped tree.

## Benchmarking

```bash
./bindings/rust/run_bench.sh
```

Criterion micro-benches: `encrypt_message` and `encrypt_stream_pump`
throughput at 1 KiB / 64 KiB / 1 MiB / 16 MiB. Positional arguments
are forwarded to the Criterion harness (e.g.
`./run_bench.sh --measurement-time 5`).

## itb3 CLI

The Go core ships an openssl-style CLI utility
[`itb3`](https://github.com/everanium/itb/tree/main/cmd/itb3/) that generates session blobs on disk
(`itb3 genblob <mode> <hash> -o blob.json`); this binding reopens
such blobs via `Pipeline::load_f`. `itb3` also encrypts / decrypts
payloads directly on disk (`-i` / `-o`) or through stdin / stdout,
rotates outer masters, and inspects stored blobs. See
[`cmd/itb3/README.md`](https://github.com/everanium/itb/blob/main/cmd/itb3/README.md) for the full
subcommand reference.

## eitb utility

A small CLI under `bindings/rust/eitb/` mirrors the shipped Go
`tools/eitb` scope for shell smoke tests:

```bash
cd bindings/rust/eitb && cargo build --release
./target/release/eitb version
./target/release/eitb profiles
./target/release/eitb encrypt singlemsg-triple-mac-v1 in.bin out.bin  # blob hex on stderr
./target/release/eitb decrypt singlemsg-triple-mac-v1 <blob-hex> out.bin back.bin
```

`decrypt` reopens the session with `Pipeline::load` from the blob
hex; the profile argument only selects the Single Message or
streaming cipher pair.

## Limitations

- The binding wraps the Triple Pipeline surface only. The Low-Level
  seed / MAC / blob / wrapper / parallax APIs are not exposed — use
  the shipped Go core for those.
- Streaming-decrypt caveat: chunked Streaming AEAD verifies per
  chunk, so plaintext of verified chunks is released before a later
  chunk can fail authentication.
- `ITB_LastError` is process-global last-write-wins; the textual
  diagnostic attached to an `ItbError` may belong to a different call
  under concurrent FFI use. The status code is always attributable.
- `Rekey` must not run concurrently with cipher calls or open stream
  sessions on the same `Pipeline`.
- libitb3 must be reachable at runtime through the lookup order above.

## License

Apache-2.0 — see [LICENSE](https://github.com/everanium/itb/blob/main/LICENSE).
