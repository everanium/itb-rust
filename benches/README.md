# ITB Rust Binding - Easy Mode Benchmark

Two binaries cover the Easy Mode encryption / decryption surface
exposed by the Rust binding:

* `bench_single.rs` — Single Ouroboros (mode=1, 3 seeds + optional
  dedicated lockSeed). Walks the nine PRF-grade primitives plus
  one mixed-primitive variant.
* `bench_triple.rs` — Triple Ouroboros (mode=3, 7 seeds + optional
  dedicated lockSeed). Same nine + one mixed grid as the Single
  binary.

Both binaries pin **1024-bit ITB key width** and **16 MiB
non-deterministic-fill payload**, run four ops per case (`encrypt`,
`decrypt`, `encrypt_auth`, `decrypt_auth`), and emit a
Go-bench-style line per case (`name iters ns/op MB/s`).

The harness is a custom Go-bench-style runner in `benches/common.rs`
(no `criterion` / `libtest` dependency); the two `[[bench]]` entries
in `Cargo.toml` declare `harness = false` so each bench file's own
`fn main()` is the entry point. `cargo bench` builds in release mode
by default, so no `--release` flag is needed.

## Prerequisites

Build the shared library once (see the binding
[README](../README.md)):

```bash
go build -trimpath -buildmode=c-shared \
    -o dist/linux-amd64/libitb.so ./cmd/cshared
```

A project-private opt-out tag is available when the 4-lane
chain-absorb wrapper is dead weight (hosts without AVX-512+VL).
The tag disables only the chain-absorb asm; upstream stdlib asm
stays engaged so the per-pixel single Func runs at upstream-asm
speed via `process_cgo`'s nil-`BatchHash` fallback:

```bash
go build -trimpath -tags=noitbasm -buildmode=c-shared \
    -o dist/linux-amd64/libitb.so ./cmd/cshared
```

The Rust binding loads `libitb.so` / `.dll` / `.dylib` at runtime
through `libloading`, picking it up from `LD_LIBRARY_PATH`,
`<repo>/dist/<os>-<arch>/`, or the system loader path; see
`bindings/rust/src/ffi.rs` for the full search list.

## Run

From the binding root (`bindings/rust/`):

```bash
cargo bench --bench bench_single
cargo bench --bench bench_triple
```

## Environment variables

| Variable             | Default | Purpose |
|----------------------|---------|---------|
| `ITB_NONCE_BITS`     | `128`   | Process-wide nonce width — `128`, `256`, or `512`. Mirrors `ITB_NONCE_BITS` from `bitbyte_test.go`. |
| `ITB_LOCKSEED`       | unset   | When set to a non-empty / non-`0` value, every encryptor in the run calls `set_lock_seed(1)`. Easy Mode auto-couples `set_bit_soup(1)` + `set_lock_soup(1)`, so no separate flags are needed. The mixed-primitive cases already attach a dedicated lockSeed at construction (via `primitive_l`) and ignore this knob. |
| `ITB_BENCH_FILTER`   | unset   | Substring filter on bench-function names — only cases whose name contains the filter are run. Useful when iterating on one primitive / op. |
| `ITB_BENCH_MIN_SEC`  | `2.0`   | Minimum measured wall-clock seconds per case. The runner keeps doubling iteration count until the measured batch reaches the threshold, mirroring Go's `-benchtime=Ns`. |

Worker count is fixed at `itb::set_max_workers(0)` (auto-detect),
matching the Go bench default.

## Examples

Whole grid, default settings (128-bit nonces, no lockSeed):

```bash
cargo bench --bench bench_single
```

512-bit nonces with the dedicated lockSeed channel + auto-coupled
overlay:

```bash
ITB_NONCE_BITS=512 ITB_LOCKSEED=1 cargo bench --bench bench_triple
```

Just the BLAKE3 row of the Single grid:

```bash
ITB_BENCH_FILTER=blake3_1024bit cargo bench --bench bench_single
```

Only the encrypt-with-MAC ops across every primitive in the Triple
grid, with a longer 5-second per-case budget for tighter
confidence intervals:

```bash
ITB_BENCH_FILTER=encrypt_auth_16mb ITB_BENCH_MIN_SEC=5 \
    cargo bench --bench bench_triple
```

Just the mixed-primitive cases on the Single side:

```bash
ITB_BENCH_FILTER=mixed cargo bench --bench bench_single
```

## Output format

```
# easy_single primitives=9 key_bits=1024 mac=kmac256 nonce_bits=128 lockseed=off workers=auto
# benchmarks=40 payload_bytes=16777216 min_seconds=2
bench_single_aescmac_1024bit_encrypt_16mb               4    493210110.0 ns/op    32.44 MB/s
bench_single_aescmac_1024bit_decrypt_16mb               4    488104225.0 ns/op    32.78 MB/s
...
```

The four columns are:

1. Bench-function name (matches the `BenchmarkSingle*` /
   `BenchmarkTriple*` Go cohort, snake-cased and without the `Ext`
   infix that the Go side carries for namespace reasons).
2. Iteration count chosen to reach `ITB_BENCH_MIN_SEC`.
3. Per-iter wall-clock cost in nanoseconds.
4. Throughput in MiB/s, derived from `payload_bytes / ns_per_op`.

Comparison with the Go bench cohort goes via `(MB/s ratio)` — the
throughput column is the most direct cross-language signal for how
much overhead the Rust binding adds on top of the underlying
libitb call path.

## Recorded results

A snapshot of the four canonical pass results (Single + Triple,
each with and without `ITB_LOCKSEED=1`) is collected in
[BENCH.md](BENCH.md). The same file briefly discusses the FFI
overhead the binding leaves on top of the native Go path.
