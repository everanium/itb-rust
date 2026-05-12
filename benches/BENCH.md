# ITB Rust Binding - Easy Mode Benchmark Results

Throughput (MB/s) of `itb::Encryptor::encrypt` / `decrypt` /
`encrypt_auth` / `decrypt_auth` over the libitb c-shared library
through the `libloading`-based Rust binding. Single + Triple
Ouroboros at 1024-bit ITB key width on a 16 MiB
non-deterministic-fill payload, four ops per primitive. The MAC
slot is bound to **HMAC-BLAKE3** — the lightest authenticated-mode
overhead among the three shipping MACs (the `encrypt_auth` row
sits within a few percent of the matching `encrypt` row).

The harness lives in this directory — see [README.md](README.md)
for invocation, environment variables, and the per-case output
format. The default measurement window is 5 seconds per case
(`ITB_BENCH_MIN_SEC=5`), wide enough to absorb the cold-cache /
warm-up transient that distorts shorter windows on the 16 MiB
encrypt / decrypt path.

## FFI overhead vs. native Go

The Rust path adds a `libloading` symbol dispatch per call, the C
ABI crossing into Go, and a result-copy from the c-shared output
buffer back into a Rust `Vec<u8>`. The binding caches a
per-encryptor output buffer and pre-allocates from a 1.25× upper
bound on the empirical ITB ciphertext-expansion factor (≤ 1.155
across every primitive / mode / nonce / payload-size combination)
so the hot loop avoids the size-probe round-trip the
process-global FFI helpers use.

The numbers below ride the default build (no opt-out tags). On
hosts without AVX-512+VL the Go side automatically nil-routes the
4-lane batched chain-absorb arm so the per-pixel hash falls
through to the upstream stdlib asm via the single Func — see the
build-tag table in [`../README.md`](../README.md) for the
`-tags=noitbasm` opt-outs.

## Intel Core i7-11700K (16 HT, native Linux, c-shared mode)

### ITB Single 1024-bit (security: P × 2^1024)

| Hash | Width | Crypto | Encrypt | Decrypt | Encrypt + MAC | Decrypt + MAC |
|---|---|---|---|---|---|---|
| **Areion-SoEM-256** | 256 | PRF | 188 | 286 | 182 | 264 |
| **Areion-SoEM-512** | 512 | PRF | 201 | 292 | 184 | 270 |
| **SipHash-2-4** | 128 | PRF | 153 | 190 | 141 | 183 |
| **AES-CMAC** | 128 | PRF | 186 | 266 | 174 | 247 |
| **BLAKE2b-512** | 512 | PRF | 133 | 165 | 128 | 159 |
| **BLAKE2b-256** | 256 | PRF | 91 | 106 | 88 | 102 |
| **BLAKE2s** | 256 | PRF | 100 | 117 | 97 | 114 |
| **BLAKE3** | 256 | PRF | 120 | 148 | 117 | 143 |
| **ChaCha20** | 256 | PRF | 109 | 129 | 103 | 126 |
| **Mixed** | 256 | PRF | 106 | 128 | 104 | 123 |

### ITB Triple 1024-bit (security: P × 2^(3×1024) = P × 2^3072)

| Hash | Width | Crypto | Encrypt | Decrypt | Encrypt + MAC | Decrypt + MAC |
|---|---|---|---|---|---|---|
| **Areion-SoEM-256** | 256 | PRF | 271 | 316 | 242 | 285 |
| **Areion-SoEM-512** | 512 | PRF | 282 | 338 | 248 | 314 |
| **SipHash-2-4** | 128 | PRF | 189 | 210 | 175 | 198 |
| **AES-CMAC** | 128 | PRF | 251 | 286 | 223 | 274 |
| **BLAKE2b-512** | 512 | PRF | 165 | 177 | 153 | 172 |
| **BLAKE2b-256** | 256 | PRF | 105 | 111 | 101 | 110 |
| **BLAKE2s** | 256 | PRF | 115 | 123 | 110 | 119 |
| **BLAKE3** | 256 | PRF | 143 | 155 | 136 | 144 |
| **ChaCha20** | 256 | PRF | 124 | 135 | 120 | 129 |
| **Mixed** | 256 | PRF | 125 | 133 | 116 | 130 |

## Intel Core i7-11700K (16 HT, native Linux, c-shared mode, LockSeed mode)

The dedicated lockSeed channel (`set_lock_seed(1)` / `ITB_LOCKSEED=1`)
auto-couples bit-soup + lock-soup on the on-direction. Numbers
below run with all three overlays active.

### ITB Single 1024-bit (security: P × 2^1024)

| Hash | Width | Crypto | Encrypt | Decrypt | Encrypt + MAC | Decrypt + MAC |
|---|---|---|---|---|---|---|
| **Areion-SoEM-256** | 256 | PRF | 59 | 71 | 61 | 70 |
| **Areion-SoEM-512** | 512 | PRF | 52 | 57 | 51 | 57 |
| **SipHash-2-4** | 128 | PRF | 69 | 76 | 67 | 73 |
| **AES-CMAC** | 128 | PRF | 75 | 86 | 74 | 85 |
| **BLAKE2b-512** | 512 | PRF | 47 | 51 | 47 | 50 |
| **BLAKE2b-256** | 256 | PRF | 43 | 46 | 42 | 46 |
| **BLAKE2s** | 256 | PRF | 45 | 48 | 44 | 47 |
| **BLAKE3** | 256 | PRF | 45 | 47 | 44 | 46 |
| **ChaCha20** | 256 | PRF | 46 | 49 | 45 | 48 |
| **Mixed** | 256 | PRF | 47 | 54 | 48 | 54 |

### ITB Triple 1024-bit (security: P × 2^(3×1024) = P × 2^3072)

| Hash | Width | Crypto | Encrypt | Decrypt | Encrypt + MAC | Decrypt + MAC |
|---|---|---|---|---|---|---|
| **Areion-SoEM-256** | 256 | PRF | 58 | 63 | 60 | 65 |
| **Areion-SoEM-512** | 512 | PRF | 53 | 54 | 52 | 54 |
| **SipHash-2-4** | 128 | PRF | 72 | 75 | 69 | 72 |
| **AES-CMAC** | 128 | PRF | 80 | 83 | 77 | 82 |
| **BLAKE2b-512** | 512 | PRF | 48 | 49 | 47 | 49 |
| **BLAKE2b-256** | 256 | PRF | 42 | 42 | 41 | 44 |
| **BLAKE2s** | 256 | PRF | 46 | 47 | 45 | 46 |
| **BLAKE3** | 256 | PRF | 44 | 46 | 44 | 46 |
| **ChaCha20** | 256 | PRF | 48 | 50 | 40 | 44 |
| **Mixed** | 256 | PRF | 48 | 52 | 48 | 51 |
