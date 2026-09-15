#!/usr/bin/env bash
#
# run_bench.sh -- Criterion bench runner for the Rust binding.
# Builds libitb3.so + the crate via build.sh, points ITB_LIBITB3_PATH
# at the freshly-built shared library, then runs every bench binary
# (bench_message + bench_stream + bench_stream_one_shot). Positional
# arguments are forwarded to the Criterion harness
# (e.g. `./run_bench.sh --measurement-time 2`).

set -eu
set -o pipefail

cd "$(dirname "$0")"
REPO_ROOT="$(cd ../.. && pwd)"
DIST_DIR="$REPO_ROOT/dist/linux-amd64"

./build.sh

export ITB_LIBITB3_PATH="$DIST_DIR/libitb3.so"

# Bench-hostile Go runtime defaults are capped at libitb3 load time
# via env vars so a bench crash before the benches' own
# set_memory_limit / set_gc_percent calls still runs under a bounded
# heap. The benches themselves reassert these via the API for
# self-contained reproducibility.
export ITB_GOMEMLIMIT="${ITB_GOMEMLIMIT:-4GiB}"
export ITB_GOGC="${ITB_GOGC:-100}"

# Bench-shape defaults — match the root Go BENCH3.md pin so the
# throughput numbers are directly comparable to the shipped Go
# Encrypt3x{128,256,512}Cfg baseline. Override any of these before
# calling the script to change the shape.
export ITB_NONCE_BITS="${ITB_NONCE_BITS:-512}"
export ITB_KEY_BITS="${ITB_KEY_BITS:-1024}"
export ITB_WITH_PARALLAX="${ITB_WITH_PARALLAX:-false}"
export ITB_WITH_WRAPPER="${ITB_WITH_WRAPPER:-false}"
export ITB_INNER_HASH="${ITB_INNER_HASH:-areion512}"

# ITB_WITH_MAC=true derives MAC/AEAD profile counterparts. When
# ITB_PROFILE is set explicitly by the caller, it wins over the
# derivation and applies to both shapes (expert override).
: "${ITB_WITH_MAC:=false}"
if [ -n "${ITB_PROFILE:-}" ]; then
    ITB_MSG_PROFILE_DEFAULT="${ITB_PROFILE}"
    ITB_STREAM_PROFILE_DEFAULT="${ITB_PROFILE}"
elif [ "${ITB_WITH_MAC}" = "true" ]; then
    ITB_MSG_PROFILE_DEFAULT="singlemsg-triple-mac-v1"
    ITB_STREAM_PROFILE_DEFAULT="streaming-aead-triple-mac-v1"
else
    ITB_MSG_PROFILE_DEFAULT="singlemsg-triple-nomac-v1"
    ITB_STREAM_PROFILE_DEFAULT="streaming-noaead-triple-v1"
fi

export ITB_PROFILE="${ITB_MSG_PROFILE_DEFAULT}"
cargo bench --bench bench_message -- "$@"
export ITB_PROFILE="${ITB_STREAM_PROFILE_DEFAULT}"
cargo bench --bench bench_stream -- "$@"
cargo bench --bench bench_stream_one_shot -- "$@"
