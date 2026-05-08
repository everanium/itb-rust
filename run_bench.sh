#!/usr/bin/env bash
#
# run_bench.sh -- canonical 4-pass bench runner for the Rust binding.
# Sequentially runs:
#
#   Pass 1: Single Ouroboros, ITB_LOCKSEED unset
#   Pass 2: Triple Ouroboros, ITB_LOCKSEED unset
#   Pass 3: Single Ouroboros, ITB_LOCKSEED=1
#   Pass 4: Triple Ouroboros, ITB_LOCKSEED=1
#
# The bench binaries are produced by `cargo bench` (custom harness,
# see Cargo.toml `harness = false` for `bench_single` / `bench_triple`).
# Each pass walks 40 cases and converges per case at the configured
# 5-second per-case budget; total wall-clock ~30-40 minutes.
#
# Environment variables forwarded to the bench binaries:
#   ITB_NONCE_BITS    nonce width (128 / 256 / 512; default 128)
#   ITB_BENCH_FILTER  substring match against bench-case names
#   ITB_BENCH_MIN_SEC per-case wall-clock budget (default 5.0)
#
# `ITB_LOCKSEED` is managed by this script per pass.
#
# Usage:
#   ./run_bench.sh                  # full 4-pass canonical sweep
#   ./run_bench.sh single           # pass 1 + pass 3 only
#   ./run_bench.sh triple           # pass 2 + pass 4 only
#   ./run_bench.sh --no-lockseed    # pass 1 + pass 2 only
#   ./run_bench.sh --lockseed-only  # pass 3 + pass 4 only

set -eu
set -o pipefail

cd "$(dirname "$0")"
REPO_ROOT="$(cd ../.. && pwd)"
DIST_DIR="$REPO_ROOT/dist/linux-amd64"

if [[ ! -f "$DIST_DIR/libitb.so" ]]; then
    echo "error: libitb.so not found at $DIST_DIR" >&2
    echo "       run ./build.sh first" >&2
    exit 1
fi

export LD_LIBRARY_PATH="$DIST_DIR${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"

run_single=1
run_triple=1
run_no_lockseed=1
run_with_lockseed=1
case "${1:-}" in
    single)            run_triple=0;;
    triple)            run_single=0;;
    --no-lockseed)     run_with_lockseed=0;;
    --lockseed-only)   run_no_lockseed=0;;
    -h|--help)         sed -n '3,30p' "$0"; exit 0;;
    "")                ;;
    *)                 echo "unknown option: $1" >&2; exit 2;;
esac

run_pass() {
    local label="$1"
    local bench="$2"
    local lockseed="$3"
    echo
    echo "===================================================================="
    echo "  $label"
    echo "===================================================================="
    if [[ "$lockseed" == "1" ]]; then
        ITB_LOCKSEED=1 cargo bench --bench "$bench"
    else
        unset ITB_LOCKSEED
        cargo bench --bench "$bench"
    fi
}

if [[ $run_no_lockseed -eq 1 && $run_single -eq 1 ]]; then
    run_pass "Pass 1 / 4 -- Single, ITB_LOCKSEED=off" bench_single 0
fi
if [[ $run_no_lockseed -eq 1 && $run_triple -eq 1 ]]; then
    run_pass "Pass 2 / 4 -- Triple, ITB_LOCKSEED=off" bench_triple 0
fi
if [[ $run_with_lockseed -eq 1 && $run_single -eq 1 ]]; then
    run_pass "Pass 3 / 4 -- Single, ITB_LOCKSEED=on" bench_single 1
fi
if [[ $run_with_lockseed -eq 1 && $run_triple -eq 1 ]]; then
    run_pass "Pass 4 / 4 -- Triple, ITB_LOCKSEED=on" bench_triple 1
fi

echo
echo "===================================================================="
echo "  bench passes complete -- update benches/BENCH.md by hand"
echo "===================================================================="
