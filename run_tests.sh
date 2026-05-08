#!/usr/bin/env bash
#
# run_tests.sh -- one-step test runner for the Rust binding.
# Verifies libitb.so is present, sets LD_LIBRARY_PATH, then invokes
# `cargo test --release`. Forwards any positional arguments through
# to cargo (e.g. `--test test_blake3` for one binary).
#
# Usage:
#   ./run_tests.sh                          # all tests
#   ./run_tests.sh --test test_blake3       # one test binary
#   ./run_tests.sh --test test_blob -- -q   # quieter output for one binary

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

exec cargo test --release "$@"
