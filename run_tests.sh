#!/usr/bin/env bash
#
# run_tests.sh -- one-step test runner for the Rust binding.
# Builds libitb3.so + the crate via build.sh, points ITB_LIBITB3_PATH
# at the freshly-built shared library, then invokes
# `cargo test --release`. Positional arguments are forwarded straight
# to cargo (e.g. `./run_tests.sh --test smoke` for one binary).

set -eu
set -o pipefail

cd "$(dirname "$0")"
REPO_ROOT="$(cd ../.. && pwd)"
DIST_DIR="$REPO_ROOT/dist/linux-amd64"

./build.sh

export ITB_LIBITB3_PATH="$DIST_DIR/libitb3.so"

exec cargo test --release "$@"
