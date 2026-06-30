#!/usr/bin/env bash
# Build the netflow VGI worker, (re)generate the golden datagram fixtures, and
# run the SQLLogic E2E suite against the worker using the haybarn DuckDB
# distribution's unittest runner (which ships the `vgi` extension via community).
#
# Prerequisites (one-time):
#   uv tool install haybarn-unittest                       # the DuckDB unittest binary
#   echo "INSTALL vgi FROM community;" | uvx haybarn-cli   # install the vgi extension
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$REPO_ROOT"

UNITTEST="${VGI_UNITTEST:-$(command -v haybarn-unittest || true)}"
if [[ -z "$UNITTEST" || ! -x "$UNITTEST" ]]; then
    echo "ERROR: haybarn-unittest not found. Install it with:" >&2
    echo "       uv tool install haybarn-unittest" >&2
    exit 1
fi

echo "==> Regenerating golden datagram fixtures (test/data/*.dat)"
cargo run -q -p netflow-core --example gen_fixtures -- test/data

echo "==> Building netflow-worker (release)"
cargo build --release --bin netflow-worker

WORKER="$REPO_ROOT/target/release/netflow-worker"
# Catch2 test-name filter (trailing `*` only), not a shell glob.
TEST_GLOB="${1:-test/sql/*}"

echo "==> Running SQLLogic E2E"
echo "    worker:   $WORKER"
echo "    unittest: $UNITTEST"
echo "    tests:    $TEST_GLOB"

VGI_NETFLOW_WORKER="$WORKER" \
VGI_WORKER_CATALOG_NAME="netflow" \
    "$UNITTEST" --test-dir "$REPO_ROOT" "$TEST_GLOB"
