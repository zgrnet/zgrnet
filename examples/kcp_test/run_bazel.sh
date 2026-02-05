#!/bin/bash
#
# KCP interop test runner for Bazel.
# This script is designed to be run via `bazel test //examples/kcp_test:interop_test`
#
# Tests all language pairs:
#   1. Go <-> Rust
#   2. Go <-> Zig
#   3. Rust <-> Zig
#

set -e

# Get the directory containing this script (for config files)
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# Find binaries - Bazel puts them in runfiles
# The paths are relative to the workspace root
GO_BIN="${SCRIPT_DIR}/examples/kcp_test/go/kcp_test_/kcp_test"
RUST_BIN="${SCRIPT_DIR}/examples/kcp_test/rust/kcp_test"
ZIG_BIN="${SCRIPT_DIR}/examples/kcp_test/zig/kcp_test"

# Alternative: use TEST_SRCDIR if available (Bazel test environment)
if [ -n "$TEST_SRCDIR" ]; then
    RUNFILES="$TEST_SRCDIR/_main"
    GO_BIN="$RUNFILES/examples/kcp_test/go/kcp_test_/kcp_test"
    RUST_BIN="$RUNFILES/examples/kcp_test/rust/kcp_test"
    ZIG_BIN="$RUNFILES/examples/kcp_test/zig/kcp_test"
    SCRIPT_DIR="$RUNFILES/examples/kcp_test"
fi

# Check binaries exist
for bin in "$GO_BIN" "$RUST_BIN" "$ZIG_BIN"; do
    if [ ! -x "$bin" ]; then
        echo "Binary not found: $bin"
        echo "SCRIPT_DIR=$SCRIPT_DIR"
        echo "TEST_SRCDIR=$TEST_SRCDIR"
        ls -la "$SCRIPT_DIR" || true
        exit 1
    fi
done

SIZE_MB=10  # Small size for CI
CONFIG_TEMPLATE="$SCRIPT_DIR/config.json"

echo "=== ZGRNet KCP Interop Test (Bazel) ==="
echo "Transfer size: ${SIZE_MB} MB per direction"
echo ""

# Create temp config
TEMP_DIR=$(mktemp -d)
trap "rm -rf $TEMP_DIR" EXIT

# Test results
RESULTS=""
PASS_COUNT=0
FAIL_COUNT=0

# Port counter for deterministic port allocation (avoids RANDOM flakiness)
PORT_COUNTER=0

get_next_ports() {
    PORT_COUNTER=$((PORT_COUNTER + 1))
    # Use deterministic ports: base + counter * 10 to avoid collisions
    # Opener: 10010, 10020, 10030, ...
    # Accepter: 11010, 11020, 11030, ...
    OPENER_PORT=$((10000 + PORT_COUNTER * 10))
    ACCEPTER_PORT=$((11000 + PORT_COUNTER * 10))
}

run_pair_test() {
    local opener=$1
    local accepter=$2
    local opener_bin=$3
    local accepter_bin=$4

    echo "Test: $opener <-> $accepter"

    # Get deterministic ports for this test pair
    get_next_ports

    # Create pair config
    local CONFIG="$TEMP_DIR/config_${opener}_${accepter}.json"
    cat > "$CONFIG" << EOF
{
  "hosts": [
    {"name": "${opener}", "private_key": "0000000000000000000000000000000000000000000000000000000000000001", "port": ${OPENER_PORT}, "role": "opener"},
    {"name": "${accepter}", "private_key": "0000000000000000000000000000000000000000000000000000000000000002", "port": ${ACCEPTER_PORT}, "role": "accepter"}
  ],
  "test": {
    "echo_message": "Hello KCP Interop!",
    "throughput_mb": ${SIZE_MB},
    "chunk_kb": 64
  }
}
EOF

    # Start accepter
    "$accepter_bin" --name "$accepter" --config "$CONFIG" > "$TEMP_DIR/${accepter}.log" 2>&1 &
    local PID_ACCEPTER=$!
    sleep 0.5

    # Start opener
    "$opener_bin" --name "$opener" --config "$CONFIG" > "$TEMP_DIR/${opener}.log" 2>&1 &
    local PID_OPENER=$!

    # Wait with timeout
    local TIMEOUT=60
    local START=$(date +%s)
    while kill -0 $PID_ACCEPTER 2>/dev/null || kill -0 $PID_OPENER 2>/dev/null; do
        local NOW=$(date +%s)
        if [ $((NOW - START)) -gt $TIMEOUT ]; then
            echo "  TIMEOUT"
            kill $PID_ACCEPTER $PID_OPENER 2>/dev/null || true
            FAIL_COUNT=$((FAIL_COUNT + 1))
            RESULTS="${RESULTS}${opener}-${accepter}: TIMEOUT\n"
            return
        fi
        sleep 1
    done

    wait $PID_ACCEPTER
    local ACCEPTER_EXIT=$?
    wait $PID_OPENER
    local OPENER_EXIT=$?

    if [ $ACCEPTER_EXIT -eq 0 ] && [ $OPENER_EXIT -eq 0 ]; then
        echo "  PASS"
        PASS_COUNT=$((PASS_COUNT + 1))
        RESULTS="${RESULTS}${opener}-${accepter}: PASS\n"
    else
        echo "  FAIL (opener: $OPENER_EXIT, accepter: $ACCEPTER_EXIT)"
        echo "  Opener log:"
        tail -10 "$TEMP_DIR/${opener}.log" 2>/dev/null || echo "    (no log)"
        echo "  Accepter log:"
        tail -10 "$TEMP_DIR/${accepter}.log" 2>/dev/null || echo "    (no log)"
        FAIL_COUNT=$((FAIL_COUNT + 1))
        RESULTS="${RESULTS}${opener}-${accepter}: FAIL\n"
    fi
}

echo "Running pair tests..."
echo ""

run_pair_test "go" "rust" "$GO_BIN" "$RUST_BIN"
run_pair_test "go" "zig" "$GO_BIN" "$ZIG_BIN"
run_pair_test "rust" "zig" "$RUST_BIN" "$ZIG_BIN"

echo ""
echo "=== Results ==="
echo -e "$RESULTS"
echo "Passed: $PASS_COUNT/3"
echo "Failed: $FAIL_COUNT/3"

if [ $FAIL_COUNT -gt 0 ]; then
    exit 1
fi

echo ""
echo "=== All tests passed! ==="
