#!/bin/bash
#
# Node SDK interop test runner for Bazel.
# Tests all language pairs via Node API (Dial + AcceptStream + echo).
#
# bazel test //examples/node_test:interop_test
#

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

GO_BIN="${SCRIPT_DIR}/examples/node_test/go/node_test_/node_test"
RUST_BIN="${SCRIPT_DIR}/examples/node_test/rust/node_test"
ZIG_BIN="${SCRIPT_DIR}/examples/node_test/zig/node_test"

if [ -n "$TEST_SRCDIR" ]; then
    RUNFILES="$TEST_SRCDIR/_main"
    GO_BIN="$RUNFILES/examples/node_test/go/node_test_/node_test"
    RUST_BIN="$RUNFILES/examples/node_test/rust/node_test"
    ZIG_BIN="$RUNFILES/examples/node_test/zig/node_test"
    SCRIPT_DIR="$RUNFILES/examples/node_test"
fi

for bin in "$GO_BIN" "$RUST_BIN"; do
    if [ ! -x "$bin" ]; then
        echo "Binary not found: $bin"
        exit 1
    fi
done

CONFIG_TEMPLATE="$SCRIPT_DIR/config.json"
TEMP_DIR=$(mktemp -d)
trap "rm -rf $TEMP_DIR" EXIT

RESULTS=""
PASS_COUNT=0
FAIL_COUNT=0
PORT_COUNTER=0

get_next_ports() {
    PORT_COUNTER=$((PORT_COUNTER + 1))
    OPENER_PORT=$((20000 + PORT_COUNTER * 10))
    ACCEPTER_PORT=$((21000 + PORT_COUNTER * 10))
}

run_pair_test() {
    local opener=$1
    local accepter=$2
    local opener_bin=$3
    local accepter_bin=$4

    echo "Test: $opener <-> $accepter"

    get_next_ports

    local CONFIG="$TEMP_DIR/config_${opener}_${accepter}.json"
    cat > "$CONFIG" << EOF
{
  "hosts": [
    {"name": "${opener}", "private_key": "0000000000000000000000000000000000000000000000000000000000000001", "port": ${OPENER_PORT}, "role": "opener"},
    {"name": "${accepter}", "private_key": "0000000000000000000000000000000000000000000000000000000000000002", "port": ${ACCEPTER_PORT}, "role": "accepter"}
  ],
  "test": {
    "echo_message": "Hello Node Interop!"
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
    local TIMEOUT=30
    local START=$(date +%s)
    while kill -0 $PID_ACCEPTER 2>/dev/null || kill -0 $PID_OPENER 2>/dev/null; do
        local NOW=$(date +%s)
        if [ $((NOW - START)) -gt $TIMEOUT ]; then
            echo "  TIMEOUT"
            kill $PID_ACCEPTER $PID_OPENER 2>/dev/null || true
            wait $PID_ACCEPTER 2>/dev/null || true
            wait $PID_OPENER 2>/dev/null || true
            echo "  Opener log:"
            tail -5 "$TEMP_DIR/${opener}.log" 2>/dev/null || echo "    (no log)"
            echo "  Accepter log:"
            tail -5 "$TEMP_DIR/${accepter}.log" 2>/dev/null || echo "    (no log)"
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

echo "=== ZGRNet Node SDK Interop Test ==="
echo ""

TOTAL=2
run_pair_test "go" "rust" "$GO_BIN" "$RUST_BIN"

# Zig binary may not be available on all platforms
if [ -x "$ZIG_BIN" ]; then
    TOTAL=3
    run_pair_test "go" "zig" "$GO_BIN" "$ZIG_BIN"
fi

echo ""
echo "=== Results ==="
echo -e "$RESULTS"
echo "Passed: $PASS_COUNT/$TOTAL"
echo "Failed: $FAIL_COUNT/$TOTAL"

if [ $FAIL_COUNT -gt 0 ]; then
    exit 1
fi

echo ""
echo "=== All tests passed! ==="
