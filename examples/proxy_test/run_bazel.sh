#!/bin/bash
#
# Cross-language proxy interop test runner for Bazel.
#
# Tests TCP_PROXY(69) KCP stream handling between Go, Rust, and Zig.
# Each pair: one "handler" (echo server + TCP_PROXY handler) and one "proxy"
# (opens KCP stream, sends data, verifies echo).
#
# Usage:
#   bazel test //examples/proxy_test:interop_test
#

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# Find binaries in Bazel runfiles
GO_BIN="${SCRIPT_DIR}/examples/proxy_test/go/proxy_test_/proxy_test"
RUST_BIN="${SCRIPT_DIR}/examples/proxy_test/rust/proxy_test"
ZIG_BIN="${SCRIPT_DIR}/zig/proxy_test"

if [ -n "$TEST_SRCDIR" ]; then
    RUNFILES="$TEST_SRCDIR/_main"
    GO_BIN="$RUNFILES/examples/proxy_test/go/proxy_test_/proxy_test"
    RUST_BIN="$RUNFILES/examples/proxy_test/rust/proxy_test"
    ZIG_BIN="$RUNFILES/zig/proxy_test"
    SCRIPT_DIR="$RUNFILES/examples/proxy_test"
fi

# Check binaries
for bin in "$GO_BIN" "$RUST_BIN"; do
    if [ ! -x "$bin" ]; then
        echo "Binary not found: $bin"
        echo "TEST_SRCDIR=$TEST_SRCDIR"
        exit 1
    fi
done

# ZIG binary may not exist if Zig build is disabled
HAS_ZIG=false
if [ -x "$ZIG_BIN" ]; then
    HAS_ZIG=true
fi

TEMP_DIR=$(mktemp -d)
trap "rm -rf $TEMP_DIR" EXIT

echo "=== ZGRNet Proxy Cross-Language Interop Test ==="
echo ""

RESULTS=""
PASS_COUNT=0
FAIL_COUNT=0
PORT_COUNTER=0

get_ports() {
    PORT_COUNTER=$((PORT_COUNTER + 1))
    HANDLER_PORT=$((20000 + PORT_COUNTER * 10))
    PROXY_PORT=$((21000 + PORT_COUNTER * 10))
    ECHO_PORT=$((22000 + PORT_COUNTER * 10))
}

run_pair() {
    local handler_lang=$1
    local proxy_lang=$2
    local handler_bin=$3
    local proxy_bin=$4

    echo "Test: $proxy_lang proxy → $handler_lang handler"

    get_ports

    # Create config for this pair
    local CONFIG="$TEMP_DIR/config_${handler_lang}_${proxy_lang}.json"
    cat > "$CONFIG" << EOF
{
  "hosts": [
    {"name": "handler", "private_key": "0000000000000000000000000000000000000000000000000000000000000001", "port": ${HANDLER_PORT}, "role": "handler"},
    {"name": "proxy", "private_key": "0000000000000000000000000000000000000000000000000000000000000002", "port": ${PROXY_PORT}, "role": "proxy"}
  ],
  "echo_port": ${ECHO_PORT},
  "test": {"message": "cross-lang proxy test ${proxy_lang}->${handler_lang}!"}
}
EOF

    # Start handler
    "$handler_bin" --name handler --config "$CONFIG" > "$TEMP_DIR/${handler_lang}_handler.log" 2>&1 &
    local PID_HANDLER=$!
    sleep 0.5

    # Start proxy (runs test internally, exits when done)
    "$proxy_bin" --name proxy --config "$CONFIG" > "$TEMP_DIR/${proxy_lang}_proxy.log" 2>&1 &
    local PID_PROXY=$!

    # Wait with timeout
    local TIMEOUT=30
    local START=$(date +%s)
    local PROXY_DONE=false
    while true; do
        if ! kill -0 $PID_PROXY 2>/dev/null; then
            PROXY_DONE=true
            break
        fi
        local NOW=$(date +%s)
        if [ $((NOW - START)) -gt $TIMEOUT ]; then
            break
        fi
        sleep 0.5
    done

    # Get proxy exit code
    local PROXY_EXIT=1
    if $PROXY_DONE; then
        wait $PID_PROXY
        PROXY_EXIT=$?
    else
        echo "  TIMEOUT"
        kill $PID_PROXY 2>/dev/null || true
    fi

    # Kill handler
    kill $PID_HANDLER 2>/dev/null || true
    wait $PID_HANDLER 2>/dev/null || true

    if [ $PROXY_EXIT -eq 0 ]; then
        echo "  PASS"
        PASS_COUNT=$((PASS_COUNT + 1))
        RESULTS="${RESULTS}${proxy_lang} → ${handler_lang}: PASS\n"
    else
        echo "  FAIL (exit: $PROXY_EXIT)"
        echo "  --- Handler log ---"
        tail -5 "$TEMP_DIR/${handler_lang}_handler.log" 2>/dev/null || echo "    (no log)"
        echo "  --- Proxy log ---"
        tail -5 "$TEMP_DIR/${proxy_lang}_proxy.log" 2>/dev/null || echo "    (no log)"
        FAIL_COUNT=$((FAIL_COUNT + 1))
        RESULTS="${RESULTS}${proxy_lang} → ${handler_lang}: FAIL\n"
    fi
}

# Run all pairs (handler × proxy)
TOTAL=0

# Go ↔ Go
run_pair "go" "go" "$GO_BIN" "$GO_BIN"
TOTAL=$((TOTAL + 1))

# Go ↔ Rust
run_pair "go" "rust" "$GO_BIN" "$RUST_BIN"
TOTAL=$((TOTAL + 1))

# Rust ↔ Go
run_pair "rust" "go" "$RUST_BIN" "$GO_BIN"
TOTAL=$((TOTAL + 1))

# Rust ↔ Rust
run_pair "rust" "rust" "$RUST_BIN" "$RUST_BIN"
TOTAL=$((TOTAL + 1))

if $HAS_ZIG; then
    run_pair "go" "zig" "$GO_BIN" "$ZIG_BIN"
    TOTAL=$((TOTAL + 1))
    run_pair "zig" "go" "$ZIG_BIN" "$GO_BIN"
    TOTAL=$((TOTAL + 1))
    run_pair "rust" "zig" "$RUST_BIN" "$ZIG_BIN"
    TOTAL=$((TOTAL + 1))
    run_pair "zig" "rust" "$ZIG_BIN" "$RUST_BIN"
    TOTAL=$((TOTAL + 1))
    run_pair "zig" "zig" "$ZIG_BIN" "$ZIG_BIN"
    TOTAL=$((TOTAL + 1))
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
echo "=== All proxy interop tests passed! ==="
