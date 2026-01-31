#!/bin/bash
#
# Cross-language net.UDP communication test.
#
# Runs 3 Go UDP instances by default, but can be configured to run
# the Go, Rust, and Zig implementations for cross-language testing.
#
# Usage:
#   ./run.sh
#

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
GO_DIR="$ROOT_DIR/go"
CONFIG="$SCRIPT_DIR/config.json"

echo "=== ZGRNet Cross-Language net.UDP Test ==="
echo ""
echo "Building Go net_test..."
cd "$GO_DIR"
go build -o "$SCRIPT_DIR/net_go" ./examples/net_test

echo ""
echo "Starting 3 UDP instances (go, rust, zig identities)..."
echo "Config: $CONFIG"
echo ""

# Cleanup function
cleanup() {
    echo ""
    echo "Shutting down..."
    kill $PID_GO $PID_RUST $PID_ZIG 2>/dev/null || true
    rm -f "$SCRIPT_DIR/net_go"
}
trap cleanup EXIT

# Start UDP instances
cd "$SCRIPT_DIR"

echo "--- Starting 'go' on port 10001 ---"
./net_go -name go -config "$CONFIG" &
PID_GO=$!

sleep 0.5

echo "--- Starting 'rust' on port 10002 ---"
./net_go -name rust -config "$CONFIG" &
PID_RUST=$!

sleep 0.5

echo "--- Starting 'zig' on port 10003 ---"
./net_go -name zig -config "$CONFIG" &
PID_ZIG=$!

echo ""
echo "=== All instances started ==="
echo "Press Ctrl+C to stop"
echo ""

# Wait for any instance to exit
wait
