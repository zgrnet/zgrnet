#!/bin/bash
#
# Cross-language Host communication test.
#
# Runs 3 Go hosts by default, but can be configured to run
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

echo "=== ZGRNet Cross-Language Host Test ==="
echo ""
echo "Building Go host..."
cd "$GO_DIR"
go build -o "$SCRIPT_DIR/host_go" ./examples/host_test

echo ""
echo "Starting 3 hosts (go, rust, zig identities)..."
echo "Config: $CONFIG"
echo ""

# Cleanup function
cleanup() {
    echo ""
    echo "Shutting down..."
    kill $PID_GO $PID_RUST $PID_ZIG 2>/dev/null || true
    rm -f "$SCRIPT_DIR/host_go"
}
trap cleanup EXIT

# Start hosts
cd "$SCRIPT_DIR"

echo "--- Starting 'go' host on port 10001 ---"
./host_go -name go -config "$CONFIG" &
PID_GO=$!

sleep 0.5

echo "--- Starting 'rust' host on port 10002 ---"
./host_go -name rust -config "$CONFIG" &
PID_RUST=$!

sleep 0.5

echo "--- Starting 'zig' host on port 10003 ---"
./host_go -name zig -config "$CONFIG" &
PID_ZIG=$!

echo ""
echo "=== All hosts started ==="
echo "Press Ctrl+C to stop"
echo ""

# Wait for any host to exit
wait
