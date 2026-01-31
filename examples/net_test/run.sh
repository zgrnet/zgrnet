#!/bin/bash
#
# Cross-language net.UDP communication test.
#
# Runs Go, Rust, and Zig UDP implementations for true cross-language testing.
#
# Usage:
#   ./run.sh
#

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
GO_DIR="$ROOT_DIR/go"
RUST_DIR="$ROOT_DIR/rust"
ZIG_DIR="$ROOT_DIR/zig"
CONFIG="$SCRIPT_DIR/config.json"

echo "=== ZGRNet Cross-Language net.UDP Test ==="
echo ""

# Build Go
echo "Building Go net_test..."
cd "$GO_DIR"
go build -o "$SCRIPT_DIR/net_go" ./examples/net_test

# Build Rust (use bazel if cargo not available)
echo "Building Rust host_test..."
cd "$ROOT_DIR"
if command -v cargo &> /dev/null; then
    cd "$RUST_DIR"
    cargo build --example host_test --release 2>/dev/null || cargo build --example host_test
    cp target/release/examples/host_test "$SCRIPT_DIR/net_rust" 2>/dev/null || \
    cp target/debug/examples/host_test "$SCRIPT_DIR/net_rust"
else
    echo "  (cargo not found, skipping Rust build - will use Go for rust identity)"
    # Create a symlink so script doesn't break
    RUST_AVAILABLE=false
fi

# Build Zig
echo "Building Zig host_test..."
cd "$ZIG_DIR"
zig build -Doptimize=ReleaseFast 2>/dev/null || zig build
cp zig-out/bin/host_test "$SCRIPT_DIR/net_zig" 2>/dev/null || \
  echo "Warning: Zig host_test not found in zig-out/bin/"

echo ""
echo "Starting 3 UDP instances (Go, Rust, Zig)..."
echo "Config: $CONFIG"
echo ""

# Cleanup function
cleanup() {
    echo ""
    echo "Shutting down..."
    kill $PID_GO $PID_RUST $PID_ZIG 2>/dev/null || true
    rm -f "$SCRIPT_DIR/net_go" "$SCRIPT_DIR/net_rust" "$SCRIPT_DIR/net_zig"
}
trap cleanup EXIT

# Start UDP instances
cd "$SCRIPT_DIR"

echo "--- Starting Go on port 10001 ---"
./net_go -name go -config "$CONFIG" &
PID_GO=$!

sleep 0.5

echo "--- Starting Rust on port 10002 ---"
if [ -f ./net_rust ]; then
    CONFIG_PATH="$CONFIG" ./net_rust --name rust &
    PID_RUST=$!
else
    # Fallback to Go binary with rust identity
    ./net_go -name rust -config "$CONFIG" &
    PID_RUST=$!
fi

sleep 0.5

echo "--- Starting Zig on port 10003 ---"
./net_zig --name zig --config "$CONFIG" &
PID_ZIG=$!

echo ""
echo "=== All instances started (Go + Rust + Zig) ==="
echo "Press Ctrl+C to stop"
echo ""

# Wait for any instance to exit
wait
