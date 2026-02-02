#!/bin/bash
#
# Cross-language KCP stream interoperability test.
#
# Runs Go and Rust KCP implementations to verify cross-language compatibility.
#
# Usage:
#   ./run.sh
#

set -e

# Check for required dependencies
if ! command -v jq &> /dev/null; then
    echo "Error: jq is not installed. Please install it to run this script." >&2
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
GO_DIR="$ROOT_DIR/go"
RUST_DIR="$ROOT_DIR/rust"
CONFIG="$SCRIPT_DIR/config.json"

echo "=== ZGRNet KCP Cross-Language Interop Test ==="
echo ""

# Build Go
echo "Building Go kcp_test..."
cd "$GO_DIR"
go build -o "$SCRIPT_DIR/kcp_go" ./examples/kcp_test

# Build Rust
echo "Building Rust kcp_interop..."
cd "$RUST_DIR"
cargo build --example kcp_interop --release 2>/dev/null || cargo build --example kcp_interop
cp target/release/examples/kcp_interop "$SCRIPT_DIR/kcp_rust" 2>/dev/null || \
cp target/debug/examples/kcp_interop "$SCRIPT_DIR/kcp_rust"

echo ""
echo "Starting KCP interop test (Go opener + Rust accepter)..."
echo "Config: $CONFIG"
echo ""

# Cleanup function
cleanup() {
    echo ""
    echo "Cleaning up..."
    kill $PID_GO $PID_RUST 2>/dev/null || true
    rm -f "$SCRIPT_DIR/kcp_go" "$SCRIPT_DIR/kcp_rust"
}
trap cleanup EXIT

# Start instances
cd "$SCRIPT_DIR"

# Read roles from config using jq
GO_ROLE=$(jq -r '.hosts[] | select(.name=="go") | .role' "$CONFIG")
RUST_ROLE=$(jq -r '.hosts[] | select(.name=="rust") | .role' "$CONFIG")

echo "Go role: $GO_ROLE, Rust role: $RUST_ROLE"

# Start accepter first, then opener
if [ "$GO_ROLE" = "accepter" ]; then
    echo "--- Starting Go (accepter) on port 10001 ---"
    ./kcp_go -name go -config "$CONFIG" &
    PID_GO=$!
    sleep 0.5
    echo "--- Starting Rust (opener) on port 10002 ---"
    ./kcp_rust --name rust --config "$CONFIG" &
    PID_RUST=$!
else
    echo "--- Starting Rust (accepter) on port 10002 ---"
    ./kcp_rust --name rust --config "$CONFIG" &
    PID_RUST=$!
    sleep 0.5
    echo "--- Starting Go (opener) on port 10001 ---"
    ./kcp_go -name go -config "$CONFIG" &
    PID_GO=$!
fi

echo ""
echo "=== Test running... ==="
echo ""

# Wait for both to complete
wait $PID_GO
GO_EXIT=$?
wait $PID_RUST
RUST_EXIT=$?

echo ""
if [ $GO_EXIT -eq 0 ] && [ $RUST_EXIT -eq 0 ]; then
    echo "=== KCP Interop Test PASSED ==="
else
    echo "=== KCP Interop Test FAILED ==="
    echo "Go exit code: $GO_EXIT"
    echo "Rust exit code: $RUST_EXIT"
    exit 1
fi
