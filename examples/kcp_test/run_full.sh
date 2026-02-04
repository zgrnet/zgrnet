#!/bin/bash
#
# Full 3-way KCP stream interoperability test.
#
# Tests all language pairs:
#   1. Go <-> Rust
#   2. Go <-> Zig
#   3. Rust <-> Zig
#
# Usage:
#   ./run_full.sh [--size-mb <MB>]
#

set -e

# Parse arguments
SIZE_MB=100  # Default smaller for quick tests
while [[ $# -gt 0 ]]; do
    case $1 in
        --size-mb)
            SIZE_MB="$2"
            shift 2
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Check for required dependencies
if ! command -v jq &> /dev/null; then
    echo "Error: jq is not installed. Please install it to run this script." >&2
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
# Each language example is now in its own subdirectory under examples/kcp_test/
GO_DIR="$SCRIPT_DIR/go"
RUST_DIR="$SCRIPT_DIR/rust"
ZIG_DIR="$SCRIPT_DIR/zig"

echo "=== ZGRNet Full 3-Way KCP Interop Test ==="
echo "Transfer size: ${SIZE_MB} MB per direction per pair"
echo ""

# Create temp config with specified size
TEMP_CONFIG="$SCRIPT_DIR/config_temp.json"
cat > "$TEMP_CONFIG" << EOF
{
  "hosts": [
    {"name": "go", "private_key": "0000000000000000000000000000000000000000000000000000000000000001", "port": 10001, "role": "opener"},
    {"name": "rust", "private_key": "0000000000000000000000000000000000000000000000000000000000000002", "port": 10002, "role": "accepter"},
    {"name": "zig", "private_key": "0000000000000000000000000000000000000000000000000000000000000003", "port": 10003, "role": "accepter"}
  ],
  "test": {
    "echo_message": "Hello KCP Interop!",
    "throughput_mb": ${SIZE_MB},
    "chunk_kb": 64
  }
}
EOF

# Build all implementations
echo "=== Building all implementations ==="

echo "Building Go kcp_test..."
cd "$GO_DIR"
go build -o "$SCRIPT_DIR/kcp_go" . || {
    echo "Note: Go kcp_test not found, skipping Go"
    touch "$SCRIPT_DIR/kcp_go_skip"
}

echo "Building Rust kcp_test..."
cd "$RUST_DIR"
cargo build --release || cargo build
if [ -f target/release/kcp_test ]; then
    cp target/release/kcp_test "$SCRIPT_DIR/kcp_rust"
elif [ -f target/debug/kcp_test ]; then
    cp target/debug/kcp_test "$SCRIPT_DIR/kcp_rust"
else
    echo "Note: Rust kcp_test not found, skipping Rust"
    touch "$SCRIPT_DIR/kcp_rust_skip"
fi

echo "Building Zig kcp_test..."
cd "$ZIG_DIR"
zig build -Doptimize=ReleaseFast || zig build
if [ -f zig-out/bin/kcp_test ]; then
    cp zig-out/bin/kcp_test "$SCRIPT_DIR/kcp_zig"
else
    echo "Note: Zig kcp_test not found, skipping Zig"
    touch "$SCRIPT_DIR/kcp_zig_skip"
fi

echo ""

# Cleanup function
cleanup() {
    echo ""
    echo "Cleaning up..."
    pkill -f "kcp_go" 2>/dev/null || true
    pkill -f "kcp_rust" 2>/dev/null || true
    pkill -f "kcp_zig" 2>/dev/null || true
    rm -f "$SCRIPT_DIR/kcp_go" "$SCRIPT_DIR/kcp_rust" "$SCRIPT_DIR/kcp_zig"
    rm -f "$SCRIPT_DIR/kcp_go_skip" "$SCRIPT_DIR/kcp_rust_skip" "$SCRIPT_DIR/kcp_zig_skip"
    rm -f "$TEMP_CONFIG"
}
trap cleanup EXIT

cd "$SCRIPT_DIR"

# Track results
RESULTS=""
TOTAL_TIME=0
TOTAL_BYTES=0
TEST_COUNT=0

run_pair_test() {
    local opener=$1
    local accepter=$2
    local opener_bin="kcp_${opener}"
    local accepter_bin="kcp_${accepter}"

    # Check if binaries exist
    if [ -f "${opener}_skip" ] || [ -f "${accepter}_skip" ]; then
        echo "  Skipping (missing binary)"
        return
    fi
    if [ ! -f "$opener_bin" ] || [ ! -f "$accepter_bin" ]; then
        echo "  Skipping (missing binary)"
        return
    fi

    echo "  Running ${opener} <-> ${accepter}..."

    # Create pair-specific config
    local PAIR_CONFIG="$SCRIPT_DIR/config_${opener}_${accepter}.json"
    cat > "$PAIR_CONFIG" << EOF
{
  "hosts": [
    {"name": "${opener}", "private_key": "$(jq -r ".hosts[] | select(.name==\"${opener}\") | .private_key" "$TEMP_CONFIG")", "port": $(jq -r ".hosts[] | select(.name==\"${opener}\") | .port" "$TEMP_CONFIG"), "role": "opener"},
    {"name": "${accepter}", "private_key": "$(jq -r ".hosts[] | select(.name==\"${accepter}\") | .private_key" "$TEMP_CONFIG")", "port": $(jq -r ".hosts[] | select(.name==\"${accepter}\") | .port" "$TEMP_CONFIG"), "role": "accepter"}
  ],
  "test": $(jq '.test' "$TEMP_CONFIG")
}
EOF

    local START_TIME=$(date +%s.%N)

    # Start accepter first
    if [ "$accepter" = "go" ]; then
        ./$accepter_bin -name $accepter -config "$PAIR_CONFIG" > /tmp/kcp_${accepter}.log 2>&1 &
    else
        ./$accepter_bin --name $accepter --config "$PAIR_CONFIG" > /tmp/kcp_${accepter}.log 2>&1 &
    fi
    local PID_ACCEPTER=$!
    sleep 0.5

    # Start opener
    if [ "$opener" = "go" ]; then
        ./$opener_bin -name $opener -config "$PAIR_CONFIG" > /tmp/kcp_${opener}.log 2>&1 &
    else
        ./$opener_bin --name $opener --config "$PAIR_CONFIG" > /tmp/kcp_${opener}.log 2>&1 &
    fi
    local PID_OPENER=$!

    # Wait for both
    wait $PID_ACCEPTER 2>/dev/null
    local ACCEPTER_EXIT=$?
    wait $PID_OPENER 2>/dev/null
    local OPENER_EXIT=$?

    local END_TIME=$(date +%s.%N)
    local ELAPSED=$(echo "$END_TIME - $START_TIME" | bc)

    rm -f "$PAIR_CONFIG"

    if [ $ACCEPTER_EXIT -eq 0 ] && [ $OPENER_EXIT -eq 0 ]; then
        local BYTES=$((SIZE_MB * 1024 * 1024 * 2))  # Bidirectional
        local THROUGHPUT=$(echo "scale=2; $BYTES / $ELAPSED / 1024 / 1024" | bc)
        echo "    PASS - ${ELAPSED}s, ${THROUGHPUT} MB/s"
        TOTAL_TIME=$(echo "$TOTAL_TIME + $ELAPSED" | bc)
        TOTAL_BYTES=$((TOTAL_BYTES + BYTES))
        TEST_COUNT=$((TEST_COUNT + 1))
        RESULTS="${RESULTS}${opener}-${accepter}: ${THROUGHPUT} MB/s\n"
    else
        echo "    FAIL (opener: $OPENER_EXIT, accepter: $ACCEPTER_EXIT)"
        echo "    Opener log: $(tail -5 /tmp/kcp_${opener}.log 2>/dev/null || echo 'no log')"
        echo "    Accepter log: $(tail -5 /tmp/kcp_${accepter}.log 2>/dev/null || echo 'no log')"
        RESULTS="${RESULTS}${opener}-${accepter}: FAILED\n"
    fi
}

echo "=== Running pair tests ==="
echo ""

echo "Test 1/3: Go <-> Rust"
run_pair_test "go" "rust"

echo "Test 2/3: Go <-> Zig"
run_pair_test "go" "zig"

echo "Test 3/3: Rust <-> Zig"
run_pair_test "rust" "zig"

echo ""
echo "=== Results Summary ==="
echo ""
echo -e "$RESULTS"

if [ $TEST_COUNT -gt 0 ]; then
    AVG_THROUGHPUT=$(echo "scale=2; $TOTAL_BYTES / $TOTAL_TIME / 1024 / 1024" | bc)
    echo "Total tests passed: $TEST_COUNT/3"
    echo "Total time: ${TOTAL_TIME}s"
    echo "Total transferred: $((TOTAL_BYTES / 1024 / 1024)) MB"
    echo "Average throughput: ${AVG_THROUGHPUT} MB/s"
else
    echo "No tests completed successfully"
    exit 1
fi

echo ""
echo "=== Full 3-Way Test Complete ==="
