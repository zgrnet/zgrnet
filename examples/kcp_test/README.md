# ZGRNet KCP Cross-Language Interop Test

This example tests KCP stream multiplexing interoperability between Go and Rust implementations.

## Status

| Language | Status | Notes |
|----------|--------|-------|
| Go | Complete | Full KCP stream support |
| Rust | Complete | Full KCP stream support |
| Zig | Pending | Placeholder in config |

## Quick Start

Run the interop test:

```bash
./run.sh
```

## Configuration

The `config.json` file defines test hosts with deterministic keys:

```json
{
  "hosts": [
    {"name": "go",   "role": "opener",   "port": 10001},
    {"name": "rust", "role": "accepter", "port": 10002},
    {"name": "zig",  "role": "accepter", "port": 10003}
  ],
  "test": {
    "echo_message": "Hello KCP Interop!",
    "throughput_mb": 1,
    "chunk_kb": 32
  }
}
```

## What It Tests

1. **Noise Handshake**: Cross-language IK pattern handshake
2. **KCP Stream Open/Accept**: Go opens stream, Rust accepts
3. **Bidirectional Data**: Echo test verifies data integrity
4. **Throughput**: Bidirectional 1GB transfer (~95 MB/s)

## Test Flow

```
Go (opener)                    Rust (accepter)
    |                               |
    |------ Noise Handshake ------->|
    |                               |
    |--- OpenStream (SYN) --------->|
    |<-- AcceptStream (ACK) --------|
    |                               |
    |--- Echo message ------------->|
    |<-- Echo response -------------|
    |                               |
    |=== Bidirectional 1GB Test ====|
    |--- TX: 1GB data ------------->|
    |<-- TX: 1GB data --------------|
    |       (simultaneous)          |
    |                               |
    [Both exit with success]
```

## Sample Output

```
=== ZGRNet KCP Cross-Language Interop Test ===

Building Go kcp_test...
Building Rust kcp_interop...

Starting KCP interop test (Go opener + Rust accepter)...

--- Starting Rust (accepter) on port 10002 ---
[rust] Public key: ad8c48c2...
[rust] Role: accepter
[rust] Listening on 0.0.0.0:10002

--- Starting Go (opener) on port 10001 ---
[go] Public key: fd3384e1...
[go] Role: opener
[go] Connecting to rust...
[go] Connected to rust!
[opener] Opened stream 2
[opener] Running echo test...
[accepter] Accepted stream 2
[accepter] Received echo: "Hello KCP Interop!"
[opener] Received echo response: "Echo from accepter: Hello KCP Interop!"
[opener] Starting bidirectional test: 1024 MB each direction, 64 KB chunks
[accepter] Starting bidirectional test: 1024 MB each direction, 64 KB chunks
[opener] TX complete: 1073741824 bytes
[accepter] TX complete: 1073741824 bytes
[accepter] RX complete: 1073741824 bytes
[accepter] ========== Bidirectional Results ==========
[accepter] Sent:       1073741824 bytes (1.00 GB)
[accepter] Received:   1073741824 bytes (1.00 GB)
[accepter] Total:      2147483648 bytes (2.00 GB)
[accepter] Time:       21.5s
[accepter] Throughput: 95.24 MB/s (bidirectional)
[accepter] ============================================
[opener] RX complete: 1073741824 bytes
[opener] ========== Bidirectional Results ==========
[opener] Sent:       1073741824 bytes (1.00 GB)
[opener] Received:   1073741824 bytes (1.00 GB)
[opener] Total:      2147483648 bytes (2.00 GB)
[opener] Time:       22.5s
[opener] Throughput: 91.02 MB/s (bidirectional)
[opener] ============================================

=== KCP Interop Test PASSED ===
```

## Running Individual Components

### Go (opener)
```bash
cd go && go run ./examples/kcp_test -name go -config ../examples/kcp_test/config.json
```

### Rust (accepter)
```bash
cd rust && cargo run --example kcp_interop -- --name rust --config ../examples/kcp_test/config.json
```

## Adding Zig Support

When Zig KCP implementation is ready:

1. Implement `zig/examples/kcp_test.zig`
2. Update `run.sh` to start Zig instance
3. Add bidirectional tests between all three languages
