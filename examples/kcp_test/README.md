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
4. **Throughput**: 1 MB transfer with measured speed

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
    |--- Throughput data (1MB) ---->|
    |<-- Throughput ACK ------------|
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
[rust] Public key: 0a8ddb14...
[rust] Role: accepter
[rust] Listening on 0.0.0.0:10002

--- Starting Go (opener) on port 10001 ---
[go] Public key: 2fe57da3...
[go] Role: opener
[go] Connecting to rust...
[go] Connected to rust!
[opener] Opened stream 1
[opener] Running echo test...
[accepter] Accepted stream 1
[accepter] Received echo: "Hello KCP Interop!"
[opener] Received echo response: "Echo from accepter: Hello KCP Interop!"
[opener] Running throughput test (1 MB, 32 KB chunks)...
[accepter] Receiving throughput data...
[opener] ========== Results ==========
[opener] Sent: 1048576 bytes (1.00 MB)
[opener] Time: 50ms
[opener] Throughput: 20.00 MB/s
[opener] ==============================

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
