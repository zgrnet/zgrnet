# ZGRNet Cross-Language Host Test

This example demonstrates communication between multiple ZGRNet hosts.

## Status

| Language | Status | Notes |
|----------|--------|-------|
| Go | ✅ Complete | Full implementation with UDP transport |
| Rust | ✅ Complete | Full implementation with UdpListener |
| Zig | ✅ Complete | Full implementation with UdpListener |

## Quick Start

Run 3 hosts (using Go implementation for all):

```bash
./run.sh
```

## Configuration

The `config.json` file defines three hosts with deterministic keys:

```json
{
  "hosts": [
    {"name": "go",   "private_key": "...01", "port": 10001},
    {"name": "rust", "private_key": "...02", "port": 10002},
    {"name": "zig",  "private_key": "...03", "port": 10003}
  ]
}
```

## What It Tests

1. **Handshake**: Each host performs Noise IK handshake with others
2. **Encryption**: All messages are encrypted with session keys
3. **Routing**: Messages are routed based on session index
4. **Roaming**: Endpoint updates on valid packet receipt

## Sample Output

```
[go] Connecting to rust...
[rust] Connecting to go...
[rust] Connected to go!
[go] Connected to rust!
[go] Sent message to rust
[rust] Received from go: protocol=128, data="Hello from go to rust!"
[go] Received from rust: protocol=128, data="ACK from rust: Hello from go to rust!"
```

## Running Individual Languages

### Go
```bash
cd go && go run examples/host_test/main.go -name go -config ../examples/host_test/config.json
```

### Rust
```bash
cd rust && cargo run --example host_test -- --name rust
```

### Zig
```bash
cd zig && zig run examples/host_test.zig -- --name zig
```
