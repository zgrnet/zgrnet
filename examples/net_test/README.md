# ZGRNet Cross-Language net.UDP Test

This example demonstrates communication between multiple ZGRNet `net.UDP` instances.

## Status

| Language | Status | Notes |
|----------|--------|-------|
| Go | ✅ Complete | Full implementation with `net.UDP` |
| Rust | ✅ Complete | Full implementation with `net::UDP` |
| Zig | ✅ Complete | Full implementation with `net.UDP` |

## Quick Start

Run 3 UDP instances (using Go implementation for all):

```bash
./run.sh
```

## Configuration

The `config.json` file defines three instances with deterministic test keys:

```json
{
  "_WARNING": "TEST KEYS ONLY - DO NOT USE IN PRODUCTION",
  "hosts": [
    {"name": "go",   "private_key": "...01", "port": 10001},
    {"name": "rust", "private_key": "...02", "port": 10002},
    {"name": "zig",  "private_key": "...03", "port": 10003}
  ]
}
```

## What It Tests

1. **Handshake**: Each instance performs Noise IK handshake with others
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
[rust] Received from go: data="Hello from go to rust!"
[go] Received from rust: data="ACK from rust: Hello from go to rust!"
```

## Running Individual Languages

### Go
```bash
cd go && go run ./examples/net_test -name go -config ../examples/net_test/config.json
```

### Rust
```bash
cd rust && cargo run --example host_test -- --name rust
```

### Zig
```bash
cd zig && zig build && ./zig-out/bin/host_test --name zig
```
