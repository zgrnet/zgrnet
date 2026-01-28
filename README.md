# zgrnet

> **Z**ig + **G**o + **R**ust **Net**work Library

A Noise Protocol based networking library for building secure distributed systems.

## Features

- **Noise Protocol** - End-to-end encryption with forward secrecy
- **Public Key Identity** - No registration, self-generated identity
- **Multi-language SDKs** - Go, Rust, Zig with full interoperability
- **Relay Support** - NAT traversal with multi-hop relay

## Project Structure

```
zgrnet/
├── go/             # Go SDK
├── rust/           # Rust SDK
├── zig/            # Zig SDK
└── docs/
    └── design/     # Design documents
```

## Quick Start

### Build with Bazel

```bash
# Build all
bazel build //...

# Test all (coverage >= 90%)
bazel test //...

# Coverage report
bazel coverage //...
```

### Build with Native Tools

```bash
# Go
cd go && go build ./... && go test ./...

# Rust
cd rust && cargo build && cargo test

# Zig
cd zig && zig build && zig build test
```

## Documentation

- [Design Documents](docs/design/) - Architecture and protocol specs
- [AGENTS.md](AGENTS.md) - Development guidelines

## Development Status

| Phase | Description | Go | Rust | Zig |
|-------|-------------|:--:|:----:|:---:|
| 1 | Noise Protocol | ✅ | ✅ | ✅ |
| 2 | Session Management | ⏳ | ⏳ | ⏳ |
| 3 | Transport (UDP) | ⏳ | ⏳ | ⏳ |
| 4 | Peer Management | ⏳ | ⏳ | ⏳ |
| 5 | Host Integration | ⏳ | ⏳ | ⏳ |
| 6 | Relay Protocol | ⏳ | ⏳ | ⏳ |

## License

MIT
