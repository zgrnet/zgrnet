# zgrnet Development Guidelines

> zgrnet = **Z**ig + **G**o + **R**ust **Net**work Library

A Noise Protocol based networking library with multi-language SDKs.

---

## Project Structure

```
zgrnet/
├── go/                 # Go SDK
│   └── noise/          # Noise Protocol implementation
├── rust/               # Rust SDK
│   └── src/
├── zig/                # Zig SDK
│   └── src/
├── docs/
│   └── design/         # Design documents
├── MODULE.bazel        # Bazel module definition
├── BUILD.bazel         # Root build file
└── .bazelrc            # Bazel configuration
```

---

## Development Phases

| Phase | Description | Go | Rust | Zig |
|-------|-------------|:--:|:----:|:---:|
| **1** | Noise Protocol + Tests | ✅ | ✅ | ✅ |
| **2** | Session Management | ⏳ | ⏳ | ⏳ |
| **3** | Transport Layer (UDP) | ⏳ | ⏳ | ⏳ |
| **4** | Peer Management | ⏳ | ⏳ | ⏳ |
| **5** | Host Integration | ⏳ | ⏳ | ⏳ |
| **6** | Relay Protocol | ⏳ | ⏳ | ⏳ |

Legend: ✅ Done | 🔄 In Progress | ⏳ Pending

---

## Build System (Bazel)

### Prerequisites

- [Bazelisk](https://github.com/bazelbuild/bazelisk) (recommended) or Bazel 7.0+

### Common Commands

```bash
# Build all
bazel build //...

# Test all
bazel test //...

# Test with coverage
bazel coverage //...

# Build specific SDK
bazel build //go/noise:noise
bazel build //rust:zgrnet
bazel build //zig:zgrnet
```

### Coverage Requirements

| Metric | Minimum | Target |
|--------|---------|--------|
| Line Coverage | 90% | 100% |
| Branch Coverage | 85% | 95% |

---

## Go SDK

### Directory Structure

```
go/
├── go.mod
├── BUILD.bazel
└── noise/
    ├── BUILD.bazel
    ├── keypair.go          # Key, KeyPair types
    ├── keypair_test.go
    ├── cipher.go           # DH, Hash, HKDF, AEAD
    ├── cipher_test.go
    ├── state.go            # CipherState, SymmetricState
    ├── state_test.go
    ├── handshake.go        # HandshakeState, patterns
    ├── handshake_test.go
    └── interop_test.go     # Cross-language tests (future)
```

### Build & Test

```bash
cd go

# Native Go
go build ./...
go test ./... -cover
go test ./... -coverprofile=coverage.out
go tool cover -html=coverage.out

# Bazel
bazel build //go/...
bazel test //go/... --test_output=all
bazel coverage //go/... --combined_report=lcov
```

### Coding Style

- Follow standard `gofmt` / `goimports`
- Use `golangci-lint` for linting
- Test files: `*_test.go`
- Benchmark files: `*_bench_test.go`

---

## Rust SDK

### Directory Structure

```
rust/
├── Cargo.toml
├── BUILD.bazel
└── src/
    ├── lib.rs
    ├── keypair.rs
    ├── cipher.rs
    ├── state.rs
    └── handshake.rs
```

### Build & Test

```bash
cd rust

# Native Cargo
cargo build
cargo test
cargo test -- --nocapture
cargo tarpaulin --out Html  # Coverage

# Bazel
bazel build //rust:zgrnet
bazel test //rust:zgrnet_test
```

### Coding Style

- Follow `rustfmt` defaults
- Use `clippy` for linting
- Test modules: `#[cfg(test)] mod tests { ... }`

---

## Zig SDK

### Directory Structure

```
zig/
├── build.zig
├── build.zig.zon
├── BUILD.bazel
└── src/
    ├── root.zig
    ├── keypair.zig
    ├── cipher.zig
    ├── state.zig
    └── handshake.zig
```

### Build & Test

```bash
cd zig

# Native Zig
zig build
zig build test

# Bazel
bazel build //zig:zgrnet
bazel test //zig:zgrnet_test
```

### Coding Style

- Follow Zig standard style
- Use `zig fmt` for formatting
- Tests: `test "description" { ... }`

---

## Testing Guidelines

### Test Categories

1. **Unit Tests** - Test individual functions/methods
2. **Integration Tests** - Test module interactions
3. **Interop Tests** - Cross-language compatibility (Phase 2+)
4. **Fuzz Tests** - Security-critical code (handshake, crypto)

### Test Naming

| Language | Pattern | Example |
|----------|---------|---------|
| Go | `TestXxx`, `BenchmarkXxx` | `TestHandshake_IK` |
| Rust | `#[test] fn xxx()` | `fn test_handshake_ik()` |
| Zig | `test "xxx"` | `test "handshake IK pattern"` |

### Coverage Enforcement

All PRs must maintain or improve coverage:

```bash
# Go
go test ./... -coverprofile=coverage.out
go tool cover -func=coverage.out | grep total

# Rust
cargo tarpaulin --out Xml

# Zig (manual inspection for now)
zig build test
```

---

## Cross-Language Interoperability

### Phase 2+ Goal

All three SDKs must be able to:
1. Complete a Noise IK handshake with each other
2. Exchange encrypted messages post-handshake

### Test Vectors

Shared test vectors will be placed in:
```
tests/
└── vectors/
    ├── keypair.json       # Known keypairs for testing
    ├── handshake_ik.json  # IK pattern test vectors
    └── transport.json     # Encrypted message vectors
```

---

## Reference Materials

### WireGuard C Implementation (for Noise Protocol reference)

```
/tmp/wireguard-ref/
├── wireguard-linux-compat/src/
│   ├── noise.c          # Noise Protocol implementation
│   ├── noise.h
│   └── crypto/          # Crypto primitives
└── wireguard-tools/
```

### Noise Protocol Specification

- [Noise Protocol Framework](https://noiseprotocol.org/noise.html)
- Pattern: `Noise_IK_25519_ChaChaPoly_BLAKE2s`

---

## Commit & PR Guidelines

### Branch Naming

```
cl/{lang}/{feature}
```

Examples:
- `cl/go/noise-handshake`
- `cl/rust/cipher-suite`
- `cl/zig/keypair`

### Commit Messages

```
{lang}: {description}

{lang}/noise: add IK handshake pattern
{lang}/cipher: implement BLAKE2s hash
```

### PR Checklist

- [ ] All tests pass (`bazel test //...`)
- [ ] Coverage >= 90%
- [ ] Code formatted (`gofmt`, `rustfmt`, `zig fmt`)
- [ ] No linter warnings
- [ ] Interop tests pass (if applicable)
