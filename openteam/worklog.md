# Worklog: cl/kcp-refactor

## 审查记录

### 2026-02-27 - Reviewer
- **审查范围**：
  - `go/pkg/noise/message.go`
  - `go/pkg/net/udp.go`
  - `go/pkg/net/peer.go`
  - `go/pkg/kcp/service.go`
  - `rust/src/noise/message.rs`
  - `rust/src/net/udp.rs`
  - `zig/src/noise/message.zig`
  - `zig/src/net/udp.zig`
  - `zig/src/kcp/mod.zig`
  - `e2e/kcp/interop_test.go`

- **发现问题**：
  0. 分支存在未解决合并冲突，且有冲突标记残留。
     - 位置：`go/pkg/net/udp.go`、`zig/BUILD.bazel`
     - 证据：`git ls-files -u`、`git diff --check`
  1. Rust 线协议未带 service varint，仍是 `protocol + payload`。
     - 位置：`rust/src/noise/message.rs:263-276`
  2. Zig 线协议未带 service varint，仍是 `protocol + payload`。
     - 位置：`zig/src/noise/message.zig:270-295`
  3. Rust 网络层仍是旧 Mux + 固定 1ms update 循环，不是 yamux + Check 驱动。
     - 位置：`rust/src/net/udp.rs:652-693,724-742`
  4. Zig 网络层仍是旧 KcpMux + 固定 1ms timer loop，不是 yamux 路径。
     - 位置：`zig/src/net/udp.zig:851-883,1048-1077`
  5. Go 端 relay 仍按 protocol 特判，未统一 service listener 路由。
     - 位置：`go/pkg/net/udp.go:1299-1333`
  6. Tester 标准文档缺失（`openteam/test.md` 不存在），验收闭环不完整。

- **结论**：Needs Fixes（P0 未清零，不予通过）
- **要求 Developer 修改**：见 `openteam/plan.md` 的“Reviewer 要求修改”
