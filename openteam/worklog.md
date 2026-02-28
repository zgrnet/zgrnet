# Worklog: cl/kcp-refactor

## 审查记录

### 2026-02-27 - Developer
- **处理内容**：按 `openteam/plan.md` 执行 reviewer P0 项并落地代码。
  1. 已清理 rebase 冲突与冲突标记。
     - 验证：`git ls-files -u` 空；`git diff --check` 空。
  2. Relay 路由改为“先 service 再 protocol 处理”。
     - Go：`go/pkg/net/udp.go` 将 RELAY_0/1/2/PING/PONG 从 protocol 顶层分支迁移为 `service==noise.ServiceRelay` 条件下处理；KCP 保持 `smux.Input(service, payload)`。
     - Rust：`rust/src/net/udp.rs` 同步改为 `service == message::service::RELAY` 才处理 relay 协议分支；`execute_relay_action` 发送时显式使用 relay service。
     - Zig：`zig/src/net/udp.zig` 解包统一走 `decodePayload(protocol+service+data)`；relay 分支仅在 `decoded.service == message.Service.relay` 下执行；relay 转发发送时显式 relay service。
- **验证结果**：
  - `bazel build //zig:noise` ✅
  - `bazel test //go/pkg/net:net_test --test_output=errors` ❌（失败项：`TestClosedChanGoroutineLeak`，属于现有 goroutine leak 检查，非本次 relay/service 改动直接引入）
  - Rust 相关 Bazel 构建当前受 `rules_rust crate_universe` 超时影响，未完成本地编译验证。
- **备注**：
  - `openteam/test.md` 仍缺失（P1 未完成），需 Tester 或 Lead 提供基线后补齐映射。

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
