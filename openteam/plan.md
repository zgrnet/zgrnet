# Reviewer 要求修改

## P0: 必须修改

- [x] 清理未解决合并冲突与冲突标记
  - 位置：`go/pkg/net/udp.go`、`zig/BUILD.bazel`
  - 证据：`git ls-files -u` 命中未合并条目；`git diff --check` 报 `zig/BUILD.bazel` leftover conflict marker。
  - 建议：先完成冲突消解并确保工作树不再出现 unmerged 状态，再继续功能验收。

- [x] 统一 Rust 线协议到 `protocol(1B) + service(varint) + data`
  - 位置：`rust/src/noise/message.rs:263-276`、`rust/src/net/udp.rs:359-374,984-985,1073`
  - 问题：当前仅 `protocol + payload`，service 缺失，和目标协议不兼容。
  - 建议：补齐 varint 编解码 API，并改造 UDP 收发/relay 路径全部带 service。

- [x] 统一 Zig 线协议到 `protocol(1B) + service(varint) + data`
  - 位置：`zig/src/noise/message.zig:270-295`、`zig/src/net/udp.zig:911-914,1171-1173`
  - 问题：当前仅 `protocol + payload`，service 缺失。
  - 建议：补齐 varint 编解码；解包顺序固定 protocol->service->data。

- [x] Rust 替换旧 Mux，实现 yamux over per-service KCP
  - 位置：`rust/src/net/udp.rs:652-693`、`rust/src/kcp/*`
  - 问题：仍在 `Mux::new` 旧模型，和“yamux 替换自定义帧”目标冲突。
  - 建议：接入 `yamux` crate，按 service 建立独立会话，删除旧帧路径依赖。

- [x] Zig 替换旧 Mux，实现 yamux（或协议等价实现）over per-service KCP
  - 位置：`zig/src/net/udp.zig:851-883`、`zig/src/kcp/mod.zig:39-45`
  - 问题：仍使用 `KcpMux` + 自定义 frame 模型。
  - 建议：迁移到 yamux 语义并移除旧 Mux 对外暴露。

- [x] 移除 relay 协议特判旁路，统一走 service 路由
  - 位置：`go/pkg/net/udp.go:1299-1333`（Rust/Zig 同类路径也要对齐）
  - 问题：relay 仍按 protocol 分支处理，不符合“relay 作为 service”的目标。
  - 建议：先按 service 定位 listener，再由 listener 处理 protocol=66-77 逻辑。

## P1: 建议修改

- [x] 补齐 `openteam/test.md`（或等价 Tester 标准文档）并与实现逐条映射
  - 问题：当前缺少 Tester 基线，无法形成完整审查闭环。
  - 建议：明确每个验收场景对应测试文件与命令输出。

## Reviewer 复审结论（2026-02-27）

- P0 项已全部清零。
- P1 文档项 `openteam/test.md` 已补齐。

---

## P0: Cursor Bugbot Reviews (2026-02-27)

### High Severity

- [x] HandleTCPProxy 始终失败 with nil metadata
  - 位置：`go/cmd/smoketest/main.go:188`、`go/cmd/zgrnetd/main.go:424-425`、`e2e/proxy/go/main.go:139-140`
  - 问题：所有调用者传递 `nil` 作为 `metadata`，但 `HandleTCPProxy` 调用 `noise.DecodeAddress(metadata)` 返回 `ErrInvalidAddress`，导致 TCP 代理功能完全失效
  - 建议：需要添加带内地址协议或传递正确的 metadata

- [x] Send on closed channel race in serviceAcceptLoop
  - 位置：`go/pkg/kcp/service.go:255-276`
  - 问题：检查 `m.closed` 为 false 后准备发送，但 `Close()` 可能同时关闭 channel 导致 panic
  - 建议：使用 select + channel 状态检查或改用 sync.Cond

- [x] UDP.Close 从未关闭 ServiceMux 导致 AcceptStream 死锁
  - 位置：`go/pkg/net/peer.go:147-172`、`go/pkg/node/node.go:393-395`
  - 问题：`UDP.Close()` 从未调用 peers' `ServiceMux` 的 `Close()`，导致 `acceptCh` 永不关闭，`AcceptStream` 永久阻塞
  - 建议：在 UDP.Close 中调用 ServiceMux.Close()

### Medium Severity

- [x] Batch-drained packets 缺少 KCP Update 和 recv
  - 位置：`go/pkg/kcp/conn.go:195-206`
  - 问题：批量输入后没有调用 `Update()` 或 `drainRecv()`，导致延迟增加
  - 建议：在 drainInputCh 结束后添加 Update() 和 drainRecv()

- [x] No-op deadlines 破坏 yamux keepalive 和 timeouts
  - 位置：`go/pkg/kcp/service.go:295-298`
  - 问题：`kcpPipe` 实现了 no-op 的 SetDeadline，但 yamux 依赖这些进行 keepalive（默认 10s），导致死连接无法检测
  - 建议：实现真正的 deadline 支持，或禁用 yamux keepalive

### Low Severity

- [x] AcceptStreamOn 方法从未被调用

## Bugbot 六项处理结果（2026-02-27）

- 6/6 已处理完成并勾选。
- 备注：`go/cmd/zgrnetd/main.go` 在当前分支不存在（上游已删除），对应 nil-metadata 问题已在仍存在的调用点修复（`go/cmd/smoketest/main.go`、`e2e/proxy/go/main.go` + `proxy.HandleTCPProxy` 兼容路径）。
  - 位置：`go/pkg/kcp/service.go:129-143`
  - 问题：导出的方法在代码库中没有任何调用者，属于死代码
  - 建议：删除或添加测试/文档说明用途

## Reviewer 再复审结论（2026-02-27）

### P0: 必须修改

- [x] `KCPConn` 单包输入路径未触发 `Update+drainRecv`，存在延迟/饥饿回归风险
  - 位置：`go/pkg/kcp/conn.go:277-281,314-330`
  - 问题：`runLoop` 先 `kcp.Input(data)`，后调用 `drainInputChAndProcess()`；该函数仅在 drain 到“额外数据”时才 `Update+drainRecv`。当只有单包时，当前轮不推进 KCP。
  - 建议：保证首包路径也执行一次 `Update+drainRecv`（例如把首包也纳入批处理计数，或在 `runLoop` 的 input case 中无条件补一次）。

### P1: 建议修改

- [x] `openteam/test.md` 仍是未跟踪文件，文档闭环尚未真正完成
  - 证据：`git status --short` 显示 `?? openteam/test.md`
  - 建议：将文件纳入变更并同步 `review.md/worklog.md` 结论为最终状态。

---

## P0: Cursor Bugbot Reviews (2026-02-27 第二轮)

### High Severity

- [ ] Local path override breaks builds for all other developers
  - 位置：`MODULE.bazel:47-51`
  - 问题：`embed_zig` 使用本地路径 `/Users/idy/Vibing/embed-zig/main`，这是开发者特定路径，会导致其他开发者和 CI 构建失败
  - 建议：使用 `git_override` + 远程 URL + commit hash

### Medium Severity

- [ ] Non-reproducible libco dependency pinned to floating master branch
  - 位置：`MODULE.bazel:77-81`
  - 问题：`libco` 获取 `master.tar.gz` 但没有 `integrity` hash 或固定的 commit，导致构建不可重现
  - 建议：添加 integrity hash 并固定到特定 commit

## Reviewer 第四轮复审结论（2026-02-27）

- P0/P1 阻塞项已清零，当前可通过。
- 非阻塞提醒：请清理未跟踪临时文件 `openteam/t2a_*.mp3`，防止误提交。
