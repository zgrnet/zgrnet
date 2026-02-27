# Review 标准与本轮审查结论：KCP 重构（service 协议 + yamux）

## 审查依据
- `openteam/design_proposal.md`（工作区当前缺失，按任务目标与 PR 说明交叉审）
- `openteam/task.md`（工作区当前缺失，按既定目标“protocol+service(varint)+data”执行）
- 代码与 PR：`cl/kcp-refactor` / PR #38

## 检查清单与结论

### A. 线协议与编解码一致性
- [x] Go 端 `protocol + service(varint) + data`
  - 证据：`go/pkg/noise/message.go:124-149`
- [ ] Rust 端同格式（未通过）
  - 证据：`rust/src/noise/message.rs:263-276` 仍是 `protocol + payload`，无 service varint。
- [ ] Zig 端同格式（未通过）
  - 证据：`zig/src/noise/message.zig:270-295` 仍是 `protocol + payload`，无 service varint。

### B. Host/UDP 按 service 统一路由（含 relay）
- [ ] relay 不应再走协议特判分支（未通过）
  - 证据：`go/pkg/net/udp.go:1299-1333` 仍对 `ProtocolRelay0/1/2` 单独 switch。
- [ ] 所有协议统一 `service -> listener` 路径（未通过）
  - 证据：Rust/Zig UDP 路径仍是按 protocol 分流：
    - `rust/src/net/udp.rs:984-1057`
    - `zig/src/net/udp.zig:1174-1234`

### C. KCP + yamux 架构替换
- [x] Go 侧引入 `ServiceMux + yamux`
  - 证据：`go/pkg/kcp/service.go:19-298`
- [ ] Rust 侧仍在使用旧 `Mux` + 固定 1ms update（未通过）
  - 证据：
    - `rust/src/net/udp.rs:652-693`（`Mux::new`）
    - `rust/src/net/udp.rs:724-742`（固定 1ms interval/sleep）
- [ ] Zig 侧仍在使用旧 `KcpMux` + 固定 1ms timer（未通过）
  - 证据：
    - `zig/src/net/udp.zig:851-883`（`KcpMux.init`）
    - `zig/src/net/udp.zig:1048-1077`（`sleepMs(1)` + 全量 update）
    - `zig/src/kcp/mod.zig:5-8,39-45`（仍暴露 Frame/Mux 旧模型）

### D. e2e 矩阵覆盖（静态）
- [x] e2e 覆盖 echo/streaming/multi_stream/delayed_write，且含 Go/Rust/Zig 双向组合
  - 证据：`e2e/kcp/interop_test.go:93-277`

### E. 提交卫生 / PR 质量
- [x] 未发现二进制、构建产物、临时缓存、敏感信息直接入库（按 `git diff --name-only` 静态检查）
- [x] PR 标题和描述为英文，且包含 `Summary`/`Testing`
  - 证据：PR #38 元数据

## 审查结果
- 总体状态：**Needs Fixes**
- 发现问题数：**7（P0: 6, P1: 1）**
- 最后审查时间：2026-02-27

## 关键结论（直说）
这次实现是“Go 先跑了一截，Rust/Zig 还停在旧轨道上”。PR 说“三语言完成 service+yamux 重构”，代码实际并不成立。尤其 Rust/Zig 线协议没 service varint、仍旧 Mux + 1ms 轮询，和目标架构不一致，不能放行。

另外，当前分支还有未解决合并冲突（`git ls-files -u` 命中 `go/pkg/net/udp.go` 与 `zig/BUILD.bazel`；`git diff --check` 报 `zig/BUILD.bazel` leftover conflict marker）。这属于直接阻塞项，必须先清干净再谈验收。
