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

- [ ] 补齐 `openteam/test.md`（或等价 Tester 标准文档）并与实现逐条映射
  - 问题：当前缺少 Tester 基线，无法形成完整审查闭环。
  - 建议：明确每个验收场景对应测试文件与命令输出。
