# 测试基线：Service Protocol / KCP Interop（Reviewer P1 补齐）

## 目标

对齐 `openteam/task.md` 的验收要求，补齐可执行测试标准，并将“需求 -> 测试文件 -> 运行命令 -> 预期结果”建立映射。

---

## 一、协议与路由一致性（静态 + 集成）

### T1. 线协议统一：`protocol(1B) + service(varint) + data`
- **需求来源**：`task.md` 第 3-18 行
- **代码点**：
  - Go: `go/pkg/noise/message.go`
  - Rust: `rust/src/noise/message.rs`
  - Zig: `zig/src/noise/message.zig`
- **验证方式**：
  1. 编解码 API 必须提供 service 字段（非可选旁路）
  2. UDP 解包顺序固定为 protocol -> service -> payload
- **命令**：
  - `bazel build //go/... //rust:zgrnet //zig:noise`
- **通过标准**：三语言均可编译且无旧格式回退路径。

### T2. relay 统一走 service 路由（service=relay）
- **需求来源**：`task.md` 第 114-131 行
- **代码点**：
  - Go: `go/pkg/net/udp.go`
  - Rust: `rust/src/net/udp.rs`
  - Zig: `zig/src/net/udp.zig`
- **验证方式**：
  1. 非 KCP 包先按 service 分流
  2. relay 协议（66-77）仅在 `service=relay` 分支处理
- **命令**：
  - `bazel test //go/pkg/net:net_test --test_output=errors`
- **通过标准**：无 protocol 顶层 relay 旁路逻辑。

---

## 二、KCP + yamux（per-service）

### T3. 每个 service 独立 KCP + yamux 会话
- **需求来源**：`task.md` 第 90-113 行
- **代码点**：
  - Go: `go/pkg/kcp/service.go`
  - Rust: `rust/src/kcp/service.rs`
  - Zig: `zig/src/kcp/service.zig`, `zig/src/kcp/yamux.zig`
- **验证方式**：
  1. `openStream(service)` 与 `acceptStream()` 按 service 关联
  2. KCP 数据按 service 投递至对应复用层
- **命令**：
  - `bazel build //go/... //rust:zgrnet //zig:noise`
- **通过标准**：三语言构建通过，关键跨语言 e2e 通过（见 T4）。

---

## 三、跨语言 e2e（核心验收）

测试文件：`e2e/kcp/interop_test.go`

### T4. 互通矩阵

#### Go ↔ Zig
- Echo: `TestInterop_GoZig`, `TestInterop_ZigOpener_GoAccepter_Echo`
- Streaming: `TestInterop_GoOpener_ZigAccepter_Streaming`, `TestInterop_ZigOpener_GoAccepter_Streaming`
- Multi-stream: `TestInterop_GoOpener_ZigAccepter_MultiStream`, `TestInterop_ZigOpener_GoAccepter_MultiStream`
- Delayed write: `TestInterop_GoOpener_ZigAccepter_DelayedWrite`, `TestInterop_ZigOpener_GoAccepter_DelayedWrite`

#### Rust ↔ Zig
- Echo: `TestInterop_RustZig`, `TestInterop_ZigOpener_RustAccepter_Echo`
- Streaming: `TestInterop_RustOpener_ZigAccepter_Streaming`, `TestInterop_ZigOpener_RustAccepter_Streaming`
- Multi-stream: `TestInterop_RustOpener_ZigAccepter_MultiStream`, `TestInterop_ZigOpener_RustAccepter_MultiStream`
- Delayed write: `TestInterop_RustOpener_ZigAccepter_DelayedWrite`, `TestInterop_ZigOpener_RustAccepter_DelayedWrite`

#### Go ↔ Rust（回归）
- `TestInterop_GoOpener_RustAccepter_*`
- `TestInterop_RustOpener_GoAccepter_*`
- `TestInterop_GoRust_MultiStream`
- `TestInterop_RustOpener_NoImmediateWrite`

### 建议执行命令

1) 关键 Zig 互通冒烟（快速）
```bash
bazel test //e2e/kcp:interop_test \
  --test_filter='TestInterop_(GoZig|GoOpener_ZigAccepter_Streaming|ZigOpener_GoAccepter_Streaming|RustZig|RustOpener_ZigAccepter_Streaming|ZigOpener_RustAccepter_Streaming)$' \
  --test_output=errors
```

2) 全量 interop 回归
```bash
bazel test //e2e/kcp:interop_test --test_output=errors
```

### 通过标准
- 指定 filter 用例全部 PASS；
- 全量 interop PASS（若出现环境级波动，需在 worklog 记录并给出复现与根因）。

---

## 四、当前已验证结果（本轮）

- `bazel test //e2e/kcp:interop_test --test_filter='TestInterop_(GoZig|GoOpener_ZigAccepter_Streaming|ZigOpener_GoAccepter_Streaming)$' --test_output=errors` ✅
- `bazel test //e2e/kcp:interop_test --test_filter='TestInterop_(GoZig|GoOpener_ZigAccepter_Streaming|ZigOpener_GoAccepter_Streaming|RustZig|RustOpener_ZigAccepter_Streaming|ZigOpener_RustAccepter_Streaming)$' --test_output=errors` ✅

> 备注：`//zig:noise_test` 当前含 benchmark 测项，存在超时风险，不作为本任务 P0 的阻塞判定；其性能项另行跟踪。

---

## 五、与 `task.md` 验收条目映射

1. **统一线协议（含 service varint）** → T1
2. **Host 按 service 路由（relay 无特判旁路）** → T2
3. **KCP + yamux per-service 架构** → T3
4. **跨语言互通稳定（Go/Rust/Zig）** → T4
