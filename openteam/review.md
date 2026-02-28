# Review 标准：Service Protocol（protocol + service varint + data）与 Zig-Go KCP Interop

## 审查依据
- Design Proposal: `openteam/design_proposal.md`
- Task: `openteam/task.md`
- Plan: `openteam/plan.md`
- Test: `openteam/test.md`（当前仓库未找到该文件，按“缺失测试标准”处理，要求补齐）

## 检查清单（审核前置标准）

### A. 线协议与编解码一致性（P0）
- [ ] A1. plaintext 线格式统一为：`protocol(1B) + service(varint) + data`
  - 检查方法：静态查看 Go/Zig 的 message encode/decode 与 UDP 收发路径，确认无“先 service 后 protocol”或其他分支格式。
  - 通过标准：所有入口/出口路径一致；不存在 relay 特判绕过 service。
- [ ] A2. service varint 编解码符合 protobuf 风格（续位 bit 语义正确）
  - 检查方法：检查 varint 编码循环、位移累加、终止条件、越界处理。
  - 通过标准：1/2/3+ 字节场景逻辑正确；异常输入（截断、超长）有明确错误路径，不 silent fallback。
- [ ] A3. protocol 字段读取与分发顺序正确
  - 检查方法：检查 host 解包逻辑是否“先 protocol 再 service 再 data”。
  - 通过标准：与 task.md 第 55-67 行一致，无旧架构残留。

### B. Host 路由与 Listener 语义（P0）
- [ ] B1. host 按 service 查 listener 注册表并投递
  - 检查方法：检查 listener map/register/dispatch 代码路径。
  - 通过标准：命中则投递，未命中丢弃；无错误路由到默认 handler。
- [ ] B2. relay 作为普通 service 处理（建议 service=0），不再特殊协议旁路
  - 检查方法：检查 relay 处理入口是否经统一 service 路由。
  - 通过标准：不注册 relay service 时应丢弃，不存在隐式 relay 开启。
- [ ] B3. Listener API 语义一致
  - 检查方法：检查 `Listen(service)`, `AcceptStream()`, `ReadPacket()` 的数据来源与协议边界。
  - 通过标准：`AcceptStream()` 仅承载 KCP+yamux stream；`ReadPacket()` 返回非 KCP 包（保留 protocol+data 语义）。

### C. KCP + yamux 架构落地（P0）
- [ ] C1. 每个 service 独立 KCP 实例，非全局 poll loop
  - 检查方法：检查是否仍有全局 O(N) Update 轮询；检查 per-service goroutine/任务模型。
  - 通过标准：按 service 隔离驱动，收包事件投递到对应实例。
- [ ] C2. KCP Update 调度基于 Check()/下一次唤醒，而非固定 ticker 轮询
  - 检查方法：查看 update 调度逻辑。
  - 通过标准：不存在固定周期盲轮询导致空转。
- [ ] C3. 复用层为 yamux（或 Zig 端协议等价实现），不保留自定义 SYN/FIN/PSH/NOP 帧路径
  - 检查方法：检查依赖与代码路径，确认旧 Mux 帧已移除或不再生效。
  - 通过标准：stream 多路复用统一走 yamux 语义，旧帧逻辑不参与运行。

### D. Zig↔Go interop 与稳定性（P0）
- [ ] D1. 计划中宣称修复的问题必须有对应代码变更（非口头）
  - 检查方法：对照 `plan.md` 已勾选步骤 1-5，逐项核对相关文件与实现。
  - 通过标准：每项都有可定位改动；无“标记完成但无代码”的敷衍。
- [ ] D2. streaming / multi_stream / delayed_write 所需机制完整
  - 检查方法：检查流建立、背压/关闭、延迟写处理、并发 stream 资源管理代码。
  - 通过标准：逻辑闭环完整，无 TODO stub、无假实现。
- [ ] D3. 资源释放与并发关闭安全
  - 检查方法：重点审查 socket/kcp/session deinit 顺序、锁/原子使用、双重关闭保护。
  - 通过标准：无明显竞态、UAF、重复 close 风险路径。

### E. 测试与可验证性（P1）
- [ ] E1. 覆盖 task/plan 声称的 e2e 矩阵（至少 echo/streaming/multi_stream/delayed_write）
  - 检查方法：静态检查测试用例定义、参数矩阵与断言。
  - 通过标准：测试文件中可见完整场景与双向组合，不是单点样例。
- [ ] E2. `openteam/test.md` 对齐性
  - 检查方法：核对实现/测试是否覆盖 Tester 标准。
  - 通过标准：若 `test.md` 缺失，判定为流程缺口，需补齐后复审。

### F. 代码质量与红线（P0）
- [ ] F1. 禁止 TODO 占位/空实现/返回假数据
  - 检查方法：搜索 TODO、stub 分支、硬编码假返回。
  - 通过标准：对外暴露能力必须端到端可用。
- [ ] F2. Zig 禁止 `std.atomic.Value(i128/u128)`
  - 检查方法：检查 Zig 代码中的 atomic 类型。
  - 通过标准：仅使用 i64/u64 等允许类型。
- [ ] F3. 错误处理与边界条件
  - 检查方法：检查截断包、非法 varint、未知 protocol、listener 缺失等分支。
  - 通过标准：错误路径明确、可追踪，无 silent ignore（未命中 listener 的明确丢弃除外）。

### G. 提交物卫生（P0）
- [ ] G1. 不应提交文件检查（基于 `git diff --name-only`）
  - 检查方法：核查是否出现 `bin/`、构建产物、临时缓存、IDE 配置、敏感信息等。
  - 通过标准：若出现，必须要求移除并在评审中严厉指出。
- [ ] G2. 工作日志文件提交策略
  - 检查方法：检查是否误提交无关 `*.log`。
  - 通过标准：仅允许任务要求的 `openteam/worklog.md`；其他日志文件一律移除。

### H. PR 标题与描述质量（P1）
- [ ] H1. PR 标题英文、动词开头、能说明变更目的
  - 检查方法：查看 PR title。
  - 通过标准：不满足则要求修改。
- [ ] H2. PR 描述英文且包含 `Summary`、`Testing`
  - 检查方法：查看 PR body。
  - 通过标准：`Summary` 1-3 条价值点；`Testing` 写明命令/结果或未执行原因。

## 评分与结论规则
- **Pass**：所有 P0 通过；P1 无阻塞问题。
- **Needs Fixes**：存在任一 P0 未通过，或多个 P1 影响可维护性/可验证性。
- **Reject**：核心架构与任务目标不一致（如线协议不统一、仍保留 relay 特判旁路、仍是全局 poll）。

## 本次标准更新说明
- 已按当前任务文档将线协议基准明确为 `protocol + service(varint) + data`。
- 已将“relay 无特例、统一走 service 路由”列为 P0 强制项。
- 已将 `test.md` 缺失列为流程缺口：需补齐 Tester 标准后可完成完整验收闭环。

## 审查结果（待执行）
- 总体状态：Pending
- 发现问题数：待审查
- 最后审查时间：2026-02-27
