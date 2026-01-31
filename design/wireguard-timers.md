# WireGuard 计时器与重传机制

本文档梳理自 WireGuard 白皮书第 6 节 "Timers & Stateless UX"。

## 1. 时间常量

| 常量 | 值 | 用途 |
|------|-----|------|
| `Rekey-After-Messages` | 2^60 | 发送此数量消息后触发 rekey |
| `Reject-After-Messages` | 2^64 - 2^13 - 1 | 超过此数量后拒绝使用当前会话 |
| `Rekey-After-Time` | 120 秒 | 会话存活此时间后触发 rekey |
| `Reject-After-Time` | 180 秒 | 会话超时，拒绝收发 |
| `Rekey-Attempt-Time` | 90 秒 | 握手重试的最大持续时间 |
| `Rekey-Timeout` | 5 秒 | 握手重传间隔 |
| `Keepalive-Timeout` | 10 秒 | 空闲后发送 keepalive |

**关键约束**：永远不会在 `Rekey-Timeout` 内发送超过一次握手初始化消息。

## 2. 会话生命周期

```
                    ┌─────────────────────────────────────────────────────────┐
                    │                      会话时间线                          │
                    └─────────────────────────────────────────────────────────┘
    
    0s              120s                    165s                180s           540s
    │                │                       │                   │              │
    ├────────────────┼───────────────────────┼───────────────────┼──────────────┤
    │                │                       │                   │              │
    创建会话     Rekey-After-Time    Reject-After-Time      Reject-After-Time   清除所有会话
                (发起 rekey)        - Keepalive-Timeout     (拒绝收发)        (Reject-After-Time × 3)
                                   - Rekey-Timeout
                                   (收到数据时发起 rekey)
```

## 3. Rekey 触发条件

### 3.1 基于消息数量

- 发送 `Rekey-After-Messages` 条消息后 → 发起新握手

### 3.2 基于时间（仅限 Initiator）

**发送数据时触发**：
- 当前会话超过 `Rekey-After-Time` (120s) → 发起新握手

**接收数据时触发**：
- 当前会话超过 `Reject-After-Time - Keepalive-Timeout - Rekey-Timeout` (165s)
- 且尚未对此事件采取行动
- → 发起新握手

> 注意：时间触发的 rekey 仅限 initiator 发起，防止"惊群效应"（两端同时发起握手）

### 3.3 拒绝条件

以下情况拒绝使用当前会话收发数据：
- 消息数超过 `Reject-After-Messages`
- 会话时间超过 `Reject-After-Time` (180s)

## 4. 握手重传机制

```
                          握手重传状态机
    
    ┌─────────────┐
    │ 需要发送数据  │
    │ 但无有效会话  │
    └──────┬──────┘
           │
           ▼
    ┌─────────────┐     Rekey-Timeout (5s)    ┌─────────────┐
    │ 发送握手初始化 │ ◄─────────────────────── │ 等待响应     │
    │ (生成新临时密钥)│                          │             │
    └──────┬──────┘                           └──────┬──────┘
           │                                         │
           │                                    收到响应
           │                                         │
           ▼                                         ▼
    ┌─────────────┐                           ┌─────────────┐
    │ 超过 90s?    │───── 是 ────────────────► │  放弃       │
    │             │                           │             │
    └──────┬──────┘                           └─────────────┘
           │ 否
           │
           ▼
      继续等待/重传
```

**重传规则**：
1. 发送握手初始化后，等待 `Rekey-Timeout` (5s)
2. 未收到响应 → 构造新握手初始化（新临时密钥）并发送
3. 重试持续 `Rekey-Attempt-Time` (90s) 后放弃
4. 如果用户显式发送新数据 → 重置 90s 计时器

**重要**：每次重传都生成新的临时密钥，不是简单重发旧消息。

## 5. Passive Keepalive

```
    收到有效数据
         │
         ▼
    ┌─────────────────────┐
    │ 有数据要发送？        │
    │                     │
    └──────┬──────┬───────┘
           │      │
          有      无
           │      │
           ▼      ▼
    ┌───────┐   ┌─────────────────────────┐
    │ 发送数据│   │ 等待 Keepalive-Timeout  │
    └───────┘   │ (10s)                   │
                └───────────┬─────────────┘
                            │ 超时且仍无数据
                            ▼
                    ┌───────────────┐
                    │ 发送 Keepalive │
                    │ (空 payload)   │
                    └───────────────┘
```

**Keepalive 消息**：
- payload 长度为 0 的 transport message
- 仍有 16 字节的 Poly1305 认证标签

**断线检测**：
- 如果 `Keepalive-Timeout + Rekey-Timeout` (15s) 内未收到任何数据
- → 认为会话断开
- → 每 `Rekey-Timeout` (5s) 发送一次握手初始化
- → 持续 `Rekey-Attempt-Time` (90s)

## 6. Cookie Reply 交互

收到 Cookie Reply 后：
1. **不要**立即重发握手消息
2. 仅存储解密后的 cookie 值和接收时间
3. 等待 `Rekey-Timeout` 过期后再重试握手

这防止了带宽滥用，并帮助缓解导致 cookie reply 的负载条件。

## 7. 会话轮换 (Key Rotation)

WireGuard 维护三个会话槽：

| 槽 | 用途 |
|-----|------|
| Current | 当前活跃会话 |
| Previous | 上一个会话（接收可能延迟到达的包） |
| Next | 下一个会话（responder 未确认时使用） |

**轮换流程**：
1. 新会话创建 → 现有 current 移到 previous → 新会话占用 current
2. Previous 的 previous 被丢弃并清零
3. 超过 `Reject-After-Time × 3` (540s) 无新会话 → 清除所有会话

## 8. 完整状态机总结

```
    ┌──────────────────────────────────────────────────────────────────┐
    │                          Peer 状态机                             │
    └──────────────────────────────────────────────────────────────────┘
    
    事件触发：
    
    [发送数据包]
        ├── 无有效会话 → 排队 + 发送握手初始化
        ├── 会话 > 120s (initiator) → 发送握手初始化
        └── 消息数 > 2^60 → 发送握手初始化
    
    [接收数据包]
        ├── 会话 > 165s (initiator) → 发送握手初始化
        └── 更新 lastReceived 时间戳
    
    [Tick 定时器] (每秒或更频繁)
        ├── lastSent > 10s 且 lastReceived < 10s → 发送 Keepalive
        ├── lastReceived > 15s 且有 pending 握手 → 重发握手初始化
        ├── 握手等待 > 5s 且 < 90s → 重发握手初始化
        └── 握手等待 > 90s → 放弃握手
    
    [收到握手初始化]
        └── 发送握手响应
    
    [收到握手响应]
        └── 完成会话建立 + 发送排队的数据
    
    [收到 Cookie Reply]
        └── 存储 cookie (不立即重发)
```

## 9. 与我们设计的对应

| WireGuard 概念 | zgrnet 对应 |
|---------------|-------------|
| 发送握手初始化 | `Conn.dial()` / rekey |
| 发送数据 | `Conn.Send()` |
| 发送 Keepalive | `Conn.SendKeepalive()` |
| 接收数据 | `Conn.Recv()` |
| 定时器检查 | `Conn.Tick()` |
| Current Session | `Conn.session` |
| Previous Session | 需要添加 |
| Next Session | 需要添加 (responder 用) |

## 10. 关键设计决策

1. **Tick() 应该做什么**：
   - 检查是否需要发送 Keepalive → 直接发送
   - 检查是否需要重传握手 → 直接发送
   - 检查会话是否过期 → 返回错误

2. **Recv() 应该处理什么**：
   - 握手响应 → 完成会话建立
   - Cookie Reply → 存储 cookie
   - Transport 数据 → 解密并返回

3. **Send() 触发什么**：
   - 无有效会话 → 排队 + 触发握手
   - 会话需要 rekey → 先发数据，同时触发握手

4. **需要的额外状态**：
   - `lastSent` - 最后发送时间
   - `lastReceived` - 最后接收时间
   - `handshakeStarted` - 握手开始时间
   - `sessionCreated` - 会话创建时间
   - `isInitiator` - 是否为会话发起者
   - `pendingPackets` - 等待会话建立的排队数据
