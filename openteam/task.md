# Service Protocol

## Wire Format

Noise 解密后的 plaintext，所有协议统一格式，无特例：

```
┌──────────────────────────────────────────┐
│ protocol (1B) │ service (varint) │ data  │
└──────────────────────────────────────────┘
```

- `protocol` — 传输类型（1 字节），决定 data 的处理方式
- `service` — 服务标识（varint），host 按 service 路由到对应的 listener
- `data` — 协议载荷

所有协议（包括 relay）都携带 service 字段。没有特例、没有特判。

## Service Varint 编码

Protobuf varint 风格，每个 byte 最高位标记是否有后续 byte：

```
0xxxxxxx                       → 1 byte,  值 0-127
1xxxxxxx 0xxxxxxx              → 2 bytes, 值 128-16383
1xxxxxxx 1xxxxxxx 0xxxxxxx    → 3 bytes, 值 16384-2097151
```

### 约定（非强制）

| 范围 | 编码长度 | 用途 |
|------|---------|------|
| 0-127 | 1 byte | 系统/知名服务（类似 TCP well-known ports 0-1023） |
| 128+ | 2+ bytes | 用户自定义服务 |

Host 不限制 service ID 的分配，任何 service ID 都可以被任何程序使用。

## Protocol 值

| 值 | 名称 | 说明 |
|----|------|------|
| 0 | Raw | 原始数据 |
| 1 | ICMP | ICMP（无 IP 头） |
| 4 | IP | 完整 IP 包（TUN） |
| 6 | TCP | TCP（无 IP 头） |
| 17 | UDP | UDP 不可靠逐包 |
| 64 | KCP | KCP 可靠传输 → yamux stream 多路复用 |
| 65 | UDPProxy | UDP 代理 |
| 66-77 | Relay | 中继协议（RELAY_0/1/2 及 BIND/ALIAS 变体） |
| 69 | TCPProxy | TCP 代理（通过 KCP stream） |
| 70 | Ping | Ping 探测 |
| 71 | Pong | Pong 响应 |
| 128-255 | 应用层 | Chat, File, Media, Signal, RPC 等 |

## Host 分发逻辑

```
收到 UDP 包
  → Noise 解密
  → 读 protocol (1B)
  → 读 service (varint)
  → 按 service 查 listener 注册表
  → 找到 listener → 投递 (protocol, data)
  → 没有 listener → 丢弃
```

所有协议走同一条路径，包括 relay。

## 分层架构

```
host
  → service 路由（按 service varint 分发到 listener）
      │
      ├── service=0 (relay)
      │   └── relay engine（中继转发，protocol=66-77）
      │
      ├── service=1 (proxy)
      │   ├── protocol=KCP (64) → KCP 实例 → yamux → {stream 1, 2, ...}
      │   └── protocol=UDP (17) → 逐包投递
      │
      ├── service=2 (tun)
      │   └── protocol=IP (4) → TUN 包
      │
      └── service=N (用户自定义)
          ├── protocol=KCP (64) → KCP 实例 → yamux → {stream 1, 2, ...}
          └── protocol=UDP (17) → 逐包投递
```

每个 service 有自己独立的 KCP 实例（如果使用 KCP 协议）。
不同 service 之间 KCP 完全隔离，互不影响。

## KCP + yamux

每个 service 的 KCP 实例提供可靠字节流，yamux 在上面做 stream 多路复用：

```
KCP 可靠字节流 (per-service)
  └── yamux session
      ├── stream 1 (TCP 语义, io.ReadWriteCloser)
      ├── stream 2
      └── stream N
```

- KCP：负责可靠传输（重传、排序、拥塞控制）
- yamux：负责 stream 多路复用 + per-stream 流控（窗口退让）
- 一个 service 一个 KCP 实例，一个 goroutine 驱动（事件驱动，不 poll）

yamux 实现：
- Go: `github.com/hashicorp/yamux`
- Rust: `yamux` crate
- Zig: 参照 yamux spec 实现（协议简单，12B 帧头 + 状态机，嵌入式可跑）

## Relay 作为 Service

Relay 不再是特殊协议，而是一个普通的 service（建议 service=0）。

- 想当 relay 节点 → 注册 relay service listener
- 不注册 → 收到 relay 包没有 listener → 丢弃
- 管理员可以控制哪些节点开 relay

```go
// relay 节点
ln := host.Listen(ServiceRelay) // service=0
for {
    pkt, _ := ln.ReadPacket()
    relayEngine.Handle(pkt)
}

// 普通节点：不注册 ServiceRelay → 不中继
```

## Listener 接口

一个 listener 监听一个 service，接收该 service 的所有数据：

```go
ln := host.Listen(serviceID)

// TCP stream（通过 KCP + yamux）
stream, _ := ln.AcceptStream()

// UDP packet（或其他非 KCP 协议的包）
pkt, _ := ln.ReadPacket()
```

`AcceptStream()` 返回的是 yamux stream（`io.ReadWriteCloser`），和 `net.Conn` 用法一致。
`ReadPacket()` 返回非 KCP 协议的原始包（protocol + data）。
