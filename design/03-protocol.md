# 协议设计

## 基础

基于 Noise Protocol（与 WireGuard 兼容），但有以下改进：
- 去掉 IP Header，减少开销
- 支持多种上层协议（不仅仅是 IP）
- 支持 RELAY 协议实现多跳中继

## 消息类型

```
Type 1: Handshake Initiation (握手发起)
Type 2: Handshake Response (握手响应)
Type 3: Cookie Reply (Cookie 响应，用于防 DoS)
Type 4: Transport Data (传输数据)
```

## 握手消息格式

与 WireGuard 相同，不携带 `dst_pubkey`（Noise Session 是点对点的，双方已知对方身份）。

### Handshake Initiation (Type 1)

```
┌─────────────────────────────────────────────────────┐
│ type │ sender_idx │ ephemeral │ static │ timestamp │
│ (1B) │    (4B)    │   (32B)   │ (48B)  │   (28B)   │
└─────────────────────────────────────────────────────┘
```

### Handshake Response (Type 2)

```
┌───────────────────────────────────────────────────────┐
│ type │ sender_idx │ receiver_idx │ ephemeral │ empty │
│ (1B) │    (4B)    │     (4B)     │   (32B)   │ (16B) │
└───────────────────────────────────────────────────────┘
```

## 数据消息格式 (Type 4)

与 WireGuard 相同，不携带 `dst_pubkey`。目标由 Noise Session 隐含确定。

```
┌───────────────────────────────────────────────────────────┐
│ type │ receiver_idx │ counter │ encrypted_payload │  tag  │
│ (1B) │     (4B)     │  (8B)   │       (var)       │ (16B) │
└───────────────────────────────────────────────────────────┘
```

- **receiver_idx (4B)**：接收方的会话索引。
- **counter (8B)**：计数器/nonce，防止重放。
- **encrypted_payload**：ChaCha20-Poly1305 加密的数据。

**注意**：如果需要中继转发（目标不是当前 Session 对端），使用 RELAY 协议。

### Protocol 字段 (在加密 Payload 内)

```
┌─────────────────────────────────────────┐
│  protocol (1B)  │  payload (var)        │
└─────────────────────────────────────────┘
```

#### 传输层协议 (0-63)
与 IP 协议号对应：
- 1 (ICMP): ICMP in ZigNet，去掉 IP header
- 4 (IP): IP in ZigNet，完整 IP 包（翻墙场景）
- 6 (TCP): TCP in ZigNet，去掉 IP header
- 17 (UDP): UDP in ZigNet，去掉 IP header

#### ZigNet 扩展协议 (64-127)
- 64 (KCP): 可靠 UDP 流，用于传输 SOCKS5/HTTP Proxy 的 TCP 流量
- 65 (UDP_PROXY): UDP 代理，不可靠传输 + 目标地址
- 66 (RELAY_0): 中继首跳，发起者 → 第一个中继
- 67 (RELAY_1): 中继中间跳，中继 → 中继
- 68 (RELAY_2): 中继末跳，最后中继 → 目标

#### 应用层协议 (128-255)
- 128 (CHAT): 聊天消息
- 129 (FILE): 文件传输
- 130 (MEDIA): 音视频流
- 131 (SIGNAL): 信令（WebRTC 等）
- 132 (RPC): 远程调用

## KCP 协议 (protocol = 64)

KCP 是可靠的 UDP 传输协议，提供类似 TCP 的可靠性但延迟更低。

```
┌─────────────────────────────────────────┐
│  protocol (1B)  │  KCP packet (var)     │
│      64         │                       │
└─────────────────────────────────────────┘
```

## UDP_PROXY 协议 (protocol = 65)

用于 UDP 代理场景，比 IP 包简单。

```
┌────────────────────────────────────────────────────────────────┐
│ protocol │ atyp │ dst_addr │ dst_port │ udp_data              │
│   65     │ (1B) │  (var)   │   (2B)   │  (var)                │
└────────────────────────────────────────────────────────────────┘
```

**atyp**: 1 = IPv4, 3 = 域名, 4 = IPv6

## IP Header 处理

发送时去掉 IP header（因为 IP 是本地概念，传输没有意义）。
接收端根据 src_pubkey 查本地映射表，重建 IP header，写入虚拟网卡。

## Relay 中继协议

### 设计原则

1. **每跳有独立 Session**：A-C, C-D, D-B 各自有 Noise session
2. **Payload 是端到端加密**：A-B 之间也有 session，中继节点无法解密内容
3. **只传必要信息**：
   - 首跳：发送者隐含（就是当前 session 对端），只需目标
   - 中间跳：需要完整 src/dst 路由信息
   - 末跳：目标隐含（就是当前 session 对端），只需来源

### RELAY_0 (protocol = 66) - 首跳

发起者发给第一个中继节点，只需指定最终目标。

```
┌───────────────────────────────────────────────────┐
│ protocol │ dst_pubkey │         payload           │
│   66     │   (32B)    │   (A-B 端到端加密包)      │
└───────────────────────────────────────────────────┘
```

### RELAY_1 (protocol = 67) - 中间跳

中继节点之间传递，需要完整的 src 和 dst 信息。

```
┌─────────────────────────────────────────────────────────────┐
│ protocol │ src_pubkey │ dst_pubkey │       payload         │
│   67     │   (32B)    │   (32B)    │  (A-B 端到端加密包)   │
└─────────────────────────────────────────────────────────────┘
```

### RELAY_2 (protocol = 68) - 末跳

最后一个中继发给目标，只需指定来源。

```
┌───────────────────────────────────────────────────┐
│ protocol │ src_pubkey │         payload           │
│   68     │   (32B)    │   (A-B 端到端加密包)      │
└───────────────────────────────────────────────────┘
```

### 完整流程示例

hostA 发数据给 hostB，经过 hostC 和 hostD 两个中继：

```
hostA ──[A-C session]──> hostC
        RELAY_0: dst=B, payload=(A-B加密包)

hostC ──[C-D session]──> hostD  
        RELAY_1: src=A, dst=B, payload=(A-B加密包)

hostD ──[D-B session]──> hostB
        RELAY_2: src=A, payload=(A-B加密包)

hostB 收到后：
- 从 RELAY_2 的 src_pubkey 知道是 hostA 发的
- 用 A-B session 解密 payload
```

回复路径：

```
hostB ──[B-D session]──> hostD
        RELAY_0: dst=A, payload=(B-A加密包)
        
hostD ──[D-C session]──> hostC
        RELAY_1: src=B, dst=A, payload=(B-A加密包)
        
hostC ──[C-A session]──> hostA
        RELAY_2: src=B, payload=(B-A加密包)
```

### 中继节点处理逻辑

```
收到 RELAY_0 (dst=X):
    src = 当前 session 对端
    if 我直连 X:
        发送 RELAY_2(src) 给 X
    else:
        查找下一跳 next_hop (可达 X 的中继)
        发送 RELAY_1(src, dst=X) 给 next_hop

收到 RELAY_1 (src=S, dst=X):
    if 我直连 X:
        发送 RELAY_2(src=S) 给 X
    else:
        查找下一跳 next_hop
        发送 RELAY_1(src=S, dst=X) 给 next_hop

收到 RELAY_2 (src=S):
    // 我就是目标
    用 S 的 session 解密 payload
```

### 端到端 Session 建立

A-B 的 Noise 握手也通过中继传递：

```
hostA: 生成 Handshake Initiation (给 B)
hostA ──[RELAY_0: dst=B]──> ... ──> hostB

hostB: 生成 Handshake Response (给 A)  
hostB ──[RELAY_0: dst=A]──> ... ──> hostA

握手完成，A-B session 建立
后续数据用 A-B session 加密，通过 RELAY 传输
```
