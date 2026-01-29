# 安全策略

## 基本原则

### 1. Host 可以向任何 Peer 发送数据
Host 是可信的，可以向任何 Peer 发送单播或广播数据。

### 2. Peer 数据进入 Host Network 后不能再回到 ZigNet
防止流量中转攻击。

```
Peer -> ZigNet -> Host Network (TUN) -> ❌ ZigNet
```

如果从 TUN 读到的包，Src IP 不是 Host 自己的 IP，说明是 Peer 发来的包被转发了，必须丢弃。

### 3. Relay 转发是合法的
Relay 包**不经过** Host Network (TUN)，直接在 ZigNet 层转发。

```
PeerA -> ZigNet (dst_pubkey != Self) -> PeerB
```

这是合法的，因为 ZigNet 只是充当路由器，不解密内容。

## 流量合法性矩阵

| 流量方向 | 合法 | 说明 |
|---------|------|------|
| Host → Peer (单播) | ✅ | Host 主动发送 |
| Host → All Peers (广播) | ✅ | Host 广播 |
| Peer → Host (本机服务) | ✅ | 访问 Host 服务 |
| Peer → Exit (翻墙) | ✅ | IP 转发到真实互联网 |
| Peer → Peer (Relay) | ✅ | 不经过 Host Network |
| Peer → Host → Peer | ❌ | 进入 Host Network 后不能再出去 |
| Peer → Broadcast | ❌ | Peer 不能广播 |

