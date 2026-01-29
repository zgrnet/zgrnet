# 路由与规则

ZigNet 的路由系统由三个部分组成：**Rules (规则配置)**、**Magic DNS** 和 **Proxy (翻墙)**。

## 1. 规则配置 (Rules)

配置文件定义了 `peers`, `inbound_policy`, 和 `route`。

### Peers
手动定义的 Peer 列表。也可以通过 `ziglans` 自动获取。

### Inbound Policy
控制谁能连接我、能访问我的什么服务。
- **匹配**：Pubkey 白名单、Solana Token、HTTP API 验证。
- **动作**：Allow / Deny。

### Outbound Route
控制哪些域名进入 ZigNet，以及发给哪个 Peer。

```yaml
route:
  rules:
    - domain: "*.google.com"
      peer: peer_us
    - domain: "*.company.internal"
      peer: peer_vpn
```

## 2. Magic DNS

Magic DNS 负责将域名解析为 ZigNet 内部 IP (Fake IP)。

- **`{pubkey}.zignet`**：解析为对应 Peer 的本地 IP。
- **匹配 Route 规则的域名**：转发 DNS 请求给对应 Peer，获取 Fake IP。
- **其他域名**：透传给上游 DNS。

## 3. Proxy (翻墙/出口)

当 Magic DNS 将域名解析为 Fake IP 后，流量进入 ZigNet。

### 三种代理模式

| 模式 | 协议 | 特点 | 适用场景 |
|------|------|------|----------|
| **TUN 模式** | IP (4) | 透明代理，需 TPROXY | 全局代理 |
| **TCP 代理** | KCP (64) | SOCKS5 over KCP | 应用级代理 |
| **UDP 代理** | UDP_PROXY (65) | 简单封装 | 游戏、DNS |

### TUN 模式流程 (IP Forwarding)

1. **DNS**：Magic DNS 请求 PeerB 解析 `google.com`，PeerB 返回 Fake IPv6。
2. **传输**：HostA 发送目的为 Fake IPv6 的包给 PeerB。
3. **Exit**：PeerB 收到包，通过 TPROXY/REDIRECT 劫持，查表还原域名，发起真实连接。

### 优势
- **无 DNS 污染**：DNS 解析在远端 (PeerB) 完成。
- **无 TCP over TCP**：使用 IP 转发或 KCP 传输。

