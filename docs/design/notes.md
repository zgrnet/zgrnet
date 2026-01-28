# ZigNet 设计笔记

> 讨论日期: 2026-01-07

## 目录

1. [背景知识](#背景知识)
2. [虚拟局域网架构](#虚拟局域网架构)
3. [用户态 TCP/IP 协议栈](#用户态-tcpip-协议栈)
4. [WireGuard 实现方案](#wireguard-实现方案)
5. [用户态 NAT 方案](#用户态-nat-方案)
6. [ZigNet 核心设计](#zignet-核心设计)
7. [公钥身份网络](#公钥身份网络)

---

## 背景知识

### eBPF

- **eBPF 是 Linux 特有的技术**，macOS 只有传统 BPF（用于包过滤）
- eBPF 可以在内核态运行，修改网络包（原地修改、变大、变小）
- 用 C 语言编写，编译成 eBPF 字节码
- 主要 API：
  - XDP: `bpf_xdp_adjust_head/tail`
  - TC: `bpf_skb_adjust_room`, `bpf_skb_store_bytes`
- 适合做简单混淆，不适合做复杂协议伪装（TLS/WebSocket）
- 可配合内核 WireGuard 做包混淆（加随机前缀等）

### 各平台 TUN 接口

| 平台 | TUN 设备 | 创建方式 |
|------|---------|---------|
| Linux | `/dev/net/tun` | `ioctl(TUNSETIFF)` |
| macOS | `utun` | `socket(AF_SYSTEM)` |
| Windows | Wintun | `WintunCreateAdapter()` |
| iOS | `NEPacketTunnelProvider` | Network Extension |
| Android | `/dev/tun` | `VpnService.Builder` |

---

## 虚拟局域网架构

### 整体架构

```
┌─────────────────┐                    ┌─────────────────┐
│     Peer A      │                    │     Peer B      │
│                 │                    │                 │
│  App ──► utun   │                    │    utun ──► App │
│          │      │                    │      ▲          │
│          ▼      │                    │      │          │
│    IP packet    │                    │   IP packet     │
│          │      │                    │      ▲          │
│          ▼      │                    │      │          │
│  WireGuard 加密  │ ═══════════════════►  WireGuard 解密 │
│          │      │    UDP 隧道        │      ▲          │
│          ▼      │                    │      │          │
│     UDP socket  │                    │  UDP socket     │
└─────────────────┘                    └─────────────────┘
```

### 何时需要用户态 TCP 栈

| 场景 | 需要 lwIP? | 原因 |
|------|-----------|------|
| 纯 IP 隧道（WireGuard 模式） | ❌ | IP 包原样传到对端 |
| iOS Network Extension | ✅ | 没有 raw socket 权限 |
| Linux/macOS 透明代理 | 可选 | 可用 TPROXY/NAT 替代 |
| 翻墙/协议伪装 | ✅ | 需要解析 TCP 流 |

---

## 用户态 TCP/IP 协议栈

### 协议栈对比

| 协议栈 | 语言 | 性能 | 功能完整度 | 适用场景 |
|--------|------|------|-----------|---------|
| **gVisor netstack** | Go | 🥇 高 | 🥇 最完整 | Go 项目、翻墙 |
| **lwIP** | C | 🥇 高 | 🥈 完整 | 嵌入式、iOS |
| **smoltcp** | Rust | 🥈 中高 | 🥉 基本 | Rust 项目 |
| **picoTCP** | C | 🥈 中高 | 🥈 完整 | 需要定制 |
| **FreeRTOS+TCP** | C | 🥈 中高 | 🥈 完整 | FreeRTOS |
| **uIP** | C | 低 | 基本 | 极度资源受限 |

### lwIP vs Linux 内核

- **性能差距主要是硬件**，不是 lwIP 本身的问题
- lwIP 设计目标是嵌入式，资源占用极小（~40KB RAM）
- 对于 IoT 场景（~10-20 Mbps），lwIP 完全够用

### gVisor netstack 为什么比 smoltcp 快

不是语言问题，是**工程投入**差距：
- Google 数十人团队 vs 社区少数维护者
- 完整 TCP 实现（SACK、DSACK、TLP、RACK）vs 简化实现
- 代码量：netstack ~150K 行 vs smoltcp ~15K 行
- 丢包场景差距最明显（SACK 快速恢复）

---

## WireGuard 实现方案

### 各平台 WireGuard 实现

| 平台 | 实现 | 类型 | 性能 |
|------|------|------|------|
| Linux 5.6+ | 内核模块 | 内核态 | ~3-4 Gbps |
| FreeBSD 13+ | 内核模块 | 内核态 | ~2-3 Gbps |
| Windows | wireguard-nt | 内核驱动 | ~2-3 Gbps |
| macOS | wireguard-go | 用户态 | ~800 Mbps |
| iOS | wireguard-go | 用户态 | ~500-800 Mbps |

### C 语言 WireGuard 实现

- **wireguard-lwip**: 纯 C，用户态，集成 lwIP
- **boringtun**: Rust (Cloudflare)，可编译为 C 库
- 核心依赖：Curve25519、ChaCha20-Poly1305、BLAKE2s
- 可用加密库：libsodium、mbedTLS、monocypher

### 单 Interface 多 Peer

WireGuard 支持单个 interface 连接多个 peer：
- 通过 AllowedIPs 区分不同 peer
- Tailscale 就是这么做的
- 理论上支持数万 peer（取决于内存）

---

## 用户态 NAT 方案

### 方案概述

不使用 lwIP，而是通过 NAT 把包回环到本机，让内核处理 TCP：

```
App 发起连接 1.2.3.4:80
    │
    ▼
utun 读取 IP packet
    │
    ▼
用户态 NAT: 改 dst → 127.0.0.1:8888
    │
    ▼
写回 utun
    │
    ▼
内核路由到 localhost
    │
    ▼
用户态程序监听 127.0.0.1:8888
查 NAT 表得到原始目标 → 转发
```

### 单端口 + 5元组区分

- NAT 只改 dst，保持 src 不变
- 内核用完整 5 元组区分连接
- 通过 `getpeername()` 获取 src，查表得到原始 dst
- 优势：不用管理端口分配，不会端口耗尽

### 性能分析

| 方案 | 吞吐量 | 系统调用 | 跨平台 |
|------|--------|---------|--------|
| 内核 TPROXY | ~800-900 Mbps | 少 | ❌ Linux only |
| 用户态 NAT | ~400-600 Mbps | 多 | ✅ 全平台 |
| lwIP | ~300-500 Mbps | 中等 | ✅ 全平台 |

**优化关键点**：
- 增量校验和更新（15-20x 提升）
- 高效哈希表
- 内存池

**优势**：
- TCP 由内核处理，丢包恢复更好
- 跨平台统一代码
- 日常使用（100-500 Mbps）完全够用

---

## ZigNet 核心设计

### 设计目标

1. **用户态 WireGuard 实现**
2. **动态 Peer 验证**（不需要预配置所有 peer）
3. **链上身份验证**（Solana）
4. **可插拔策略引擎**

### 与内核 WireGuard 的区别

| 对比 | 内核 WireGuard | 用户态 ZigNet |
|------|--------------|-------------|
| Peer 管理 | 静态配置 | 动态验证 |
| 规模 | ~1万 peer | 理论无限 |
| 验证方式 | 预配置公钥 | 链上/策略验证 |
| 扩展性 | 需改内核 | 灵活可扩展 |

### Magic DNS

```
浏览器访问 http://abc123.zignet/
    │
    ▼
Magic DNS 解析: abc123.zignet → 100.64.1.2
    │
    ▼
路由: 100.64.0.0/16 → zig0
    │
    ▼
WireGuard: 100.64.1.2 → Peer abc123 → 加密发送
```

### IP 地址分配策略

1. **从 pubkey 派生**：`hash(pubkey)[0:4]` → 确定性，但可能冲突
2. **本地动态分配**：无冲突，但各节点视图不同
3. **IPv6（推荐）**：地址空间够大，直接用 pubkey 派生

### 策略引擎

```yaml
policies:
  # 白名单文件
  - type: file
    path: ~/.zignet/allowed_peers.txt
    action_if_match: allow
    
  # Solana Token 检查
  - type: solana
    check: token_balance
    token_mint: "ZIGNET..."
    min_balance: 100
    action_if_match: allow
    
  # 自定义脚本
  - type: script
    command: ~/.zignet/verify.sh
    
default_action: deny
```

### Solana 集成

- WireGuard pubkey (X25519) 可与 Solana pubkey (Ed25519) 转换
- 验证方式：
  - SOL 余额门槛
  - 特定 Token 持有
  - NFT 会员
  - 链上白名单合约
- 延迟优化：本地缓存 + 预同步 + 乐观验证

---

## 公钥身份网络

### 核心理念

**从 IP 中心转向公钥身份中心**

```
传统网络：
  身份 = IP 地址（由 ISP/DHCP 分配，会变化，可被追踪）
  连接: "我要连接 93.184.216.34"
  验证: 无法确定对方身份

公钥网络（ZigNet）：
  身份 = 公钥（用户自己生成，永不变化，密码学可验证）
  连接: "我要连接 abc123.zignet"
  验证: 密码学保证对方就是 abc123
```

### 与现有系统对比

| 系统 | 身份系统 | 寻址方式 | 验证方式 |
|------|---------|---------|---------|
| 传统互联网 | IP | IP + DNS | 无/TLS证书 |
| Tor | 公钥 | .onion | 公钥派生 |
| IPFS | CID | /ipfs/Qm... | 内容哈希 |
| ENS | 公钥 | alice.eth | 链上绑定 |
| **ZigNet** | 公钥 | {pk}.zignet | Noise 握手 |

### 网络独立性

1. **不依赖 IP 分配**：不需要公网 IP、固定 IP，NAT 后也能访问
2. **不依赖 DNS 系统**：不受 DNS 审查/污染
3. **不依赖特定传输层**：UDP/TCP/WebSocket/中继 都可以
4. **身份可移植**：换设备/网络/国家，身份不变

### 本地 IP 只是"视图"

```
节点 A 的视图:
  abc123.zignet → 100.64.1.2

节点 B 的视图:
  abc123.zignet → 100.64.2.5  ← 不同的 IP！

完全 OK！因为：
- IP 只是本地路由的需要
- 真正的身份是公钥
- 跨节点通信用公钥，不用 IP
```

### 核心价值

1. **真正的点对点**：无 DNS 注册商、无 IP 分配机构
2. **抗审查**：公钥无法被"没收"或"封禁"
3. **自主身份**：身份由私钥控制，不是平台授予
4. **可验证**：密码学保证对方身份，比 TLS 证书更根本
5. **无边界**：没有地理概念，没有"内网/外网"

---

## 技术选型建议

### 语言选择

- **Zig + C**：可以直接使用 C 的 wireguard-lwip
- **Go**：可以用 gVisor netstack（最成熟）
- **Rust**：可以用 smoltcp 或 boringtun

### 构建系统

- Bazel 支持多语言混合构建
- Zig 可以零开销调用 C 代码

### 推荐架构

```
┌─────────────────────────────────────────────────────────────┐
│                     ZigNet 架构                              │
│                                                             │
│   应用层: Magic DNS + Policy Engine                         │
│                       │                                     │
│   身份层: 公钥寻址 + Solana 验证                              │
│                       │                                     │
│   协议层: WireGuard (wireguard-lwip 或自实现)                │
│                       │                                     │
│   传输层: UDP / TCP / WebSocket / Relay                     │
│                       │                                     │
│   接口层: TUN (各平台适配)                                    │
└─────────────────────────────────────────────────────────────┘
```

---

## 下一步

- [ ] 搭建 Zig + Bazel 项目结构
- [ ] 集成 wireguard-lwip 或实现核心协议
- [ ] 实现 Magic DNS 组件
- [ ] 实现策略引擎
- [ ] Solana 验证集成
- [ ] 跨平台 TUN 适配层

---

## 后续讨论补充 (2026-01-07)

### 中继问题

标准 WireGuard 的限制：

1. **DERP 无法认证身份**：DERP 只是转发加密包，不知道发送者是谁，任何人都可以伪装发送垃圾数据
2. **WG Relay 的问题**：relay 节点可以看到传输内容（因为要解密再加密）；relay 后公钥变成了 relay 节点的 key

### 改进的协议设计

不再使用标准 WireGuard 协议，而是基于 Noise Protocol 改进：

**包头增加 dst_pubkey（明文）**：用于中继路由，中继节点只看 dst_pubkey 转发，不解密内容

**去掉 IP header**：因为 IP 是本地概念，传输 IP header 没有意义。接收端根据 src_pubkey 查本地映射表重建 IP header

**protocol 字段**：
- TCP in ZigNet (6)：去掉 IP header 的 TCP 包
- UDP in ZigNet (17)：去掉 IP header 的 UDP 包  
- ICMP in ZigNet (1)：去掉 IP header 的 ICMP 包
- IP in ZigNet (4)：完整 IP 包（用于翻墙场景）

### 中继链路

支持多跳中继：`A → C → D → B`

包格式：外层明文 dst_pubkey + 签名（可选）；内层 Noise 加密数据

中继节点只看 dst_pubkey 做路由，无法解密内容

上行和下行可以是不同路径（非对称路由）

### ZigNet 生态系统

**服务节点**：
- 某些节点开启 ip_forward，支持 IP-in-ZigNet（proto=4），作为翻墙出口
- 某些节点提供 relay 服务，帮助 NAT 穿透
- 某些节点运行高速网络，提供优化路由

**去中心化**：
- 企业可以搭建自己的高速网络
- 配置允许访问的 pubkey
- 不存在特殊的 "exit node" 类型，只是配置不同

### 双规则系统

**Inbound Policy（入站策略）**：
- 控制谁能连接我、能访问我的什么服务
- 验证方式：公钥白名单、文本文件、链上 Token/NFT、数据库、自定义脚本
- 可以限制协议和端口
- 定期检查连接合法性

**Outbound Route（出站路由）**：
- 控制本机哪些流量进入 ZigNet，以及发给哪个 peer
- Magic DNS 配置：哪些域名解析为 Fake IP 进入 ZigNet
- Route 规则：`*.youtube.com → peer_us`；`142.250.0.0/16 → peer_us`

### 安全策略

**禁止 peer-to-peer 中转**：收到 IP-in-ZigNet 后，只能通过系统 ip_forward 转发到真实互联网，不能重新封装发给其他 ZigNet peer

原因：防止被用作跳板攻击；防止滥用带宽；保证来源可追溯

### ziglan 概念

**ziglan** 是 ZigNet 上的一个"局域网"或组织网络：
- 有公网可达的入口点（域名/IP）
- 帮助成员互相发现（类似目录服务）
- 帮助 NAT 穿透（中继加密包，不解密）
- 可以有自己的准入策略

一个 Host 可以同时加入多个 ziglan

ziglan 本身也是一个 ZigNet 节点，只是提供了额外的发现和中继服务

### 翻墙设计

**DNS 处理**：
- Magic DNS 只负责 `.zignet` 域名和配置的 Fake IP 域名
- 普通 DNS 查询不经过 ZigNet
- 不解决 DNS 污染问题，用户可以配合 Clash/Surge 等工具

**分域名 DNS**（macOS）：
```bash
# /etc/resolver/zignet
nameserver 127.0.0.1
port 53530
# 只有 *.zignet 走这个 DNS
```

**iOS 限制**：没有 /etc/resolver，只能通过 NEPacketTunnelProvider 配置 DNS

**Sniff 方式**：
- TLS 流量从 ClientHello 的 SNI 字段提取域名
- HTTP 流量从 Host 头提取域名
- 局限：只对 HTTPS/HTTP/QUIC 有效，其他协议无法提取域名

**简化方案**：
- 全局代理 + 多出口
- 所有流量都进 ZigNet
- 根据 Sniff 结果或 IP 规则发给不同的 peer

### Admin API

通过 `admin.zignet` 访问本地 ZigNet 管理 API：
- `GET /api/identity?ip=x.x.x.x` → 查询某个本地 IP 对应的公钥
- `GET /api/identity?pubkey=xxx` → 查询某个公钥的本地 IP 和在线状态
- `GET /api/whoami` → 查询自己的公钥和 IP
- `GET /api/contacts` → 获取通讯录
- `GET /api/peers` → 获取已连接的 peer 列表
- `GET /api/policy/check?pubkey=xxx` → 检查某个公钥是否允许连接

任何语言的程序都可以通过 HTTP 调用这些 API，获取 ZigNet 身份信息

### 个人网络体验

**通讯录**：基于 pubkey 的联系人列表

**个人服务**：
- 本地开 HTTP 服务监听 zignet 接口
- 朋友通过 `myserver.zignet` 访问
- 无需公网 IP、无需备案

### IP 地址模型

**IP 是本地概念，不是全网概念**

每个 Host 给连接的 peer 动态分配本地 IP

不同 Host 看到的同一个 peer 的 IP 可以不同

用户不需要关心 IP，只需要用 `{pubkey}.zignet` 访问

---

## ZigNet 完整设计画像

### 核心概念定义

**ZigNet** 是一个基于公钥身份的去中心化网络层。所有 ZigNet 节点理论上可以互联。公钥是唯一的全网身份标识。

**ziglan** 是 ZigNet 上的一个"局域网"或组织网络。它有公网可达的入口点（域名/IP），帮助成员互相发现和 NAT 穿透。一个 ziglan 可以是公司网络、朋友圈、社区等。节点可以同时加入多个 ziglan。ziglan 本身也是一个 ZigNet 节点，只是提供了额外的发现和中继服务。

**Host** 是运行 ZigNet 程序的设备。每个 Host 有唯一的公钥身份。Host 在本地创建一个 utun/tun 虚拟网卡。

**Peer** 是相对概念，指从某个 Host 角度看，其他可连接的节点。A 是 B 的 peer，B 也是 A 的 peer。

### 身份与地址

身份 = 公钥。使用 Ed25519/X25519 密钥对。公钥全网唯一，不需要注册，自己生成。公钥同时可作为 Solana 钱包地址，用于链上身份验证。

IP 是本地概念，不是全网概念。每个 Host 给连接的 peer 动态分配本地 IP。不同 Host 看到的同一个 peer 的 IP 可以不同。用户不需要关心 IP，只需要用 `{pubkey}.zignet` 访问。

域名：`{pubkey}.zignet`，由本地 Magic DNS 解析。用户通过域名访问 peer，不需要知道 IP。

### ZigNet 程序功能

zignet 是一个用户态程序。

zignet 在本地创建一个 utun/tun 虚拟网卡。

zignet 从 utun 读取出站 IP 包，根据 Route 规则，决定发给哪个 peer。

zignet 监听入站连接（UDP socket 等），根据 Inbound Policy 验证 peer 身份后建立连接。

zignet 使用类似 WireGuard 的 Noise Protocol 进行加密通信。

zignet 提供本地 Magic DNS 服务，解析 `.zignet` 域名，以及将配置的域名解析为 Fake IP 引入 ZigNet。

zignet 提供本地 Admin API（`admin.zignet`），供其他程序查询身份、策略等信息。

### 连接方式

Peer 可以有多种访问方式：Direct（直连）和 Relay（通过 ziglan 中继）。

**主动连接**：Host 主动添加 peer，配置其公钥和到达方式（直连地址或通过某个 ziglan）。

**被动连接**：peer 主动连接 Host，Host 根据 Inbound Policy 决定是否接受。

**回复路由**：响应包通过最近一次收到请求的路径返回。上行和下行可以是不同路径（非对称路由）。

**通过 ziglan 发现 peer**：配置 ziglan 地址后，可以通过 ziglan 查询某个公钥的当前位置并建立连接。一个 Host 可以加入多个 ziglan。找一个 peer 时，可以指定通过哪个 ziglan 去找。

### 节点能力

节点能力由配置决定，没有固定的"类型"。

**默认能力**：收发 ZigNet 流量，提供本地服务，连接其他 peer。

**开启 ip_forward（系统配置）**：可以将收到的 IP-in-ZigNet 包通过系统 NAT 转发到真实互联网。这就是所谓的"翻墙出口"能力，但只是配置不同，不是特殊节点类型。

**开启 relay（ziglan 能力）**：允许转发 ZigNet 包给其他 peer，帮助 NAT 穿透。转发的是加密包，不解密。

### 使用场景

**内网通信**：公司/团队成员互联，通过 ziglan 加入公司网络，访问 `server.zignet` 等内部服务。

**个人服务**：在家里开一个 HTTP 服务监听 zignet 接口，朋友通过 `myserver.zignet` 访问，无需公网 IP、无需备案。

**翻墙**：配置某些域名走 ZigNet，由海外节点（开启 ip_forward）转发到真实互联网。

**游戏联机**：开一个游戏服务器监听 zignet 接口，朋友直接连接 `gamehost.zignet`，无需 Hamachi。

**通讯录**：基于公钥的联系人列表，可以看到朋友的在线状态和提供的服务。

### 技术选型

语言：Zig + C（可直接使用 WireGuard 相关的 C 代码）

构建：Bazel

加密库：libsodium 或 monocypher

平台支持：Linux（tun）、macOS（utun）、Windows（Wintun）、iOS（NEPacketTunnelProvider）、Android（VpnService）

### 下一步 TODO

- 搭建 Zig + Bazel 项目结构
- 实现核心 Noise Protocol 加密
- 实现 TUN 跨平台适配层
- 实现 Magic DNS 组件
- 实现 Inbound Policy 引擎
- 实现 Outbound Route 引擎
- 实现 ziglan 中继协议
- 实现 Admin API

