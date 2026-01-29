# 程序功能

## 功能概述

1. **虚拟网卡管理**：在本地创建 utun/tun 虚拟网卡，管理 IP 地址和路由。
2. **流量拦截与路由**：从虚拟网卡读取出站 IP 包，根据 Route 规则决定发给哪个 peer。
3. **连接管理**：监听入站连接，根据 Inbound Policy 验证 peer 身份后建立连接。
4. **加密通信**：使用 Noise Protocol 进行端到端加密通信。
5. **Magic DNS**：提供本地 DNS 服务，解析 `.zignet` 域名和翻墙域名。
6. **Admin API**：提供本地 HTTP 管理接口（`admin.zignet`）。

## 平台支持

ZigNet 使用 Zig 语言编写，支持跨平台编译。

| 平台 | TUN 设备 | 创建方式 | 说明 |
|------|---------|---------|------|
| **Linux** | `/dev/net/tun` | `ioctl(TUNSETIFF)` | 标准 Linux 接口 |
| **macOS** | `utun` | `socket(AF_SYSTEM)` | 原生支持，无需驱动 |
| **Windows** | Wintun | `WintunCreateAdapter()` | 高性能用户态驱动 |
| **iOS** | `NEPacketTunnelProvider` | Network Extension | 需要开发者账号 |
| **Android** | `/dev/tun` | `VpnService.Builder` | 标准 Android VPN API |

## 运行模式

### 桌面/服务器模式 (Linux, macOS, Windows)
- 作为后台服务/守护进程运行
- 管理系统路由表和 DNS 设置
- 提供 CLI 工具进行管理

### 移动端模式 (iOS, Android)
- 作为 VPN 应用运行
- 通过系统 VPN 框架接管流量
- 提供图形界面配置


