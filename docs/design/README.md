# zgrnet 设计文档

> zgrnet = Zig + Go + Rust Network Library
>
> 一个基于 Noise Protocol 的去中心化安全网络

## 目录

### 1. 基础 (Basics)
- [00-overview.md](00-overview.md) - 概述
- [01-architecture.md](01-architecture.md) - 架构核心概念 (ZigNet, ziglan, Host, Peer)
- [02-program.md](02-program.md) - 程序功能与平台支持

### 2. 连接与通信 (Connectivity)
- [03-protocol.md](03-protocol.md) - 协议设计 (Packet Format, Protocols)
- [04-connection.md](04-connection.md) - 连接建立 (Direct, Relay)
- [05-relay.md](05-relay.md) - 中继与 ziglan
- [06-broadcast.md](06-broadcast.md) - 广播机制

### 3. 功能与应用 (Features)
- [07-routing.md](07-routing.md) - 路由系统 (Rules, Magic DNS, Proxy)
- [08-config.yaml](08-config.yaml) - 完整配置示例
- [09-security.md](09-security.md) - 安全策略
- [10-obfuscation.md](10-obfuscation.md) - 流量伪装
- [11-admin-api.md](11-admin-api.md) - 管理 API

### 4. 其他 (Meta)
- [12-use-cases.md](12-use-cases.md) - 使用场景
- [13-roadmap.md](13-roadmap.md) - 开发计划与技术栈

## 其他文档
- [notes.md](notes.md) - 原始讨论笔记
