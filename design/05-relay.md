# 中继与 ziglan

## 概述

ziglan 是 ZigNet 的一个**可插拔**的扩展系统，提供设备发现、NAT 穿透和中继服务。

## 中继原理

当 peerA 想访问 peerB，但无法直连时：

```
1. peerA 查看 peerB 的 access_points: [AP1, AP2]

2. peerA 向 AP1 发送请求：
   ┌─────────────────────────────────────────────┐
   │ dst_pubkey = peerB │ encrypted ZigNet packet │
   └─────────────────────────────────────────────┘

3. AP1 看到 dst_pubkey = peerB
   - AP1 查找 peerB 是否在线
   - AP1 转发包给 peerB

4. peerB 收到包，解密，处理
```

### 端到端加密
中继节点（AP）只能看到 `dst_pubkey`，无法解密内容。即使经过多个中继节点，A 和 B 之间的加密通道保持完整。

## ziglan 托管模式

设备可以选择完全托管给 ziglan，无需手动配置 peer 和路由：

```
1. 设备连接到 ziglan
2. 从 ziglan 拉取可访问的 peer 列表
3. ZigNet 自动：
   - 为每个 peer 分配 local IP
   - 配置好 access_points (中继节点)
   - 设置 route 规则
4. 设备直接访问 peer
```

## 多 ziglan 支持

设备可以同时加入多个 ziglan。不同 ziglan 引入的 peer 使用不同的域名空间：

```
{ziglan_name}.{pubkey}.zignet
```

**示例**：
- `company.server-a.zignet`
- `friends.bob-laptop.zignet`

## 去中心化

ziglan 可以是中心化的（HTTP API），也可以是去中心化的（DHT/区块链），取决于具体实现。

