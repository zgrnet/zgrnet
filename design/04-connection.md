# 连接建立

## 连接方式

### Direct（直连）
两个节点直接通过 UDP 通信。需要至少一方有公网 IP 或能完成 NAT 穿透（STUN/Hole punching）。

### Relay（中继）
通过 ziglan 中继连接。中继节点转发加密包，不解密内容。当直连不可行时使用。

## 连接流程

1. **查找 Peer**：
   - 检查本地配置（`peers`）
   - 通过 ziglan 查询（如果加入了 ziglan）

2. **建立握手**：
   - 发送 `Handshake Initiation`
   - 接收 `Handshake Response`
   - 派生会话密钥

3. **路由选择**：
   - 如果直连成功，优先使用直连路径
   - 如果直连失败，回退到 Relay 路径

## 主动与被动

- **主动连接**：Host 主动添加 peer，配置其公钥和到达方式。
- **被动连接**：peer 主动连接 Host，Host 根据 Inbound Policy 决定是否接受。

## 回复路由

响应包通过最近一次收到请求的路径返回。上行和下行可以是不同路径（非对称路由）。
