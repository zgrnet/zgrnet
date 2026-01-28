# Admin API

通过 `admin.zignet` (127.0.0.1) 访问本地 ZigNet 管理 API。

## 接口列表

```
GET /api/whoami
→ 查询自己的公钥和 IP

GET /api/identity?ip=x.x.x.x
→ 查询某个本地 IP 对应的公钥

GET /api/identity?pubkey=xxx
→ 查询某个公钥的本地 IP 和在线状态

GET /api/contacts
→ 获取通讯录

GET /api/peers
→ 获取已连接的 peer 列表

GET /api/policy/check?pubkey=xxx
→ 检查某个公钥是否允许连接
```

任何语言的程序都可以通过 HTTP 调用这些 API，获取 ZigNet 身份信息，不需要特殊 SDK。

