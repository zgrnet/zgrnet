# Go / Rust / Zig 实现一致性比较

## 1. 消息格式 (Wire Protocol)

### Message Types

| Type | Go | Rust | Zig | 一致 |
|------|-----|------|-----|------|
| Handshake Init | `1` | `1` | `1` | ✅ |
| Handshake Resp | `2` | `2` | `2` | ✅ |
| Cookie Reply | `3` | `3` | `3` | ✅ |
| Transport | `4` | `4` | `4` | ✅ |

### Message Sizes

| Message | Go | Rust | Zig | 一致 |
|---------|-----|------|-----|------|
| Handshake Init | 85 bytes | 85 bytes | 85 bytes | ✅ |
| Handshake Resp | 57 bytes | 57 bytes | 57 bytes | ✅ |
| Transport Header | 13 bytes | 13 bytes | 13 bytes | ✅ |
| Max Packet | 65535 | 65535 | 65535 | ✅ |

### Handshake Init Layout (85 bytes)

```
Offset  Size  Field
0       1     type (0x01)
1       4     sender_index (u32 LE)
5       32    ephemeral public key
37      48    encrypted static (32 + 16 tag)
```

| 字段 | Go | Rust | Zig | 一致 |
|------|-----|------|-----|------|
| type offset | 0 | 0 | 0 | ✅ |
| sender_index | 1-4 | 1-4 | 1-4 | ✅ |
| ephemeral | 5-36 | 5-36 | 5-36 | ✅ |
| static_enc | 37-84 | 37-84 | 37-84 | ✅ |
| endianness | Little | Little | Little | ✅ |

### Handshake Resp Layout (57 bytes)

```
Offset  Size  Field
0       1     type (0x02)
1       4     sender_index (u32 LE)
5       4     receiver_index (u32 LE)
9       32    ephemeral public key
41      16    encrypted empty (0 + 16 tag)
```

| 字段 | Go | Rust | Zig | 一致 |
|------|-----|------|-----|------|
| type offset | 0 | 0 | 0 | ✅ |
| sender_index | 1-4 | 1-4 | 1-4 | ✅ |
| receiver_index | 5-8 | 5-8 | 5-8 | ✅ |
| ephemeral | 9-40 | 9-40 | 9-40 | ✅ |
| empty_enc | 41-56 | 41-56 | 41-56 | ✅ |

### Transport Layout

```
Offset  Size  Field
0       1     type (0x04)
1       4     receiver_index (u32 LE)
5       8     counter (u64 LE)
13      N     ciphertext (payload + 16 tag)
```

| 字段 | Go | Rust | Zig | 一致 |
|------|-----|------|-----|------|
| counter endianness | Little | Little | Little | ✅ |

## 2. Session 配置

### SessionConfig 字段

| 字段 | Go | Rust | Zig | 一致 |
|------|-----|------|-----|------|
| local_index | `uint32` | `u32` | `u32` | ✅ |
| remote_index | `uint32` | `u32` | `u32` | ✅ |
| send_key | `Key [32]byte` | `Key [32]u8` | `Key [32]u8` | ✅ |
| recv_key | `Key [32]byte` | `Key [32]u8` | `Key [32]u8` | ✅ |
| remote_pk | `PublicKey [32]byte` | `Key [32]u8` | `Key [32]u8` | ✅ |

## 3. Handshake Pattern

| 属性 | Go | Rust | Zig | 一致 |
|------|-----|------|-----|------|
| Pattern | IK | IK | IK | ✅ |
| Cipher | ChaCha20-Poly1305 | ChaCha20-Poly1305 | ChaCha20-Poly1305 | ✅ |
| Hash | BLAKE2s | BLAKE2s | BLAKE2s | ✅ |
| DH | Curve25519 | Curve25519 | Curve25519 | ✅ |
| Key Size | 32 bytes | 32 bytes | 32 bytes | ✅ |
| Tag Size | 16 bytes | 16 bytes | 16 bytes | ✅ |
| Hash Size | 32 bytes | 32 bytes | 32 bytes | ✅ |

## 4. Protocol Constants

| 常量 | Go | Rust | Zig | 一致 |
|------|-----|------|-----|------|
| PROTOCOL_ICMP | 1 | 1 | 1 | ✅ |
| PROTOCOL_IP | 4 | 4 | 4 | ✅ |
| PROTOCOL_TCP | 6 | 6 | 6 | ✅ |
| PROTOCOL_UDP | 17 | 17 | 17 | ✅ |
| PROTOCOL_KCP | 64 | 64 | 64 | ✅ |
| PROTOCOL_CHAT | 128 | 128 | 128 | ✅ |
| PROTOCOL_FILE | 129 | 129 | 129 | ✅ |

## 5. Host/PeerManager API

### Host 方法

| 方法 | Go | Rust | Zig | 一致 |
|------|-----|------|-----|------|
| 构造函数 | `NewHost()` | `Host::new()` | `Host.init()` | ✅ |
| 添加Peer | `AddPeer()` | `add_peer()` | `addPeer()` | ✅ |
| 移除Peer | `RemovePeer()` | `remove_peer()` | `removePeer()` | ✅ |
| 连接 | `Connect()` | `connect()` | `connect()` | ✅ |
| 发送 | `Send()` | `send()` | `send()` | ✅ |
| 接收 | `Recv()` | `recv()` | `recvMessage()` | ✅ |
| 关闭 | `Close()` | `close()` | `close()` | ✅ |

### Transport API

| 方法 | Go | Rust | Zig | 一致 |
|------|-----|------|-----|------|
| 发送 | `SendTo()` | `send_to()` | `sendTo()` | ✅ |
| 接收 | `RecvFrom()` | `recv_from()` | `recvFrom()` | ✅ |
| 本地地址 | `LocalAddr()` | `local_addr()` | `localAddr()` | ✅ |
| 关闭 | `Close()` | `close()` | `close()` | ✅ |

## 6. 架构差异

### 并发模型

| 语言 | 模型 | 实现 |
|------|------|------|
| Go | Goroutines | 后台 `receiveLoop` goroutine |
| Rust | Threads + Channels | 后台 `receive_loop` thread + `crossbeam` channel |
| Zig | 同步 | 用户调用 `recvMessage()` 轮询 |

### 内存管理

| 语言 | 模型 |
|------|------|
| Go | GC |
| Rust | 所有权 + Arc |
| Zig | 手动 (allocator) |

## 7. 测试验证

### 跨语言兼容性测试

```bash
# 启动三个 Host（使用相同协议）
./examples/host_test/run.sh

# 输出显示互操作成功:
[go] Connected to rust!
[rust] Connected to go!
[zig] Connected to go!
# ... 所有两两通信成功
```

## 8. 总结

| 类别 | 一致性 |
|------|--------|
| 消息格式 | ✅ 100% |
| 字段布局 | ✅ 100% |
| 字节序 | ✅ 100% (Little Endian) |
| 加密套件 | ✅ 100% |
| 协议常量 | ✅ 100% |
| API 设计 | ✅ 语义一致 |

**结论：三种语言的实现完全兼容，可以互操作。**
