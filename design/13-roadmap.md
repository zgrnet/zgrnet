# 开发计划与技术栈

## 技术栈

- **语言**：Zig + C (wireguard-lwip)
- **构建**：Bazel
- **加密**：libsodium / monocypher (Curve25519, ChaCha20-Poly1305, BLAKE2s)
- **TUN**：各平台原生 API

## 开发路线图 (Roadmap)

1. **基础架构**
   - [ ] 搭建 Zig + Bazel 项目结构
   - [ ] 实现核心 Noise Protocol 加密
   - [ ] 实现 TUN 跨平台适配层

2. **核心功能**
   - [ ] 实现 Magic DNS 组件
   - [ ] 实现 Inbound Policy 引擎
   - [ ] 实现 Route 引擎

3. **网络增强**
   - [ ] 实现 ziglan 中继协议
   - [ ] 实现 Admin API
   - [ ] 实现流量伪装 (Obfuscation)

4. **高级特性**
   - [ ] Solana 验证集成
   - [ ] 移动端适配

