# embed-zig patches

临时补丁，验证通过后提交给 embed-zig 正式合并。

## embed-zig-notify.patch

给 std runtime 加两个东西：

1. **Condition.timedWait** — KcpConn 的 run loop 需要带超时的等待
2. **Notify** — 轻量事件通知原语（Linux eventfd / macOS pipe）

### 为什么需要 Notify

当前 KcpConn 用 Mutex+Condition 做线程间通知：
- signal 端：mutex.lock + cond.signal + mutex.unlock = 3 次 futex syscall
- wait 端：mutex.lock + cond.wait + mutex.unlock = 3 次 futex syscall

Notify 用 eventfd/pipe：
- signal 端：write(fd, 1) = 1 次 syscall
- wait 端：poll(fd, timeout) + read(fd) = 1-2 次 syscall

### 验证方式

1. 修改 KcpConn 的 wake 机制从 Condition 改成 Notify
2. 跑 benchmark 对比
3. 效果好就提交给 embed-zig

### 使用方式

MODULE.bazel 里切到 local_path_override 并指向打过补丁的 embed-zig：

```python
local_path_override(
    module_name = "embed_zig",
    path = "../embed-zig/main",
)
```

或用 git_override + patches（patch 格式要严格匹配）。
