//! Async I/O Primitives
//!
//! This module defines abstractions for asynchronous I/O operations.
//! Platform implementations (kqueue, epoll, etc.) implement these interfaces.
//!
//! ## Required Interface (comptime)
//!
//! Any type implementing IOService must have:
//! - `registerRead(self: *T, fd: fd_t, callback: ReadyCallback) void`
//! - `registerWrite(self: *T, fd: fd_t, callback: ReadyCallback) void`
//! - `unregister(self: *T, fd: fd_t) void`
//! - `poll(self: *T, timeout_ms: i32) usize`
//! - `wake(self: *T) void` — interrupt a blocking poll()
//!
//! ## Usage Example
//!
//! ```zig
//! // Platform provides IOService implementation
//! var io_service = os.KqueueIO.init();
//!
//! // Register for read readiness
//! io_service.registerRead(socket_fd, .{
//!     .ptr = @ptrCast(&my_handler),
//!     .callback = onReadReady,
//! });
//!
//! // Poll for events
//! while (running) {
//!     const count = io_service.poll(100);  // 100ms timeout
//!     // Callbacks are invoked for ready fds
//! }
//! ```

const std = @import("std");
const posix = std.posix;

/// Callback invoked when a file descriptor is ready for I/O.
pub const ReadyCallback = struct {
    /// Opaque pointer to callback context
    ptr: ?*anyopaque,
    /// Callback function
    callback: *const fn (ptr: ?*anyopaque, fd: posix.fd_t) void,

    /// Invoke the callback.
    pub fn call(self: ReadyCallback, fd: posix.fd_t) void {
        self.callback(self.ptr, fd);
    }

    /// A no-op callback.
    pub const noop: ReadyCallback = .{
        .ptr = null,
        .callback = struct {
            fn cb(_: ?*anyopaque, _: posix.fd_t) void {}
        }.cb,
    };
};

/// Interest flags for I/O registration.
pub const Interest = packed struct {
    read: bool = false,
    write: bool = false,

    pub const READ: Interest = .{ .read = true };
    pub const WRITE: Interest = .{ .write = true };
    pub const READ_WRITE: Interest = .{ .read = true, .write = true };
};

/// Registration entry for tracking callbacks.
pub const Registration = struct {
    fd: posix.fd_t,
    interest: Interest,
    read_callback: ReadyCallback,
    write_callback: ReadyCallback,
};

// ============================================================================
// IOService Runtime Interface (vtable-based)
// ============================================================================

/// IOService - Runtime polymorphic I/O service interface.
///
/// Use this when you need to store I/O services of different types in the same
/// variable. For comptime polymorphism, use implementations directly.
pub const IOService = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        register_read: *const fn (ptr: *anyopaque, fd: posix.fd_t, callback: ReadyCallback) void,
        register_write: *const fn (ptr: *anyopaque, fd: posix.fd_t, callback: ReadyCallback) void,
        unregister: *const fn (ptr: *anyopaque, fd: posix.fd_t) void,
        poll: *const fn (ptr: *anyopaque, timeout_ms: i32) usize,
        wake: *const fn (ptr: *anyopaque) void,
    };

    pub fn registerRead(self: IOService, fd: posix.fd_t, callback: ReadyCallback) void {
        self.vtable.register_read(self.ptr, fd, callback);
    }

    pub fn registerWrite(self: IOService, fd: posix.fd_t, callback: ReadyCallback) void {
        self.vtable.register_write(self.ptr, fd, callback);
    }

    pub fn unregister(self: IOService, fd: posix.fd_t) void {
        self.vtable.unregister(self.ptr, fd);
    }

    pub fn poll(self: IOService, timeout_ms: i32) usize {
        return self.vtable.poll(self.ptr, timeout_ms);
    }

    /// Interrupt a blocking poll() call from another thread.
    pub fn wake(self: IOService) void {
        self.vtable.wake(self.ptr);
    }
};

// ============================================================================
// Tests
// ============================================================================

test "ReadyCallback invocation" {
    var called = false;
    var called_fd: posix.fd_t = -1;

    const Context = struct {
        called: *bool,
        called_fd: *posix.fd_t,
    };

    var ctx = Context{
        .called = &called,
        .called_fd = &called_fd,
    };

    const callback = ReadyCallback{
        .ptr = @ptrCast(&ctx),
        .callback = struct {
            fn cb(ptr: ?*anyopaque, fd: posix.fd_t) void {
                const c: *Context = @ptrCast(@alignCast(ptr.?));
                c.called.* = true;
                c.called_fd.* = fd;
            }
        }.cb,
    };

    callback.call(42);

    try std.testing.expect(called);
    try std.testing.expectEqual(@as(posix.fd_t, 42), called_fd);
}

test "ReadyCallback.noop" {
    // Should not crash
    ReadyCallback.noop.call(0);
}

test "Interest flags" {
    const read_only = Interest.READ;
    try std.testing.expect(read_only.read);
    try std.testing.expect(!read_only.write);

    const write_only = Interest.WRITE;
    try std.testing.expect(!write_only.read);
    try std.testing.expect(write_only.write);

    const both = Interest.READ_WRITE;
    try std.testing.expect(both.read);
    try std.testing.expect(both.write);
}
