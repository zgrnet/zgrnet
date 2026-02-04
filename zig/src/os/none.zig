//! No-op implementation of OS primitives.
//!
//! Zero-overhead primitives for:
//! - Single-threaded environments
//! - Embedded systems (FreeRTOS single-task)
//! - WASM (no threads)
//! - Cooperative multitasking
//!
//! Usage:
//! ```zig
//! const None = os.None(allocator);
//! var chan = try None.Channel(u32).init(16);
//! ```

const std = @import("std");
const posix = std.posix;
const Allocator = std.mem.Allocator;

const async_io = @import("../async/io.zig");
const ReadyCallback = async_io.ReadyCallback;

// ============================================================================
// BusyPollIO - Fallback IOService using select/poll
// ============================================================================

/// Busy-poll based I/O service - fallback for platforms without kqueue/epoll.
///
/// This implementation uses `select()` with a short timeout for basic I/O
/// multiplexing. Less efficient than kqueue/epoll but works everywhere.
///
/// ## Direct Usage (comptime, zero overhead)
/// ```zig
/// var io = BusyPollIO.init(allocator);
/// defer io.deinit();
///
/// io.registerRead(socket_fd, .{ .ptr = ctx, .callback = onReady });
///
/// while (running) {
///     _ = io.poll(100);
/// }
/// ```
pub const BusyPollIO = struct {
    const Self = @This();
    const max_fds = 64;

    /// Internal registration entry
    const Entry = struct {
        fd: posix.fd_t,
        read_cb: ReadyCallback,
        write_cb: ReadyCallback,
        want_read: bool,
        want_write: bool,
    };

    allocator: Allocator,
    registrations: std.AutoHashMap(posix.fd_t, Entry),

    pub fn init(allocator: Allocator) Self {
        return .{
            .allocator = allocator,
            .registrations = std.AutoHashMap(posix.fd_t, Entry).init(allocator),
        };
    }

    pub fn deinit(self: *Self) void {
        self.registrations.deinit();
    }

    /// Register a file descriptor for read readiness.
    pub fn registerRead(self: *Self, fd: posix.fd_t, callback: ReadyCallback) void {
        const result = self.registrations.getOrPut(fd) catch return;
        if (!result.found_existing) {
            result.value_ptr.* = .{
                .fd = fd,
                .read_cb = ReadyCallback.noop,
                .write_cb = ReadyCallback.noop,
                .want_read = false,
                .want_write = false,
            };
        }
        result.value_ptr.read_cb = callback;
        result.value_ptr.want_read = true;
    }

    /// Register a file descriptor for write readiness.
    pub fn registerWrite(self: *Self, fd: posix.fd_t, callback: ReadyCallback) void {
        const result = self.registrations.getOrPut(fd) catch return;
        if (!result.found_existing) {
            result.value_ptr.* = .{
                .fd = fd,
                .read_cb = ReadyCallback.noop,
                .write_cb = ReadyCallback.noop,
                .want_read = false,
                .want_write = false,
            };
        }
        result.value_ptr.write_cb = callback;
        result.value_ptr.want_write = true;
    }

    /// Unregister a file descriptor from all events.
    pub fn unregister(self: *Self, fd: posix.fd_t) void {
        _ = self.registrations.remove(fd);
    }

    /// Poll for I/O events using select and invoke callbacks.
    ///
    /// Returns the number of events processed.
    pub fn poll(self: *Self, timeout_ms: i32) usize {
        if (self.registrations.count() == 0) {
            if (timeout_ms > 0) {
                std.Thread.sleep(@as(u64, @intCast(timeout_ms)) * std.time.ns_per_ms);
            }
            return 0;
        }

        // Build fd_sets for select
        var read_fds: posix.fd_set = posix.fd_set.initEmpty();
        var write_fds: posix.fd_set = posix.fd_set.initEmpty();
        var max_fd: posix.fd_t = 0;

        var iter = self.registrations.iterator();
        while (iter.next()) |entry| {
            const e = entry.value_ptr;
            if (e.want_read) {
                read_fds.set(@intCast(e.fd));
                if (e.fd > max_fd) max_fd = e.fd;
            }
            if (e.want_write) {
                write_fds.set(@intCast(e.fd));
                if (e.fd > max_fd) max_fd = e.fd;
            }
        }

        // Convert timeout
        const tv: ?posix.timeval = if (timeout_ms >= 0) .{
            .sec = @intCast(@divFloor(timeout_ms, 1000)),
            .usec = @intCast(@mod(timeout_ms, 1000) * 1000),
        } else null;

        // Call select
        const result = posix.select(
            @intCast(max_fd + 1),
            &read_fds,
            &write_fds,
            null,
            if (tv) |*t| t else null,
        );

        if (result <= 0) return 0;

        // Process ready fds - collect callbacks first to avoid modification during iteration
        var callbacks_to_call: [max_fds * 2]struct { cb: ReadyCallback, fd: posix.fd_t } = undefined;
        var callback_count: usize = 0;

        var iter2 = self.registrations.iterator();
        while (iter2.next()) |entry| {
            const e = entry.value_ptr;

            if (e.want_read and read_fds.isSet(@intCast(e.fd))) {
                if (callback_count < callbacks_to_call.len) {
                    callbacks_to_call[callback_count] = .{ .cb = e.read_cb, .fd = e.fd };
                    callback_count += 1;
                }
            }

            if (e.want_write and write_fds.isSet(@intCast(e.fd))) {
                if (callback_count < callbacks_to_call.len) {
                    callbacks_to_call[callback_count] = .{ .cb = e.write_cb, .fd = e.fd };
                    callback_count += 1;
                }
            }
        }

        // Now invoke callbacks
        for (callbacks_to_call[0..callback_count]) |item| {
            item.cb.call(item.fd);
        }

        return callback_count;
    }

    /// Create an IOService interface from this BusyPollIO.
    pub fn ioService(self: *Self) async_io.IOService {
        return .{
            .ptr = @ptrCast(self),
            .vtable = &vtable,
        };
    }

    const vtable: async_io.IOService.VTable = .{
        .register_read = registerReadVtable,
        .register_write = registerWriteVtable,
        .unregister = unregisterVtable,
        .poll = pollVtable,
    };

    fn registerReadVtable(ptr: *anyopaque, fd: posix.fd_t, callback: ReadyCallback) void {
        const self: *Self = @ptrCast(@alignCast(ptr));
        self.registerRead(fd, callback);
    }

    fn registerWriteVtable(ptr: *anyopaque, fd: posix.fd_t, callback: ReadyCallback) void {
        const self: *Self = @ptrCast(@alignCast(ptr));
        self.registerWrite(fd, callback);
    }

    fn unregisterVtable(ptr: *anyopaque, fd: posix.fd_t) void {
        const self: *Self = @ptrCast(@alignCast(ptr));
        self.unregister(fd);
    }

    fn pollVtable(ptr: *anyopaque, timeout_ms: i32) usize {
        const self: *Self = @ptrCast(@alignCast(ptr));
        return self.poll(timeout_ms);
    }
};

/// No-op OS layer with injected allocator.
pub fn None(comptime allocator: Allocator) type {
    return struct {
        /// No-op Reactor.
        pub const Reactor = struct {
            pub fn init() !Reactor {
                return .{};
            }

            pub fn deinit(_: *Reactor) void {}

            pub fn poll(_: *Reactor) void {}
        };

        /// No-op Event (simple flag).
        pub const Event = struct {
            triggered: bool,

            pub fn init() Event {
                return .{ .triggered = false };
            }

            pub fn deinit(_: *Event) void {}

            pub fn set(self: *Event) void {
                self.triggered = true;
            }

            pub fn wait(_: *Event) void {}

            pub fn timedWait(self: *Event, _: u64) bool {
                return self.triggered;
            }

            pub fn reset(self: *Event) void {
                self.triggered = false;
            }

            pub fn isSet(self: *const Event) bool {
                return self.triggered;
            }
        };

        /// No-op Channel (simple ring buffer).
        pub fn Channel(comptime T: type) type {
            return struct {
                const Self = @This();

                buffer: []T,
                capacity: usize,
                head: usize,
                tail: usize,
                closed: bool,

                pub fn init(capacity: usize) !Self {
                    const buffer = try allocator.alloc(T, capacity);
                    return .{
                        .buffer = buffer,
                        .capacity = capacity,
                        .head = 0,
                        .tail = 0,
                        .closed = false,
                    };
                }

                pub fn deinit(self: *Self) void {
                    allocator.free(self.buffer);
                }

                fn len(self: *const Self) usize {
                    if (self.tail >= self.head) {
                        return self.tail - self.head;
                    } else {
                        return self.capacity - self.head + self.tail;
                    }
                }

                fn isFull(self: *const Self) bool {
                    return self.len() == self.capacity - 1;
                }

                fn isEmpty(self: *const Self) bool {
                    return self.head == self.tail;
                }

                pub fn send(self: *Self, item: T) !void {
                    if (self.closed) return error.ChannelClosed;
                    if (self.isFull()) return error.ChannelFull;
                    self.buffer[self.tail] = item;
                    self.tail = (self.tail + 1) % self.capacity;
                }

                pub fn trySend(self: *Self, item: T) bool {
                    if (self.closed or self.isFull()) return false;
                    self.buffer[self.tail] = item;
                    self.tail = (self.tail + 1) % self.capacity;
                    return true;
                }

                pub fn recv(self: *Self) ?T {
                    if (self.isEmpty()) return null;
                    const item = self.buffer[self.head];
                    self.head = (self.head + 1) % self.capacity;
                    return item;
                }

                pub fn tryRecv(self: *Self) ?T {
                    return self.recv();
                }

                pub fn close(self: *Self) void {
                    self.closed = true;
                }
            };
        }

        /// No-op Mutex.
        pub const Mutex = struct {
            pub fn init() Mutex {
                return .{};
            }

            pub fn lock(_: *Mutex) void {}

            pub fn tryLock(_: *Mutex) bool {
                return true;
            }

            pub fn unlock(_: *Mutex) void {}
        };

        /// No-op Semaphore (counter only).
        pub const Semaphore = struct {
            permits: u32,

            pub fn init(permits: u32) Semaphore {
                return .{ .permits = permits };
            }

            pub fn wait(self: *Semaphore) void {
                if (self.permits > 0) self.permits -= 1;
            }

            pub fn tryWait(self: *Semaphore) bool {
                if (self.permits == 0) return false;
                self.permits -= 1;
                return true;
            }

            pub fn post(self: *Semaphore) void {
                self.permits += 1;
            }
        };
    };
}

// ============================================================================
// Tests
// ============================================================================

test "Event basic" {
    const Os = None(std.testing.allocator);
    var event = Os.Event.init();
    defer event.deinit();

    try std.testing.expect(!event.isSet());
    event.set();
    try std.testing.expect(event.isSet());
    event.reset();
    try std.testing.expect(!event.isSet());
}

test "Channel basic" {
    const Os = None(std.testing.allocator);
    var chan = try Os.Channel(u32).init(4);
    defer chan.deinit();

    try chan.send(1);
    try chan.send(2);

    try std.testing.expectEqual(@as(?u32, 1), chan.recv());
    try std.testing.expectEqual(@as(?u32, 2), chan.recv());
    try std.testing.expectEqual(@as(?u32, null), chan.recv());
}

test "Mutex basic" {
    const Os = None(std.testing.allocator);
    var mutex = Os.Mutex.init();

    mutex.lock();
    try std.testing.expect(mutex.tryLock());
    mutex.unlock();
}

test "Semaphore basic" {
    const Os = None(std.testing.allocator);
    var sem = Os.Semaphore.init(2);

    try std.testing.expect(sem.tryWait());
    try std.testing.expect(sem.tryWait());
    try std.testing.expect(!sem.tryWait());

    sem.post();
    try std.testing.expect(sem.tryWait());
}

test "BusyPollIO basic" {
    var io = BusyPollIO.init(std.testing.allocator);
    defer io.deinit();

    // Create a pipe for testing
    const pipe_fds = try posix.pipe();
    defer posix.close(pipe_fds[0]);
    defer posix.close(pipe_fds[1]);

    var read_called = false;

    // Register for read on pipe read end
    io.registerRead(pipe_fds[0], .{
        .ptr = @ptrCast(&read_called),
        .callback = struct {
            fn cb(ptr: ?*anyopaque, _: posix.fd_t) void {
                const called: *bool = @ptrCast(@alignCast(ptr.?));
                called.* = true;
            }
        }.cb,
    });

    // Write to pipe write end to make read end readable
    _ = try posix.write(pipe_fds[1], "hello");

    // Poll should invoke callback
    const count = io.poll(100);
    try std.testing.expect(count > 0);
    try std.testing.expect(read_called);
}

test "BusyPollIO unregister" {
    var io = BusyPollIO.init(std.testing.allocator);
    defer io.deinit();

    const pipe_fds = try posix.pipe();
    defer posix.close(pipe_fds[0]);
    defer posix.close(pipe_fds[1]);

    var called = false;

    io.registerRead(pipe_fds[0], .{
        .ptr = @ptrCast(&called),
        .callback = struct {
            fn cb(ptr: ?*anyopaque, _: posix.fd_t) void {
                const c: *bool = @ptrCast(@alignCast(ptr.?));
                c.* = true;
            }
        }.cb,
    });

    // Unregister before triggering
    io.unregister(pipe_fds[0]);

    // Write to make it readable
    _ = try posix.write(pipe_fds[1], "hello");

    // Poll should not invoke callback
    _ = io.poll(10);
    try std.testing.expect(!called);
}
