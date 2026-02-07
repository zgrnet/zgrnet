//! kqueue-based IOService backend for macOS/BSD.
//!
//! Provides efficient event-driven I/O using kqueue. Implements the IOService
//! interface defined in `async/io.zig`.
//!
//! ## Usage
//!
//! ```zig
//! var io = try KqueueIO.init(allocator);
//! defer io.deinit();
//!
//! io.registerRead(socket_fd, .{ .ptr = ctx, .callback = onReady });
//!
//! while (running) {
//!     _ = io.poll(-1);  // block until events
//! }
//!
//! // From another thread:
//! io.wake();  // interrupts blocking poll()
//! ```

const std = @import("std");
const posix = std.posix;
const Allocator = std.mem.Allocator;

const async_io = @import("../io.zig");
const ReadyCallback = async_io.ReadyCallback;
const IOService = async_io.IOService;

/// kqueue-based I/O service implementing the IOService interface.
pub const KqueueIO = struct {
    const Self = @This();
    const max_events = 64;
    const wake_ident: usize = 0xDEAD; // Unique ident for wake event

    /// Internal registration entry
    const Entry = struct {
        fd: posix.fd_t,
        read_cb: ReadyCallback,
        write_cb: ReadyCallback,
        read_registered: bool,
        write_registered: bool,
    };

    kq: posix.fd_t,
    allocator: Allocator,
    registrations: std.AutoHashMap(posix.fd_t, Entry),
    events: [max_events]posix.system.Kevent,

    pub fn init(allocator: Allocator) !Self {
        const kq = try posix.kqueue();
        errdefer posix.close(kq);

        // Register EVFILT_USER event for wake() signaling
        const changelist = [_]posix.system.Kevent{.{
            .ident = wake_ident,
            .filter = posix.system.EVFILT.USER,
            .flags = posix.system.EV.ADD | posix.system.EV.CLEAR,
            .fflags = 0,
            .data = 0,
            .udata = 0,
        }};
        _ = try posix.kevent(kq, &changelist, &[_]posix.system.Kevent{}, null);

        return .{
            .kq = kq,
            .allocator = allocator,
            .registrations = std.AutoHashMap(posix.fd_t, Entry).init(allocator),
            .events = undefined,
        };
    }

    pub fn deinit(self: *Self) void {
        posix.close(self.kq);
        self.registrations.deinit();
    }

    /// Register a file descriptor for read readiness.
    pub fn registerRead(self: *Self, fd: posix.fd_t, callback: ReadyCallback) void {
        self.registerFilter(fd, posix.system.EVFILT.READ, callback);
    }

    /// Register a file descriptor for write readiness.
    pub fn registerWrite(self: *Self, fd: posix.fd_t, callback: ReadyCallback) void {
        self.registerFilter(fd, posix.system.EVFILT.WRITE, callback);
    }

    /// Shared implementation for registering a filter on a file descriptor.
    fn registerFilter(self: *Self, fd: posix.fd_t, filter: i8, callback: ReadyCallback) void {
        const result = self.registrations.getOrPut(fd) catch |err| {
            std.log.err("KqueueIO: failed to update registration map for fd {d}: {s}", .{ fd, @errorName(err) });
            return;
        };
        const is_new = !result.found_existing;
        if (is_new) {
            result.value_ptr.* = .{
                .fd = fd,
                .read_cb = ReadyCallback.noop,
                .write_cb = ReadyCallback.noop,
                .read_registered = false,
                .write_registered = false,
            };
        }

        const is_read = (filter == posix.system.EVFILT.READ);
        if (is_read) {
            result.value_ptr.read_cb = callback;
        } else {
            result.value_ptr.write_cb = callback;
        }

        const already_registered = if (is_read) result.value_ptr.read_registered else result.value_ptr.write_registered;
        if (!already_registered) {
            // Use level-triggered (no EV_CLEAR). Edge-triggered events
            // require the caller to fully drain the fd on each callback;
            // if it cannot (e.g. pool exhaustion in UDP), remaining data
            // in the socket buffer would never trigger a new event, causing
            // an indefinite stall. Level-triggered keeps firing while the
            // condition holds, so a transient inability to drain is safe.
            const changelist = [_]posix.system.Kevent{.{
                .ident = @intCast(fd),
                .filter = filter,
                .flags = posix.system.EV.ADD,
                .fflags = 0,
                .data = 0,
                .udata = 0,
            }};
            _ = posix.kevent(self.kq, &changelist, &[_]posix.system.Kevent{}, null) catch |err| {
                std.log.err("KqueueIO: failed to register fd {d} with kqueue: {s}", .{ fd, @errorName(err) });
                // Clean up map entry if it was newly created to prevent leak
                if (is_new) {
                    _ = self.registrations.fetchRemove(fd);
                }
                return;
            };
            if (is_read) {
                result.value_ptr.read_registered = true;
            } else {
                result.value_ptr.write_registered = true;
            }
        }
    }

    /// Unregister a file descriptor from all events.
    pub fn unregister(self: *Self, fd: posix.fd_t) void {
        if (self.registrations.fetchRemove(fd)) |entry| {
            var changelist: [2]posix.system.Kevent = undefined;
            var count: usize = 0;

            if (entry.value.read_registered) {
                changelist[count] = .{
                    .ident = @intCast(fd),
                    .filter = posix.system.EVFILT.READ,
                    .flags = posix.system.EV.DELETE,
                    .fflags = 0,
                    .data = 0,
                    .udata = 0,
                };
                count += 1;
            }

            if (entry.value.write_registered) {
                changelist[count] = .{
                    .ident = @intCast(fd),
                    .filter = posix.system.EVFILT.WRITE,
                    .flags = posix.system.EV.DELETE,
                    .fflags = 0,
                    .data = 0,
                    .udata = 0,
                };
                count += 1;
            }

            if (count > 0) {
                _ = posix.kevent(self.kq, changelist[0..count], &[_]posix.system.Kevent{}, null) catch |err| {
                    std.log.err("KqueueIO: failed to unregister fd {d}: {s}", .{ fd, @errorName(err) });
                };
            }
        }
    }

    /// Poll for I/O events and invoke callbacks.
    /// Pass -1 for timeout_ms to block indefinitely.
    /// Returns the number of events processed.
    pub fn poll(self: *Self, timeout_ms: i32) usize {
        const ts: ?posix.timespec = if (timeout_ms >= 0) .{
            .sec = @intCast(@divFloor(timeout_ms, 1000)),
            .nsec = @intCast(@mod(timeout_ms, 1000) * 1_000_000),
        } else null;

        const n = posix.kevent(
            self.kq,
            &[_]posix.system.Kevent{},
            &self.events,
            if (ts) |*t| t else null,
        ) catch return 0;

        // Process events and invoke callbacks
        var processed: usize = 0;
        for (self.events[0..n]) |event| {
            // Skip wake events — they just interrupt the poll
            if (event.filter == posix.system.EVFILT.USER and event.ident == wake_ident) {
                continue;
            }

            const fd: posix.fd_t = @intCast(event.ident);

            if (self.registrations.get(fd)) |entry| {
                if (event.filter == posix.system.EVFILT.READ) {
                    entry.read_cb.call(fd);
                    processed += 1;
                } else if (event.filter == posix.system.EVFILT.WRITE) {
                    entry.write_cb.call(fd);
                    processed += 1;
                }
            }
        }

        return processed;
    }

    /// Interrupt a blocking poll() call from another thread.
    pub fn wake(self: *Self) void {
        const changelist = [_]posix.system.Kevent{.{
            .ident = wake_ident,
            .filter = posix.system.EVFILT.USER,
            .flags = 0,
            .fflags = posix.system.NOTE.TRIGGER,
            .data = 0,
            .udata = 0,
        }};
        _ = posix.kevent(self.kq, &changelist, &[_]posix.system.Kevent{}, null) catch |err| {
            std.log.err("KqueueIO: failed to wake: {s}", .{@errorName(err)});
        };
    }

    /// Create an IOService interface from this KqueueIO.
    pub fn ioService(self: *Self) IOService {
        return .{
            .ptr = @ptrCast(self),
            .vtable = &vtable,
        };
    }

    const vtable: IOService.VTable = .{
        .register_read = registerReadVtable,
        .register_write = registerWriteVtable,
        .unregister = unregisterVtable,
        .poll = pollVtable,
        .wake = wakeVtable,
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

    fn wakeVtable(ptr: *anyopaque) void {
        const self: *Self = @ptrCast(@alignCast(ptr));
        self.wake();
    }
};

// ============================================================================
// Tests
// ============================================================================

test "KqueueIO basic read" {
    var io = try KqueueIO.init(std.testing.allocator);
    defer io.deinit();

    // Create a pipe for testing
    const pipe_fds = try posix.pipe();
    defer posix.close(pipe_fds[0]);
    defer posix.close(pipe_fds[1]);

    var read_called = false;
    var read_fd: posix.fd_t = -1;

    const Ctx = struct {
        called: *bool,
        fd: *posix.fd_t,
    };

    var ctx = Ctx{
        .called = &read_called,
        .fd = &read_fd,
    };

    io.registerRead(pipe_fds[0], .{
        .ptr = @ptrCast(&ctx),
        .callback = struct {
            fn cb(ptr: ?*anyopaque, fd: posix.fd_t) void {
                const c: *Ctx = @ptrCast(@alignCast(ptr.?));
                c.called.* = true;
                c.fd.* = fd;
            }
        }.cb,
    });

    // Write to pipe to make read end readable
    _ = try posix.write(pipe_fds[1], "hello");

    const count = io.poll(100);
    try std.testing.expect(count > 0);
    try std.testing.expect(read_called);
    try std.testing.expectEqual(pipe_fds[0], read_fd);
}

test "KqueueIO unregister" {
    var io = try KqueueIO.init(std.testing.allocator);
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

    io.unregister(pipe_fds[0]);

    _ = try posix.write(pipe_fds[1], "hello");

    _ = io.poll(10);
    try std.testing.expect(!called);
}

test "KqueueIO wake interrupts poll" {
    var io = try KqueueIO.init(std.testing.allocator);
    defer io.deinit();

    // wake() should cause poll() to return without blocking forever
    io.wake();
    const count = io.poll(1000); // Would block 1s without wake
    try std.testing.expectEqual(@as(usize, 0), count); // No fd events, just wake
}

test "KqueueIO IOService vtable" {
    var io = try KqueueIO.init(std.testing.allocator);
    defer io.deinit();

    var svc = io.ioService();

    // Test wake through vtable
    svc.wake();
    const count = svc.poll(100);
    try std.testing.expectEqual(@as(usize, 0), count);
}
