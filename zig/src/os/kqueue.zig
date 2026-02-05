//! macOS/BSD Implementation using kqueue.
//!
//! Provides efficient event-driven primitives:
//! - Reactor: kqueue event loop
//! - Event: EVFILT_USER for zero-cost signaling
//! - Channel: Based on Event + ring buffer
//! - Mutex: std.Thread.Mutex wrapper
//! - Semaphore: Futex-based counting semaphore

const std = @import("std");
const posix = std.posix;
const Allocator = std.mem.Allocator;

/// C interop for select() - Zig's std.posix doesn't expose fd_set on BSD
const sys = @cImport({
    @cInclude("sys/select.h");
});

/// Helper functions for fd_set operations (C macros don't translate properly)
const FdSet = struct {
    /// Clear all bits in fd_set
    fn zero(fds: *sys.fd_set) void {
        @memset(@as([*]u8, @ptrCast(fds))[0..@sizeOf(sys.fd_set)], 0);
    }

    /// Set a file descriptor bit
    fn setBit(fd: c_int, fds: *sys.fd_set) void {
        const ufd: usize = @intCast(fd);
        const bits_per_word = @sizeOf(c_int) * 8;
        const word_index = ufd / bits_per_word;
        const bit_index: u5 = @intCast(ufd % bits_per_word);
        fds.fds_bits[word_index] |= (@as(i32, 1) << bit_index);
    }

    /// Check if a file descriptor bit is set
    fn isSet(fd: c_int, fds: *const sys.fd_set) bool {
        const ufd: usize = @intCast(fd);
        const bits_per_word = @sizeOf(c_int) * 8;
        const word_index = ufd / bits_per_word;
        const bit_index: u5 = @intCast(ufd % bits_per_word);
        return (fds.fds_bits[word_index] & (@as(i32, 1) << bit_index)) != 0;
    }
};

/// kqueue event filter and flags
pub const Filter = enum(i16) {
    read = posix.system.EVFILT.READ,
    write = posix.system.EVFILT.WRITE,
    user = posix.system.EVFILT.USER,
};

pub const Flags = struct {
    pub const ADD = posix.system.EV.ADD;
    pub const ENABLE = posix.system.EV.ENABLE;
    pub const DISABLE = posix.system.EV.DISABLE;
    pub const DELETE = posix.system.EV.DELETE;
    pub const ONESHOT = posix.system.EV.ONESHOT;
    pub const CLEAR = posix.system.EV.CLEAR;
};

pub const FFlags = struct {
    pub const TRIGGER = posix.system.NOTE.TRIGGER;
};

/// kqueue-based event reactor.
pub const Reactor = struct {
    kq: i32,
    events: [64]posix.system.Kevent,

    pub fn init() !Reactor {
        const kq = try posix.kqueue();
        return .{
            .kq = kq,
            .events = undefined,
        };
    }

    pub fn deinit(self: *Reactor) void {
        posix.close(self.kq);
    }

    /// Register a file descriptor for events.
    pub fn register(self: *Reactor, ident: usize, filter: Filter, flags: u16) !void {
        const changelist = [_]posix.system.Kevent{.{
            .ident = ident,
            .filter = @intFromEnum(filter),
            .flags = flags,
            .fflags = 0,
            .data = 0,
            .udata = 0,
        }};
        _ = try posix.kevent(self.kq, &changelist, &[_]posix.system.Kevent{}, null);
    }

    /// Register a user event (EVFILT_USER).
    pub fn registerUser(self: *Reactor, ident: usize) !void {
        const changelist = [_]posix.system.Kevent{.{
            .ident = ident,
            .filter = posix.system.EVFILT.USER,
            .flags = posix.system.EV.ADD | posix.system.EV.CLEAR,
            .fflags = 0,
            .data = 0,
            .udata = 0,
        }};
        _ = try posix.kevent(self.kq, &changelist, &[_]posix.system.Kevent{}, null);
    }

    /// Trigger a user event.
    pub fn triggerUser(self: *Reactor, ident: usize) !void {
        const changelist = [_]posix.system.Kevent{.{
            .ident = ident,
            .filter = posix.system.EVFILT.USER,
            .flags = 0,
            .fflags = posix.system.NOTE.TRIGGER,
            .data = 0,
            .udata = 0,
        }};
        _ = try posix.kevent(self.kq, &changelist, &[_]posix.system.Kevent{}, null);
    }

    /// Wait for events with optional timeout.
    /// Returns slice of triggered events.
    pub fn wait(self: *Reactor, timeout_ms: ?i32) ![]const posix.system.Kevent {
        const ts: ?posix.timespec = if (timeout_ms) |ms| .{
            .sec = @intCast(@divFloor(ms, 1000)),
            .nsec = @intCast(@mod(ms, 1000) * 1_000_000),
        } else null;

        const n = try posix.kevent(
            self.kq,
            &[_]posix.system.Kevent{},
            &self.events,
            if (ts) |*t| t else null,
        );
        return self.events[0..n];
    }
};

/// Event signal using EVFILT_USER for zero-cost thread wakeup.
pub const Event = struct {
    triggered: std.atomic.Value(bool),
    futex: std.atomic.Value(u32),

    const UNSET: u32 = 0;
    const SET: u32 = 1;

    pub fn init() Event {
        return .{
            .triggered = std.atomic.Value(bool).init(false),
            .futex = std.atomic.Value(u32).init(UNSET),
        };
    }

    pub fn deinit(_: *Event) void {
        // Nothing to clean up
    }

    /// Signal the event, waking any waiters.
    pub fn set(self: *Event) void {
        self.triggered.store(true, .release);
        self.futex.store(SET, .release);
        std.Thread.Futex.wake(&self.futex, 1);
    }

    /// Block until the event is signaled.
    pub fn wait(self: *Event) void {
        while (self.futex.load(.acquire) == UNSET) {
            std.Thread.Futex.wait(&self.futex, UNSET);
        }
    }

    /// Block with timeout. Returns true if signaled, false if timeout.
    pub fn timedWait(self: *Event, timeout_ns: u64) bool {
        if (self.futex.load(.acquire) == SET) return true;
        std.Thread.Futex.timedWait(&self.futex, UNSET, timeout_ns) catch {};
        return self.futex.load(.acquire) == SET;
    }

    /// Reset the event to unsignaled state.
    pub fn reset(self: *Event) void {
        self.triggered.store(false, .release);
        self.futex.store(UNSET, .release);
    }

    /// Check if event is signaled (non-blocking).
    pub fn isSet(self: *const Event) bool {
        return self.triggered.load(.acquire);
    }
};

/// Thread-safe bounded channel using ring buffer + Events.
pub fn Channel(comptime T: type) type {
    return struct {
        const Self = @This();

        allocator: Allocator,
        buffer: []T,
        capacity: usize,
        head: std.atomic.Value(usize),
        tail: std.atomic.Value(usize),
        closed: std.atomic.Value(bool),
        mutex: std.Thread.Mutex,
        not_empty: Event,
        not_full: Event,

        pub fn init(allocator: Allocator, capacity: usize) !Self {
            const buffer = try allocator.alloc(T, capacity);
            return .{
                .allocator = allocator,
                .buffer = buffer,
                .capacity = capacity,
                .head = std.atomic.Value(usize).init(0),
                .tail = std.atomic.Value(usize).init(0),
                .closed = std.atomic.Value(bool).init(false),
                .mutex = .{},
                .not_empty = Event.init(),
                .not_full = Event.init(),
            };
        }

        pub fn deinit(self: *Self) void {
            self.allocator.free(self.buffer);
        }

        fn len(self: *const Self) usize {
            const h = self.head.load(.acquire);
            const t = self.tail.load(.acquire);
            if (t >= h) {
                return t - h;
            } else {
                return self.capacity - h + t;
            }
        }

        fn isFull(self: *const Self) bool {
            return self.len() == self.capacity - 1;
        }

        fn isEmpty(self: *const Self) bool {
            return self.head.load(.acquire) == self.tail.load(.acquire);
        }

        /// Send item, blocking if channel is full.
        pub fn send(self: *Self, item: T) !void {
            while (true) {
                if (self.closed.load(.acquire)) return error.ChannelClosed;

                self.mutex.lock();
                if (!self.isFull()) {
                    const t = self.tail.load(.monotonic);
                    self.buffer[t] = item;
                    self.tail.store((t + 1) % self.capacity, .release);
                    self.mutex.unlock();

                    // Signal that channel is not empty
                    self.not_empty.set();
                    return;
                }
                self.mutex.unlock();

                // Wait for space
                self.not_full.wait();
                self.not_full.reset();
            }
        }

        /// Try to send without blocking. Returns false if full.
        pub fn trySend(self: *Self, item: T) bool {
            if (self.closed.load(.acquire)) return false;

            self.mutex.lock();
            defer self.mutex.unlock();

            if (self.isFull()) return false;

            const t = self.tail.load(.monotonic);
            self.buffer[t] = item;
            self.tail.store((t + 1) % self.capacity, .release);
            self.not_empty.set();
            return true;
        }

        /// Receive item, blocking if channel is empty.
        /// Returns null if channel is closed and empty.
        pub fn recv(self: *Self) ?T {
            var spins: u32 = 0;
            const max_spins: u32 = 100;

            while (true) {
                self.mutex.lock();
                if (!self.isEmpty()) {
                    const h = self.head.load(.monotonic);
                    const item = self.buffer[h];
                    self.head.store((h + 1) % self.capacity, .release);
                    self.mutex.unlock();

                    // Signal that channel is not full
                    self.not_full.set();
                    return item;
                }
                self.mutex.unlock();

                // Check if closed
                if (self.closed.load(.acquire)) return null;

                // Adaptive wait: spin first, then futex
                spins += 1;
                if (spins < max_spins) {
                    std.atomic.spinLoopHint();
                } else {
                    // Wait with short timeout to handle close()
                    _ = self.not_empty.timedWait(1 * std.time.ns_per_ms);
                    spins = 0;
                }
            }
        }

        /// Try to receive without blocking.
        pub fn tryRecv(self: *Self) ?T {
            self.mutex.lock();
            defer self.mutex.unlock();

            if (self.isEmpty()) return null;

            const h = self.head.load(.monotonic);
            const item = self.buffer[h];
            self.head.store((h + 1) % self.capacity, .release);
            self.not_full.set();
            return item;
        }

        /// Close the channel. Wakes all waiters.
        pub fn close(self: *Self) void {
            self.closed.store(true, .release);
            self.not_empty.set();
            self.not_full.set();
        }
    };
}

/// Mutex wrapper for std.Thread.Mutex with tryLock.
pub const Mutex = struct {
    inner: std.Thread.Mutex,

    pub fn init() Mutex {
        return .{ .inner = .{} };
    }

    pub fn lock(self: *Mutex) void {
        self.inner.lock();
    }

    pub fn tryLock(self: *Mutex) bool {
        return self.inner.tryLock();
    }

    pub fn unlock(self: *Mutex) void {
        self.inner.unlock();
    }
};

// ============================================================================
// KqueueIO - IOService implementation using kqueue
// ============================================================================

const async_io = @import("../async/io.zig");
const ReadyCallback = async_io.ReadyCallback;

/// kqueue-based I/O service implementing the IOService interface.
///
/// ## Direct Usage (comptime, zero overhead)
/// ```zig
/// var io = try KqueueIO.init(allocator);
/// defer io.deinit();
///
/// io.registerRead(socket_fd, .{ .ptr = ctx, .callback = onReady });
///
/// while (running) {
///     _ = io.poll(100);
/// }
/// ```
pub const KqueueIO = struct {
    const Self = @This();
    const max_events = 64;

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
    ///
    /// Direct method - use this for comptime polymorphism.
    pub fn registerRead(self: *Self, fd: posix.fd_t, callback: ReadyCallback) void {
        // Get or create entry
        const result = self.registrations.getOrPut(fd) catch return;
        if (!result.found_existing) {
            result.value_ptr.* = .{
                .fd = fd,
                .read_cb = ReadyCallback.noop,
                .write_cb = ReadyCallback.noop,
                .read_registered = false,
                .write_registered = false,
            };
        }

        result.value_ptr.read_cb = callback;

        // Register with kqueue if not already
        if (!result.value_ptr.read_registered) {
            const changelist = [_]posix.system.Kevent{.{
                .ident = @intCast(fd),
                .filter = posix.system.EVFILT.READ,
                .flags = posix.system.EV.ADD | posix.system.EV.CLEAR,
                .fflags = 0,
                .data = 0,
                .udata = 0,
            }};
            _ = posix.kevent(self.kq, &changelist, &[_]posix.system.Kevent{}, null) catch return;
            result.value_ptr.read_registered = true;
        }
    }

    /// Register a file descriptor for write readiness.
    ///
    /// Direct method - use this for comptime polymorphism.
    pub fn registerWrite(self: *Self, fd: posix.fd_t, callback: ReadyCallback) void {
        // Get or create entry
        const result = self.registrations.getOrPut(fd) catch return;
        if (!result.found_existing) {
            result.value_ptr.* = .{
                .fd = fd,
                .read_cb = ReadyCallback.noop,
                .write_cb = ReadyCallback.noop,
                .read_registered = false,
                .write_registered = false,
            };
        }

        result.value_ptr.write_cb = callback;

        // Register with kqueue if not already
        if (!result.value_ptr.write_registered) {
            const changelist = [_]posix.system.Kevent{.{
                .ident = @intCast(fd),
                .filter = posix.system.EVFILT.WRITE,
                .flags = posix.system.EV.ADD | posix.system.EV.CLEAR,
                .fflags = 0,
                .data = 0,
                .udata = 0,
            }};
            _ = posix.kevent(self.kq, &changelist, &[_]posix.system.Kevent{}, null) catch return;
            result.value_ptr.write_registered = true;
        }
    }

    /// Unregister a file descriptor from all events.
    ///
    /// Direct method - use this for comptime polymorphism.
    pub fn unregister(self: *Self, fd: posix.fd_t) void {
        if (self.registrations.fetchRemove(fd)) |entry| {
            // Remove from kqueue
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
                _ = posix.kevent(self.kq, changelist[0..count], &[_]posix.system.Kevent{}, null) catch {};
            }
        }
    }

    /// Poll for I/O events and invoke callbacks.
    ///
    /// Returns the number of events processed.
    /// Direct method - use this for comptime polymorphism.
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
        for (self.events[0..n]) |event| {
            const fd: posix.fd_t = @intCast(event.ident);

            if (self.registrations.get(fd)) |entry| {
                if (event.filter == posix.system.EVFILT.READ) {
                    entry.read_cb.call(fd);
                } else if (event.filter == posix.system.EVFILT.WRITE) {
                    entry.write_cb.call(fd);
                }
            }
        }

        return n;
    }

    /// Create an IOService interface from this KqueueIO.
    ///
    /// Use this only when runtime polymorphism is needed.
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

// ============================================================================
// BusyPollIO - Fallback IOService using select (BSD/macOS)
// ============================================================================

/// Busy-poll based I/O service using select() - fallback when kqueue overhead
/// is not justified (e.g., single fd, short-lived operations).
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

        // Build fd_sets for select using C interop
        var read_fds: sys.fd_set = undefined;
        var write_fds: sys.fd_set = undefined;
        FdSet.zero(&read_fds);
        FdSet.zero(&write_fds);
        var max_fd: c_int = 0;

        var iter = self.registrations.iterator();
        while (iter.next()) |entry| {
            const e = entry.value_ptr;
            if (e.want_read) {
                FdSet.setBit(e.fd, &read_fds);
                if (e.fd > max_fd) max_fd = e.fd;
            }
            if (e.want_write) {
                FdSet.setBit(e.fd, &write_fds);
                if (e.fd > max_fd) max_fd = e.fd;
            }
        }

        // Convert timeout
        var tv: sys.struct_timeval = .{
            .tv_sec = @intCast(@divFloor(timeout_ms, 1000)),
            .tv_usec = @intCast(@mod(timeout_ms, 1000) * 1000),
        };
        const tv_ptr: ?*sys.struct_timeval = if (timeout_ms >= 0) &tv else null;

        // Call select
        const result = sys.select(
            max_fd + 1,
            &read_fds,
            &write_fds,
            null,
            tv_ptr,
        );

        if (result <= 0) return 0;

        // Process ready fds - collect callbacks first to avoid modification during iteration
        var callbacks_to_call: [max_fds * 2]struct { cb: ReadyCallback, fd: posix.fd_t } = undefined;
        var callback_count: usize = 0;

        var iter2 = self.registrations.iterator();
        while (iter2.next()) |entry| {
            const e = entry.value_ptr;

            if (e.want_read and FdSet.isSet(e.fd, &read_fds)) {
                if (callback_count < callbacks_to_call.len) {
                    callbacks_to_call[callback_count] = .{ .cb = e.read_cb, .fd = e.fd };
                    callback_count += 1;
                }
            }

            if (e.want_write and FdSet.isSet(e.fd, &write_fds)) {
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

/// Counting semaphore using futex.
pub const Semaphore = struct {
    permits: std.atomic.Value(u32),

    pub fn init(permits: u32) Semaphore {
        return .{
            .permits = std.atomic.Value(u32).init(permits),
        };
    }

    /// P operation (wait/decrement). Blocks if permits == 0.
    pub fn wait(self: *Semaphore) void {
        while (true) {
            const current = self.permits.load(.acquire);
            if (current > 0) {
                if (self.permits.cmpxchgWeak(
                    current,
                    current - 1,
                    .acq_rel,
                    .acquire,
                ) == null) {
                    return;
                }
            } else {
                std.Thread.Futex.wait(&self.permits, 0);
            }
        }
    }

    /// Non-blocking P operation.
    pub fn tryWait(self: *Semaphore) bool {
        const current = self.permits.load(.acquire);
        if (current == 0) return false;
        return self.permits.cmpxchgWeak(
            current,
            current - 1,
            .acq_rel,
            .acquire,
        ) == null;
    }

    /// V operation (signal/increment).
    pub fn post(self: *Semaphore) void {
        _ = self.permits.fetchAdd(1, .release);
        std.Thread.Futex.wake(&self.permits, 1);
    }
};

// ============================================================================
// Tests
// ============================================================================

test "Event basic" {
    var event = Event.init();
    defer event.deinit();

    try std.testing.expect(!event.isSet());
    event.set();
    try std.testing.expect(event.isSet());
    event.reset();
    try std.testing.expect(!event.isSet());
}

test "Event wait/set" {
    var event = Event.init();
    defer event.deinit();

    const thread = try std.Thread.spawn(.{}, struct {
        fn run(e: *Event) void {
            std.Thread.sleep(10_000_000); // 10ms
            e.set();
        }
    }.run, .{&event});

    event.wait();
    try std.testing.expect(event.isSet());
    thread.join();
}

test "Channel basic" {
    var chan = try Channel(u32).init(std.testing.allocator, 4);
    defer chan.deinit();

    try chan.send(1);
    try chan.send(2);
    try chan.send(3);

    try std.testing.expectEqual(@as(?u32, 1), chan.recv());
    try std.testing.expectEqual(@as(?u32, 2), chan.recv());
    try std.testing.expectEqual(@as(?u32, 3), chan.recv());
}

test "Channel trySend/tryRecv" {
    var chan = try Channel(u32).init(std.testing.allocator, 2);
    defer chan.deinit();

    try std.testing.expect(chan.trySend(1));
    try std.testing.expect(!chan.trySend(2)); // Full (capacity-1 = 1)

    try std.testing.expectEqual(@as(?u32, 1), chan.tryRecv());
    try std.testing.expectEqual(@as(?u32, null), chan.tryRecv()); // Empty
}

test "Channel close" {
    var chan = try Channel(u32).init(std.testing.allocator, 4);
    defer chan.deinit();

    try chan.send(42);
    chan.close();

    // Can still receive buffered items
    try std.testing.expectEqual(@as(?u32, 42), chan.recv());
    // Then returns null
    try std.testing.expectEqual(@as(?u32, null), chan.recv());
}

test "Mutex basic" {
    var mutex = Mutex.init();

    mutex.lock();
    try std.testing.expect(!mutex.tryLock());
    mutex.unlock();

    try std.testing.expect(mutex.tryLock());
    mutex.unlock();
}

test "Semaphore basic" {
    var sem = Semaphore.init(2);

    try std.testing.expect(sem.tryWait());
    try std.testing.expect(sem.tryWait());
    try std.testing.expect(!sem.tryWait()); // No permits left

    sem.post();
    try std.testing.expect(sem.tryWait());
}

test "Reactor basic" {
    var reactor = try Reactor.init();
    defer reactor.deinit();

    // Register user event
    try reactor.registerUser(1);

    // Trigger it
    try reactor.triggerUser(1);

    // Wait should return immediately
    const events = try reactor.wait(100);
    try std.testing.expect(events.len > 0);
}

test "KqueueIO basic" {
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

    // Register for read on pipe read end
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

    // Write to pipe write end to make read end readable
    _ = try posix.write(pipe_fds[1], "hello");

    // Poll should invoke callback
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

    // Unregister before triggering
    io.unregister(pipe_fds[0]);

    // Write to make it readable
    _ = try posix.write(pipe_fds[1], "hello");

    // Poll should not invoke callback
    _ = io.poll(10);
    try std.testing.expect(!called);
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
