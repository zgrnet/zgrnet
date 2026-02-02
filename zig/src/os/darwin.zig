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
