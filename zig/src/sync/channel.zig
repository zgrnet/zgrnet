//! Generic bounded channel implementation for Zig.
//!
//! Provides a thread-safe MPMC (multi-producer, multi-consumer) channel
//! similar to Go's channels.
//!
//! Usage:
//! ```zig
//! const MyChannel = Channel(u32);
//! var ch = try MyChannel.init(allocator, 100); // capacity 100
//! defer ch.deinit();
//!
//! try ch.send(42);
//! const val = ch.recv(); // blocks until value available
//! ```

const std = @import("std");
const Allocator = std.mem.Allocator;
const Mutex = std.Thread.Mutex;
const Condition = std.Thread.Condition;

/// A bounded, thread-safe channel.
pub fn Channel(comptime T: type) type {
    return struct {
        const Self = @This();

        allocator: Allocator,
        buffer: []T,
        capacity: usize,
        head: usize = 0, // read position
        tail: usize = 0, // write position
        count: usize = 0, // current items
        closed: bool = false,

        mutex: Mutex = .{},
        not_empty: Condition = .{}, // signaled when items available
        not_full: Condition = .{}, // signaled when space available

        /// Initialize a channel with given capacity.
        pub fn init(allocator: Allocator, capacity: usize) !Self {
            const buffer = try allocator.alloc(T, capacity);
            return Self{
                .allocator = allocator,
                .buffer = buffer,
                .capacity = capacity,
            };
        }

        /// Deinitialize the channel.
        pub fn deinit(self: *Self) void {
            self.allocator.free(self.buffer);
        }

        /// Send a value to the channel. Blocks if full.
        /// Returns error if channel is closed.
        pub fn send(self: *Self, value: T) !void {
            self.mutex.lock();
            defer self.mutex.unlock();

            // Wait for space
            while (self.count == self.capacity and !self.closed) {
                self.not_full.wait(&self.mutex);
            }

            if (self.closed) {
                return error.ChannelClosed;
            }

            // Add to buffer
            self.buffer[self.tail] = value;
            self.tail = (self.tail + 1) % self.capacity;
            self.count += 1;

            // Signal waiting receivers
            self.not_empty.signal();
        }

        /// Try to send without blocking. Returns false if full or closed.
        pub fn trySend(self: *Self, value: T) bool {
            self.mutex.lock();
            defer self.mutex.unlock();

            if (self.closed or self.count == self.capacity) {
                return false;
            }

            self.buffer[self.tail] = value;
            self.tail = (self.tail + 1) % self.capacity;
            self.count += 1;

            self.not_empty.signal();
            return true;
        }

        /// Receive a value from the channel. Blocks if empty.
        /// Returns null if channel is closed and empty.
        pub fn recv(self: *Self) ?T {
            self.mutex.lock();
            defer self.mutex.unlock();

            // Wait for items
            while (self.count == 0 and !self.closed) {
                self.not_empty.wait(&self.mutex);
            }

            if (self.count == 0) {
                return null; // closed and empty
            }

            // Get from buffer
            const value = self.buffer[self.head];
            self.head = (self.head + 1) % self.capacity;
            self.count -= 1;

            // Signal waiting senders
            self.not_full.signal();

            return value;
        }

        /// Try to receive without blocking. Returns null if empty.
        pub fn tryRecv(self: *Self) ?T {
            self.mutex.lock();
            defer self.mutex.unlock();

            if (self.count == 0) {
                return null;
            }

            const value = self.buffer[self.head];
            self.head = (self.head + 1) % self.capacity;
            self.count -= 1;

            self.not_full.signal();
            return value;
        }

        /// Close the channel. No more sends allowed.
        pub fn close(self: *Self) void {
            self.mutex.lock();
            defer self.mutex.unlock();

            self.closed = true;

            // Wake up all waiters
            self.not_empty.broadcast();
            self.not_full.broadcast();
        }

        /// Check if channel is closed.
        pub fn isClosed(self: *Self) bool {
            self.mutex.lock();
            defer self.mutex.unlock();
            return self.closed;
        }

        /// Get current item count.
        pub fn len(self: *Self) usize {
            self.mutex.lock();
            defer self.mutex.unlock();
            return self.count;
        }
    };
}

/// A simple ready signal (like Go's close(chan struct{})).
pub const ReadySignal = struct {
    mutex: Mutex = .{},
    cond: Condition = .{},
    ready: bool = false,

    /// Set the ready signal.
    pub fn set(self: *ReadySignal) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        self.ready = true;
        self.cond.broadcast();
    }

    /// Wait for the ready signal.
    pub fn wait(self: *ReadySignal) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        while (!self.ready) {
            self.cond.wait(&self.mutex);
        }
    }

    /// Check if ready without blocking.
    pub fn isReady(self: *ReadySignal) bool {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.ready;
    }

    /// Reset the signal (for reuse).
    pub fn reset(self: *ReadySignal) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        self.ready = false;
    }
};

test "channel basic" {
    const allocator = std.testing.allocator;
    var ch = try Channel(u32).init(allocator, 10);
    defer ch.deinit();

    try ch.send(42);
    try ch.send(43);

    try std.testing.expectEqual(@as(?u32, 42), ch.recv());
    try std.testing.expectEqual(@as(?u32, 43), ch.recv());
}

test "channel close" {
    const allocator = std.testing.allocator;
    var ch = try Channel(u32).init(allocator, 10);
    defer ch.deinit();

    try ch.send(1);
    ch.close();

    // Can still receive existing items
    try std.testing.expectEqual(@as(?u32, 1), ch.recv());
    // Returns null after empty and closed
    try std.testing.expectEqual(@as(?u32, null), ch.recv());
}

test "ready signal" {
    var sig = ReadySignal{};

    try std.testing.expect(!sig.isReady());
    sig.set();
    try std.testing.expect(sig.isReady());

    // wait should return immediately
    sig.wait();
}
