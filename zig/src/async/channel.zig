//! Channel - Go-style bounded channel with close support
//!
//! A multi-producer multi-consumer bounded channel that supports:
//! - Blocking send/recv with optional timeout
//! - Non-blocking trySend/tryRecv
//! - Close semantics (recv returns null after close and drain)
//!
//! ## Design
//!
//! This implements Go's channel semantics:
//! - send() blocks if channel is full
//! - recv() blocks if channel is empty
//! - close() marks channel closed, recv returns null after drain
//! - Sending to closed channel returns error
//!
//! ## Memory Management
//!
//! The channel uses a fixed-size ring buffer allocated at init time.
//! No per-item allocation is needed.

const std = @import("std");
const Allocator = std.mem.Allocator;

/// A bounded MPMC channel with close support.
pub fn Channel(comptime T: type) type {
    return struct {
        const Self = @This();

        buffer: []T,
        capacity: usize,
        head: usize, // Read position
        tail: usize, // Write position
        len: usize, // Current items count

        mutex: std.Thread.Mutex,
        not_empty: std.Thread.Condition, // Signal when items available
        not_full: std.Thread.Condition, // Signal when space available

        closed: bool,
        allocator: Allocator,

        /// Initialize a new channel with given capacity.
        pub fn init(allocator: Allocator, capacity: usize) !Self {
            const buffer = try allocator.alloc(T, capacity);
            return Self{
                .buffer = buffer,
                .capacity = capacity,
                .head = 0,
                .tail = 0,
                .len = 0,
                .mutex = .{},
                .not_empty = .{},
                .not_full = .{},
                .closed = false,
                .allocator = allocator,
            };
        }

        /// Deinitialize the channel.
        pub fn deinit(self: *Self) void {
            self.allocator.free(self.buffer);
        }

        /// Close the channel.
        /// After close, send() returns error, recv() returns null after drain.
        pub fn close(self: *Self) void {
            self.mutex.lock();
            defer self.mutex.unlock();

            self.closed = true;
            // Wake all waiters
            self.not_empty.broadcast();
            self.not_full.broadcast();
        }

        /// Check if the channel is closed.
        pub fn isClosed(self: *Self) bool {
            self.mutex.lock();
            defer self.mutex.unlock();
            return self.closed;
        }

        /// Send an item to the channel.
        /// Blocks if the channel is full.
        /// Returns error.Closed if channel is closed.
        pub fn send(self: *Self, value: T) error{Closed}!void {
            self.mutex.lock();
            defer self.mutex.unlock();

            // Wait for space
            while (self.len >= self.capacity and !self.closed) {
                self.not_full.wait(&self.mutex);
            }

            if (self.closed) {
                return error.Closed;
            }

            self.buffer[self.tail] = value;
            self.tail = (self.tail + 1) % self.capacity;
            self.len += 1;

            self.not_empty.signal();
        }

        /// Try to send without blocking.
        /// Returns false if channel is full or closed.
        pub fn trySend(self: *Self, value: T) bool {
            self.mutex.lock();
            defer self.mutex.unlock();

            if (self.closed or self.len >= self.capacity) {
                return false;
            }

            self.buffer[self.tail] = value;
            self.tail = (self.tail + 1) % self.capacity;
            self.len += 1;

            self.not_empty.signal();
            return true;
        }

        /// Receive an item from the channel.
        /// Blocks if the channel is empty.
        /// Returns null if channel is closed and empty.
        pub fn recv(self: *Self) ?T {
            self.mutex.lock();
            defer self.mutex.unlock();

            // Wait for items
            while (self.len == 0 and !self.closed) {
                self.not_empty.wait(&self.mutex);
            }

            if (self.len == 0) {
                return null; // Closed and empty
            }

            const value = self.buffer[self.head];
            self.head = (self.head + 1) % self.capacity;
            self.len -= 1;

            self.not_full.signal();
            return value;
        }

        /// Try to receive without blocking.
        /// Returns null if channel is empty.
        pub fn tryRecv(self: *Self) ?T {
            self.mutex.lock();
            defer self.mutex.unlock();

            if (self.len == 0) {
                return null;
            }

            const value = self.buffer[self.head];
            self.head = (self.head + 1) % self.capacity;
            self.len -= 1;

            self.not_full.signal();
            return value;
        }

        /// Receive with timeout.
        /// Returns null if timeout or closed.
        pub fn recvTimeout(self: *Self, timeout_ns: u64) ?T {
            self.mutex.lock();
            defer self.mutex.unlock();

            // Wait for items with timeout
            while (self.len == 0 and !self.closed) {
                self.not_empty.timedWait(&self.mutex, timeout_ns) catch {
                    return null; // Timeout
                };
            }

            if (self.len == 0) {
                return null; // Closed and empty
            }

            const value = self.buffer[self.head];
            self.head = (self.head + 1) % self.capacity;
            self.len -= 1;

            self.not_full.signal();
            return value;
        }

        /// Get current number of items in channel.
        pub fn length(self: *Self) usize {
            self.mutex.lock();
            defer self.mutex.unlock();
            return self.len;
        }
    };
}

/// A simple one-shot signal (like Go's chan struct{} that's closed once).
/// Used for signaling completion (e.g., ready signal).
pub const Signal = struct {
    const Self = @This();

    mutex: std.Thread.Mutex,
    cond: std.Thread.Condition,
    signaled: bool,

    pub fn init() Self {
        return Self{
            .mutex = .{},
            .cond = .{},
            .signaled = false,
        };
    }

    /// Signal (like close(chan struct{})).
    /// Can only be called once.
    pub fn signal(self: *Self) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        self.signaled = true;
        self.cond.broadcast();
    }

    /// Wait for the signal.
    pub fn wait(self: *Self) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        while (!self.signaled) {
            self.cond.wait(&self.mutex);
        }
    }

    /// Wait with timeout. Returns true if signaled, false if timeout.
    pub fn waitTimeout(self: *Self, timeout_ns: u64) bool {
        self.mutex.lock();
        defer self.mutex.unlock();

        while (!self.signaled) {
            self.cond.timedWait(&self.mutex, timeout_ns) catch {
                return false; // Timeout
            };
        }
        return true;
    }

    /// Check if signaled without waiting.
    pub fn isSignaled(self: *Self) bool {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.signaled;
    }

    /// Reset the signal (for reuse).
    pub fn reset(self: *Self) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        self.signaled = false;
    }
};

// ============================================================================
// Tests
// ============================================================================

test "Channel basic send/recv" {
    var ch = try Channel(u32).init(std.testing.allocator, 4);
    defer ch.deinit();

    // Send items
    try ch.send(1);
    try ch.send(2);
    try ch.send(3);

    // Receive items
    try std.testing.expectEqual(@as(?u32, 1), ch.recv());
    try std.testing.expectEqual(@as(?u32, 2), ch.recv());
    try std.testing.expectEqual(@as(?u32, 3), ch.recv());
}

test "Channel trySend/tryRecv" {
    var ch = try Channel(u32).init(std.testing.allocator, 2);
    defer ch.deinit();

    // trySend should work until full
    try std.testing.expect(ch.trySend(1));
    try std.testing.expect(ch.trySend(2));
    try std.testing.expect(!ch.trySend(3)); // Full

    // tryRecv
    try std.testing.expectEqual(@as(?u32, 1), ch.tryRecv());
    try std.testing.expectEqual(@as(?u32, 2), ch.tryRecv());
    try std.testing.expectEqual(@as(?u32, null), ch.tryRecv()); // Empty
}

test "Channel close semantics" {
    var ch = try Channel(u32).init(std.testing.allocator, 4);
    defer ch.deinit();

    // Send before close
    try ch.send(1);
    try ch.send(2);

    // Close
    ch.close();

    // Recv should still get buffered items
    try std.testing.expectEqual(@as(?u32, 1), ch.recv());
    try std.testing.expectEqual(@as(?u32, 2), ch.recv());

    // Recv returns null after drain
    try std.testing.expectEqual(@as(?u32, null), ch.recv());

    // Send to closed channel returns error
    try std.testing.expectError(error.Closed, ch.send(3));
}

test "Signal basic" {
    var sig = Signal.init();

    try std.testing.expect(!sig.isSignaled());

    sig.signal();

    try std.testing.expect(sig.isSignaled());

    // Wait should return immediately
    sig.wait();
}

test "Signal reset" {
    var sig = Signal.init();

    sig.signal();
    try std.testing.expect(sig.isSignaled());

    sig.reset();
    try std.testing.expect(!sig.isSignaled());
}
