//! MPSC Queue - Multi-Producer Single-Consumer Queue
//!
//! A thread-safe queue optimized for the actor pattern where multiple threads
//! can send messages but only one thread (the actor) consumes them.
//!
//! ## Implementation
//!
//! This implementation uses a simple mutex-protected linked list for correctness.
//! For high-performance scenarios, consider using a lock-free implementation.
//!
//! ## Memory Management
//!
//! The queue allocates nodes for each pushed item. The caller provides an
//! allocator, and nodes are freed when items are popped.

const std = @import("std");

/// A multi-producer single-consumer queue.
///
/// Multiple threads can safely push items concurrently.
/// Only one thread should pop items (typically the actor thread).
pub fn MpscQueue(comptime T: type) type {
    return struct {
        const Self = @This();

        /// Internal node structure
        const Node = struct {
            value: T,
            next: ?*Node,
        };

        /// Head of the queue (consumer reads from here)
        head: ?*Node,

        /// Tail of the queue (producers push here)
        tail: ?*Node,

        /// Allocator for nodes
        allocator: std.mem.Allocator,

        /// Mutex for thread safety
        mutex: std.Thread.Mutex,

        /// Initialize a new MPSC queue.
        pub fn init(allocator: std.mem.Allocator) Self {
            return .{
                .head = null,
                .tail = null,
                .allocator = allocator,
                .mutex = .{},
            };
        }

        /// Deinitialize the queue, freeing any remaining nodes.
        ///
        /// Note: This is NOT thread-safe. Ensure no other threads are
        /// accessing the queue when calling deinit.
        pub fn deinit(self: *Self) void {
            // Pop and free all remaining items
            while (self.pop()) |_| {}
        }

        /// Push an item to the queue.
        ///
        /// This is thread-safe and can be called from multiple threads.
        /// Returns false if allocation fails.
        pub fn push(self: *Self, value: T) bool {
            const node = self.allocator.create(Node) catch return false;
            node.* = .{
                .value = value,
                .next = null,
            };

            self.mutex.lock();
            defer self.mutex.unlock();

            if (self.tail) |t| {
                t.next = node;
                self.tail = node;
            } else {
                self.head = node;
                self.tail = node;
            }

            return true;
        }

        /// Pop an item from the queue.
        ///
        /// This is NOT thread-safe for multiple consumers.
        /// Only one thread should call pop().
        ///
        /// Returns null if the queue is empty.
        pub fn pop(self: *Self) ?T {
            self.mutex.lock();
            defer self.mutex.unlock();

            const head = self.head orelse return null;
            const value = head.value;

            self.head = head.next;
            if (self.head == null) {
                self.tail = null;
            }

            self.allocator.destroy(head);
            return value;
        }

        /// Check if the queue appears empty.
        pub fn isEmpty(self: *Self) bool {
            self.mutex.lock();
            defer self.mutex.unlock();
            return self.head == null;
        }
    };
}

/// A simplified bounded MPSC queue using a mutex.
///
/// For cases where lock-free complexity isn't needed, this provides
/// a simpler alternative with bounded capacity.
pub fn BoundedMpscQueue(comptime T: type, comptime capacity: usize) type {
    return struct {
        const Self = @This();

        buffer: [capacity]T,
        head: usize,
        tail: usize,
        len: usize,
        mutex: std.Thread.Mutex,
        not_empty: std.Thread.Condition,

        pub fn init() Self {
            return .{
                .buffer = undefined,
                .head = 0,
                .tail = 0,
                .len = 0,
                .mutex = .{},
                .not_empty = .{},
            };
        }

        /// Push an item to the queue.
        ///
        /// Returns false if the queue is full.
        pub fn push(self: *Self, value: T) bool {
            self.mutex.lock();
            defer self.mutex.unlock();

            if (self.len >= capacity) {
                return false; // Queue full
            }

            self.buffer[self.tail] = value;
            self.tail = (self.tail + 1) % capacity;
            self.len += 1;

            self.not_empty.signal();
            return true;
        }

        /// Pop an item from the queue.
        ///
        /// Returns null if the queue is empty.
        pub fn pop(self: *Self) ?T {
            self.mutex.lock();
            defer self.mutex.unlock();

            if (self.len == 0) {
                return null;
            }

            const value = self.buffer[self.head];
            self.head = (self.head + 1) % capacity;
            self.len -= 1;

            return value;
        }

        /// Pop an item, waiting if the queue is empty.
        ///
        /// Blocks until an item is available or timeout_ns nanoseconds pass.
        /// Returns null on timeout.
        pub fn popWait(self: *Self, timeout_ns: u64) ?T {
            self.mutex.lock();
            defer self.mutex.unlock();

            while (self.len == 0) {
                self.not_empty.timedWait(&self.mutex, timeout_ns) catch {
                    return null; // Timeout
                };
            }

            const value = self.buffer[self.head];
            self.head = (self.head + 1) % capacity;
            self.len -= 1;

            return value;
        }

        /// Get the current number of items in the queue.
        pub fn length(self: *Self) usize {
            self.mutex.lock();
            defer self.mutex.unlock();
            return self.len;
        }
    };
}

// ============================================================================
// Tests
// ============================================================================

test "MpscQueue single-threaded push/pop" {
    var queue = MpscQueue(u32).init(std.testing.allocator);
    defer queue.deinit();

    try std.testing.expect(queue.isEmpty());

    // Push some items
    try std.testing.expect(queue.push(1));
    try std.testing.expect(queue.push(2));
    try std.testing.expect(queue.push(3));

    try std.testing.expect(!queue.isEmpty());

    // Pop them back
    try std.testing.expectEqual(@as(?u32, 1), queue.pop());
    try std.testing.expectEqual(@as(?u32, 2), queue.pop());
    try std.testing.expectEqual(@as(?u32, 3), queue.pop());
    try std.testing.expectEqual(@as(?u32, null), queue.pop());

    try std.testing.expect(queue.isEmpty());
}

test "MpscQueue push after empty" {
    var queue = MpscQueue(u32).init(std.testing.allocator);
    defer queue.deinit();

    // Push and drain
    try std.testing.expect(queue.push(42));
    try std.testing.expectEqual(@as(?u32, 42), queue.pop());
    try std.testing.expect(queue.isEmpty());

    // Push again after empty
    try std.testing.expect(queue.push(100));
    try std.testing.expect(!queue.isEmpty());
    try std.testing.expectEqual(@as(?u32, 100), queue.pop());
}

test "BoundedMpscQueue basic operations" {
    var queue = BoundedMpscQueue(u32, 4).init();

    // Push items
    try std.testing.expect(queue.push(1));
    try std.testing.expect(queue.push(2));
    try std.testing.expect(queue.push(3));
    try std.testing.expect(queue.push(4));

    // Queue should be full
    try std.testing.expect(!queue.push(5));

    try std.testing.expectEqual(@as(usize, 4), queue.length());

    // Pop items
    try std.testing.expectEqual(@as(?u32, 1), queue.pop());
    try std.testing.expectEqual(@as(?u32, 2), queue.pop());

    // Can push again
    try std.testing.expect(queue.push(5));

    try std.testing.expectEqual(@as(?u32, 3), queue.pop());
    try std.testing.expectEqual(@as(?u32, 4), queue.pop());
    try std.testing.expectEqual(@as(?u32, 5), queue.pop());
    try std.testing.expectEqual(@as(?u32, null), queue.pop());
}

test "MpscQueue with struct values" {
    const Message = struct {
        id: u32,
        data: []const u8,
    };

    var queue = MpscQueue(Message).init(std.testing.allocator);
    defer queue.deinit();

    try std.testing.expect(queue.push(.{ .id = 1, .data = "hello" }));
    try std.testing.expect(queue.push(.{ .id = 2, .data = "world" }));

    const msg1 = queue.pop().?;
    try std.testing.expectEqual(@as(u32, 1), msg1.id);
    try std.testing.expectEqualStrings("hello", msg1.data);

    const msg2 = queue.pop().?;
    try std.testing.expectEqual(@as(u32, 2), msg2.id);
    try std.testing.expectEqualStrings("world", msg2.data);
}
