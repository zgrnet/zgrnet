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
const Allocator = std.mem.Allocator;

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
