//! RingBuffer - A generic O(1) FIFO ring buffer implementation.

const std = @import("std");

/// RingBuffer - O(1) read/write from head/tail
pub fn RingBuffer(comptime T: type) type {
    return struct {
        const Self = @This();

        buf: []T,
        head: usize = 0,
        tail: usize = 0,
        allocator: std.mem.Allocator,

        pub fn init(allocator: std.mem.Allocator) Self {
            return .{
                .buf = &[_]T{},
                .head = 0,
                .tail = 0,
                .allocator = allocator,
            };
        }

        pub fn deinit(self: *Self) void {
            if (self.buf.len > 0) {
                self.allocator.free(self.buf);
            }
        }

        pub fn readableLength(self: *const Self) usize {
            if (self.tail >= self.head) {
                return self.tail - self.head;
            } else {
                return self.buf.len - self.head + self.tail;
            }
        }

        pub fn read(self: *Self, dest: []T) usize {
            const to_read = @min(dest.len, self.readableLength());
            if (to_read == 0) return 0;

            const head = self.head;
            const cap = self.buf.len;

            // Use @memcpy for efficient bulk copy (handles wrap-around with at most 2 copies)
            const part1_len = @min(to_read, cap - head);
            @memcpy(dest[0..part1_len], self.buf[head..][0..part1_len]);

            const part2_len = to_read - part1_len;
            if (part2_len > 0) {
                @memcpy(dest[part1_len..][0..part2_len], self.buf[0..part2_len]);
            }

            self.head = (head + to_read) % cap;
            return to_read;
        }

        pub fn write(self: *Self, src: []const T) !void {
            // Ensure capacity
            const needed = self.readableLength() + src.len + 1;
            if (needed > self.buf.len) {
                try self.grow(needed);
            }

            // Use @memcpy for efficient bulk copy (handles wrap-around)
            const tail = self.tail;
            const cap = self.buf.len;
            const part1_len = @min(src.len, cap - tail);
            @memcpy(self.buf[tail..][0..part1_len], src[0..part1_len]);

            const part2_len = src.len - part1_len;
            if (part2_len > 0) {
                @memcpy(self.buf[0..part2_len], src[part1_len..][0..part2_len]);
            }

            self.tail = (tail + src.len) % cap;
        }

        fn grow(self: *Self, min_cap: usize) !void {
            var new_cap = if (self.buf.len == 0) 64 else self.buf.len;
            while (new_cap < min_cap) {
                new_cap *= 2;
            }

            const new_buf = try self.allocator.alloc(T, new_cap);
            const len = self.readableLength();

            // Use @memcpy for efficient bulk copy (handles wrap-around)
            if (len > 0) {
                const head = self.head;
                const cap = self.buf.len;
                const part1_len = @min(len, cap - head);
                @memcpy(new_buf[0..part1_len], self.buf[head..][0..part1_len]);

                const part2_len = len - part1_len;
                if (part2_len > 0) {
                    @memcpy(new_buf[part1_len..][0..part2_len], self.buf[0..part2_len]);
                }
            }

            if (self.buf.len > 0) {
                self.allocator.free(self.buf);
            }

            self.buf = new_buf;
            self.head = 0;
            self.tail = len;
        }
    };
}
