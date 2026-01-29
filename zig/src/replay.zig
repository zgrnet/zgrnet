//! Replay protection using sliding window.

const std = @import("std");
const Mutex = std.Thread.Mutex;

/// Size of the sliding window in bits.
pub const window_size: usize = 2048;

/// Number of u64 words needed for the bitmap.
const window_words: usize = window_size / 64;

/// Replay filter using sliding window algorithm.
///
/// Tracks received nonces and rejects duplicates or nonces that are too old.
pub const ReplayFilter = struct {
    mutex: Mutex = .{},
    bitmap: [window_words]u64 = [_]u64{0} ** window_words,
    max_nonce: u64 = 0,

    /// Creates a new replay filter.
    pub fn init() ReplayFilter {
        return .{};
    }

    /// Checks if a nonce is valid (not a replay).
    /// Returns true if valid, false if replay.
    pub fn check(self: *ReplayFilter, nonce: u64) bool {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.checkLocked(nonce);
    }

    fn checkLocked(self: *const ReplayFilter, nonce: u64) bool {
        if (nonce > self.max_nonce) {
            return true;
        }

        const delta = self.max_nonce - nonce;
        if (delta >= window_size) {
            return false;
        }

        const word_index: usize = @intCast(delta / 64);
        const bit_index: u6 = @intCast(delta % 64);
        return (self.bitmap[word_index] & (@as(u64, 1) << bit_index)) == 0;
    }

    /// Updates the filter with a nonce.
    pub fn update(self: *ReplayFilter, nonce: u64) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        self.updateLocked(nonce);
    }

    fn updateLocked(self: *ReplayFilter, nonce: u64) void {
        if (nonce > self.max_nonce) {
            const shift = nonce - self.max_nonce;
            self.slideWindow(shift);
            self.max_nonce = nonce;
            self.bitmap[0] |= 1;
        } else {
            const delta = self.max_nonce - nonce;
            if (delta < window_size) {
                const word_index: usize = @intCast(delta / 64);
                const bit_index: u6 = @intCast(delta % 64);
                self.bitmap[word_index] |= @as(u64, 1) << bit_index;
            }
        }
    }

    /// Atomically checks and updates.
    /// Returns true if nonce is valid and was recorded.
    pub fn checkAndUpdate(self: *ReplayFilter, nonce: u64) bool {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (!self.checkLocked(nonce)) {
            return false;
        }
        self.updateLocked(nonce);
        return true;
    }

    fn slideWindow(self: *ReplayFilter, shift: u64) void {
        if (shift >= window_size) {
            self.bitmap = [_]u64{0} ** window_words;
            return;
        }

        const word_shift: usize = @intCast(shift / 64);
        const bit_shift: u6 = @intCast(shift % 64);

        // First handle word shifts using memmove for efficiency
        if (word_shift > 0) {
            const src = self.bitmap[0 .. window_words - word_shift];
            const dst = self.bitmap[word_shift..window_words];
            // Use backward copy to handle overlapping regions
            std.mem.copyBackwards(u64, dst, src);
            // Clear the lower words
            @memset(self.bitmap[0..word_shift], 0);
        }

        // Then handle bit shifts
        if (bit_shift > 0) {
            var carry: u64 = 0;
            const complement_shift: u6 = @intCast(64 - @as(u7, bit_shift));
            for (0..window_words) |i| {
                const new_carry = self.bitmap[i] >> complement_shift;
                self.bitmap[i] = (self.bitmap[i] << bit_shift) | carry;
                carry = new_carry;
            }
        }
    }

    /// Resets the filter.
    pub fn reset(self: *ReplayFilter) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        self.bitmap = [_]u64{0} ** window_words;
        self.max_nonce = 0;
    }

    /// Returns the highest nonce seen.
    pub fn maxNonce(self: *ReplayFilter) u64 {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.max_nonce;
    }
};

// Tests
test "sequential" {
    var rf = ReplayFilter.init();
    for (0..100) |i| {
        try std.testing.expect(rf.checkAndUpdate(i));
    }
}

test "duplicate" {
    var rf = ReplayFilter.init();
    try std.testing.expect(rf.checkAndUpdate(42));
    try std.testing.expect(!rf.checkAndUpdate(42));
}

test "out of order" {
    var rf = ReplayFilter.init();
    const nonces = [_]u64{ 100, 50, 75, 25, 99, 1 };

    for (nonces) |n| {
        try std.testing.expect(rf.checkAndUpdate(n));
    }

    for (nonces) |n| {
        try std.testing.expect(!rf.checkAndUpdate(n));
    }
}

test "window boundary" {
    var rf = ReplayFilter.init();

    try std.testing.expect(rf.checkAndUpdate(window_size + 100));

    // Just within window
    try std.testing.expect(rf.checkAndUpdate(101));

    // Outside window
    try std.testing.expect(!rf.checkAndUpdate(100));
}

test "too old" {
    var rf = ReplayFilter.init();
    try std.testing.expect(rf.checkAndUpdate(5000));

    // Outside window (5000 - 2047 = 2953)
    const outside = [_]u64{ 0, 1, 100, 2952 };
    for (outside) |n| {
        try std.testing.expect(!rf.checkAndUpdate(n));
    }

    // Within window
    const inside = [_]u64{ 2953, 3000, 4000, 4999 };
    for (inside) |n| {
        try std.testing.expect(rf.checkAndUpdate(n));
    }
}

test "large jump" {
    var rf = ReplayFilter.init();

    for (0..10) |i| {
        _ = rf.checkAndUpdate(i);
    }

    try std.testing.expect(rf.checkAndUpdate(10000));

    for (0..10) |i| {
        try std.testing.expect(!rf.checkAndUpdate(i));
    }
}

test "max nonce" {
    var rf = ReplayFilter.init();
    try std.testing.expectEqual(@as(u64, 0), rf.maxNonce());

    _ = rf.checkAndUpdate(100);
    try std.testing.expectEqual(@as(u64, 100), rf.maxNonce());

    _ = rf.checkAndUpdate(50);
    try std.testing.expectEqual(@as(u64, 100), rf.maxNonce());

    _ = rf.checkAndUpdate(200);
    try std.testing.expectEqual(@as(u64, 200), rf.maxNonce());
}

test "reset" {
    var rf = ReplayFilter.init();

    for (0..100) |i| {
        _ = rf.checkAndUpdate(i);
    }

    rf.reset();

    for (0..100) |i| {
        try std.testing.expect(rf.checkAndUpdate(i));
    }
}

test "check without update" {
    var rf = ReplayFilter.init();

    try std.testing.expect(rf.check(100));
    try std.testing.expect(rf.check(100)); // Still true

    rf.update(100);
    try std.testing.expect(!rf.check(100)); // Now false
}

test "bit boundaries" {
    var rf = ReplayFilter.init();

    const boundaries = [_]u64{ 63, 64, 65, 127, 128, 129, 2047 };
    for (boundaries) |n| {
        try std.testing.expect(rf.checkAndUpdate(n));
    }

    for (boundaries) |n| {
        try std.testing.expect(!rf.checkAndUpdate(n));
    }
}
