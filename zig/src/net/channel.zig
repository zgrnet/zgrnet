//! Channel compatibility layer for embed-zig selector branch
//!
//! Provides the old Channel(T, N, Rt) and Signal(Rt) APIs using
//! the new platform-specific implementations.

const std = @import("std");

// Use platform's Channel (from selector branch)
const platform = @import("std_impl");
const PlatformChannel = platform.channel.Channel;

// Use local Signal implementation
const SignalMod = @import("../signal.zig");

/// Bounded channel with Go chan semantics (compatibility wrapper)
///
/// - `T`: element type
/// - `N`: buffer capacity
/// - `Rt`: Runtime type (ignored, for API compatibility)
pub fn Channel(comptime T: type, comptime N: usize, comptime Rt: type) type {
    _ = Rt; // Runtime is not needed in selector branch

    return struct {
        const Self = @This();
        const Inner = PlatformChannel(T, N);

        inner: Inner,

        pub fn init() Self {
            return .{ .inner = Inner.init() catch @panic("Channel init failed") };
        }

        pub fn deinit(self: *Self) void {
            self.inner.deinit();
        }

        pub fn send(self: *Self, item: T) error{Closed}!void {
            return self.inner.send(item);
        }

        pub fn trySend(self: *Self, item: T) error{ Closed, Full }!void {
            return self.inner.trySend(item);
        }

        pub fn recv(self: *Self) ?T {
            return self.inner.recv();
        }

        pub fn tryRecv(self: *Self) ?T {
            return self.inner.tryRecv();
        }

        pub fn close(self: *Self) void {
            self.inner.close();
        }

        pub fn isClosed(self: *Self) bool {
            return self.inner.isClosed();
        }

        pub fn count(self: *Self) usize {
            return self.inner.count();
        }

        pub fn isEmpty(self: *Self) bool {
            return self.inner.isEmpty();
        }
    };
}

/// Signal type (re-export from signal.zig)
pub fn Signal(comptime Rt: type) type {
    return SignalMod.Signal(Rt);
}
