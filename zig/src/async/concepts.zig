//! Comptime Constraints for Async Abstractions
//!
//! This module provides compile-time checks for async interface conformance.
//! Instead of runtime vtables, we use comptime duck typing with explicit checks.
//!
//! ## Usage
//! ```zig
//! pub fn MyAsyncType(comptime E: type) type {
//!     comptime assertExecutor(E);
//!     return struct { ... };
//! }
//! ```

const std = @import("std");
const Task = @import("task.zig").Task;
const TimerHandle = @import("timer.zig").TimerHandle;

// ============================================================================
// Executor Concept
// ============================================================================

/// Check if T implements the Executor interface.
///
/// Required methods:
/// - `dispatch(self: *T, task: Task) void`
///
/// Optional methods:
/// - `isCurrentThread(self: *T) bool`
pub fn isExecutor(comptime T: type) bool {
    if (!@hasDecl(T, "dispatch")) return false;

    const dispatch_info = @typeInfo(@TypeOf(@field(T, "dispatch")));
    if (dispatch_info != .@"fn") return false;

    // Check dispatch signature: fn(*T, Task) void
    const params = dispatch_info.@"fn".params;
    if (params.len != 2) return false;
    if (params[1].type != Task) return false;
    if (dispatch_info.@"fn".return_type != void) return false;

    return true;
}

/// Assert that T implements Executor at compile time.
pub fn assertExecutor(comptime T: type) void {
    if (!isExecutor(T)) {
        @compileError(std.fmt.comptimePrint(
            "Type '{s}' does not implement Executor interface. " ++
                "Required: fn dispatch(*{s}, Task) void",
            .{ @typeName(T), @typeName(T) },
        ));
    }
}

// ============================================================================
// TimerService Concept
// ============================================================================

/// Check if T implements the TimerService interface.
///
/// Required methods:
/// - `schedule(self: *T, delay_ms: u32, task: Task) TimerHandle`
/// - `cancel(self: *T, handle: TimerHandle) void`
///
/// Optional methods:
/// - `nowMs(self: *T) u64`
pub fn isTimerService(comptime T: type) bool {
    if (!@hasDecl(T, "schedule")) return false;
    if (!@hasDecl(T, "cancel")) return false;

    // Basic check - has the methods
    return true;
}

/// Assert that T implements TimerService at compile time.
pub fn assertTimerService(comptime T: type) void {
    if (!isTimerService(T)) {
        @compileError(std.fmt.comptimePrint(
            "Type '{s}' does not implement TimerService interface. " ++
                "Required: schedule(), cancel()",
            .{@typeName(T)},
        ));
    }
}

// ============================================================================
// IOService Concept
// ============================================================================

/// Check if T implements the IOService interface.
///
/// Required methods:
/// - `registerRead(self: *T, fd: fd_t, callback: ReadyCallback) void`
/// - `registerWrite(self: *T, fd: fd_t, callback: ReadyCallback) void`
/// - `unregister(self: *T, fd: fd_t) void`
/// - `poll(self: *T, timeout_ms: i32) usize`
/// - `wake(self: *T) void`
pub fn isIOService(comptime T: type) bool {
    if (!@hasDecl(T, "registerRead")) return false;
    if (!@hasDecl(T, "registerWrite")) return false;
    if (!@hasDecl(T, "unregister")) return false;
    if (!@hasDecl(T, "poll")) return false;
    if (!@hasDecl(T, "wake")) return false;

    return true;
}

/// Assert that T implements IOService at compile time.
pub fn assertIOService(comptime T: type) void {
    if (!isIOService(T)) {
        @compileError(std.fmt.comptimePrint(
            "Type '{s}' does not implement IOService interface. " ++
                "Required: registerRead(), registerWrite(), unregister(), poll(), wake()",
            .{@typeName(T)},
        ));
    }
}

// ============================================================================
// Tests
// ============================================================================

test "isExecutor checks dispatch method" {
    const ValidExecutor = struct {
        pub fn dispatch(_: *@This(), _: Task) void {}
    };

    const InvalidExecutor = struct {
        pub fn notDispatch(_: *@This()) void {}
    };

    try std.testing.expect(isExecutor(ValidExecutor));
    try std.testing.expect(!isExecutor(InvalidExecutor));
}

test "isTimerService checks schedule and cancel" {
    const ValidTimer = struct {
        pub fn schedule(_: *@This(), _: u32, _: Task) TimerHandle {
            return .{ .id = 0 };
        }
        pub fn cancel(_: *@This(), _: TimerHandle) void {}
    };

    const InvalidTimer = struct {
        pub fn schedule(_: *@This(), _: u32, _: Task) TimerHandle {
            return .{ .id = 0 };
        }
        // missing cancel
    };

    try std.testing.expect(isTimerService(ValidTimer));
    try std.testing.expect(!isTimerService(InvalidTimer));
}

test "isIOService checks all required methods" {
    const ValidIO = struct {
        pub fn registerRead(_: *@This(), _: std.posix.fd_t, _: anytype) void {}
        pub fn registerWrite(_: *@This(), _: std.posix.fd_t, _: anytype) void {}
        pub fn unregister(_: *@This(), _: std.posix.fd_t) void {}
        pub fn poll(_: *@This(), _: i32) usize {
            return 0;
        }
        pub fn wake(_: *@This()) void {}
    };

    const InvalidIO = struct {
        pub fn registerRead(_: *@This(), _: std.posix.fd_t, _: anytype) void {}
        // missing other methods
    };

    try std.testing.expect(isIOService(ValidIO));
    try std.testing.expect(!isIOService(InvalidIO));
}
