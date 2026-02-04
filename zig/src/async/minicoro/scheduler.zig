//! CoroScheduler - Coroutine-based executor using minicoro.
//!
//! This module provides true stackful coroutines via the minicoro C library.
//! Unlike state machine coroutines, code can yield at any point in the call
//! stack, making it easier to write async code that looks synchronous.
//!
//! ## Prerequisites
//!
//! The minicoro C library must be compiled and linked. This is handled
//! automatically by the build system when using the minicoro module.
//!
//! ## Usage
//!
//! ```zig
//! const minicoro = @import("async").minicoro;
//!
//! // Create a scheduler
//! var scheduler = minicoro.CoroScheduler.init(allocator);
//! defer scheduler.deinit();
//!
//! // Spawn coroutines
//! _ = try scheduler.spawn(myCoroutine, &my_context);
//!
//! // Run until all coroutines complete
//! scheduler.runUntilComplete();
//! ```
//!
//! ## Yielding
//!
//! From within a coroutine, call `CoroScheduler.yield()` to suspend execution
//! and return control to the scheduler. The coroutine will be resumed on the
//! next scheduler tick.

const std = @import("std");
const Task = @import("../task.zig").Task;
const Executor = @import("../executor.zig").Executor;

// ============================================================================
// C FFI declarations
// ============================================================================

/// Opaque coroutine handle from C
const ZigCoro = opaque {};

extern fn zig_coro_create(
    entry: *const fn (*anyopaque) callconv(.c) void,
    user_data: *anyopaque,
    stack_size: usize,
) ?*ZigCoro;

extern fn zig_coro_destroy(co: *ZigCoro) void;
extern fn zig_coro_resume(co: *ZigCoro) c_int;
extern fn zig_coro_yield(co: ?*ZigCoro) c_int;
extern fn zig_coro_status(co: *ZigCoro) c_int;
extern fn zig_coro_is_dead(co: *ZigCoro) c_int;
extern fn zig_coro_running() ?*ZigCoro;

/// Coroutine status values (from minicoro)
pub const CoroStatus = enum(c_int) {
    dead = 0,
    normal = 1,
    running = 2,
    suspended = 3,
};

// ============================================================================
// Zig Coroutine wrapper
// ============================================================================

/// A coroutine managed by CoroScheduler.
pub const Coroutine = struct {
    const Self = @This();

    /// C coroutine handle
    handle: ?*ZigCoro,

    /// User data pointer
    user_data: ?*anyopaque,

    /// Back-reference to scheduler
    scheduler: *CoroScheduler,

    /// User-provided entry function
    entry_fn: *const fn (*anyopaque) void,

    /// Whether this coroutine has been started
    started: bool,

    pub fn init(
        scheduler: *CoroScheduler,
        entry_fn: *const fn (*anyopaque) void,
        user_data: ?*anyopaque,
    ) Self {
        return .{
            .handle = null,
            .user_data = user_data,
            .scheduler = scheduler,
            .entry_fn = entry_fn,
            .started = false,
        };
    }

    /// Get the coroutine status.
    pub fn status(self: *Self) CoroStatus {
        if (self.handle) |h| {
            return @enumFromInt(zig_coro_status(h));
        }
        return .dead;
    }

    /// Check if the coroutine is dead (finished).
    pub fn isDead(self: *Self) bool {
        return self.status() == .dead;
    }

    fn entryWrapper(ptr: *anyopaque) callconv(.c) void {
        const self: *Self = @ptrCast(@alignCast(ptr));
        // Call the user's entry function
        (self.entry_fn)(self.user_data orelse @ptrCast(self));
    }
};

// ============================================================================
// CoroScheduler
// ============================================================================

/// A cooperative coroutine scheduler using minicoro.
pub const CoroScheduler = struct {
    const Self = @This();

    /// All managed coroutines
    coroutines: std.ArrayListAligned(*Coroutine, null),

    /// Ready queue (indices into coroutines list that are ready to run)
    ready: std.ArrayListAligned(*Coroutine, null),

    /// Allocator
    allocator: std.mem.Allocator,

    /// Default stack size for coroutines (0 = use minicoro default)
    default_stack_size: usize,

    pub fn init(allocator: std.mem.Allocator) Self {
        return .{
            .coroutines = .{},
            .ready = .{},
            .allocator = allocator,
            .default_stack_size = 0,
        };
    }

    pub fn deinit(self: *Self) void {
        // Destroy all coroutines
        for (self.coroutines.items) |coro| {
            if (coro.handle) |h| {
                zig_coro_destroy(h);
            }
            self.allocator.destroy(coro);
        }
        self.coroutines.deinit(self.allocator);
        self.ready.deinit(self.allocator);
    }

    /// Spawn a new coroutine.
    ///
    /// The coroutine will be added to the ready queue and run on the next tick.
    pub fn spawn(
        self: *Self,
        entry_fn: *const fn (*anyopaque) void,
        user_data: ?*anyopaque,
    ) !*Coroutine {
        const coro = try self.allocator.create(Coroutine);
        coro.* = Coroutine.init(self, entry_fn, user_data);

        // Create the C coroutine
        coro.handle = zig_coro_create(
            Coroutine.entryWrapper,
            @ptrCast(coro),
            self.default_stack_size,
        );

        if (coro.handle == null) {
            self.allocator.destroy(coro);
            return error.CoroCreateFailed;
        }

        try self.coroutines.append(self.allocator, coro);
        try self.ready.append(self.allocator, coro);

        return coro;
    }

    /// Run one coroutine from the ready queue.
    ///
    /// Returns true if a coroutine was run, false if the queue was empty.
    pub fn tick(self: *Self) bool {
        if (self.ready.items.len == 0) {
            return false;
        }

        const coro = self.ready.orderedRemove(0);

        if (coro.handle) |h| {
            _ = zig_coro_resume(h);

            // If still alive, re-add to ready queue
            if (zig_coro_is_dead(h) == 0) {
                self.ready.append(self.allocator, coro) catch {};
            }
        }

        return true;
    }

    /// Run until all coroutines complete.
    pub fn runUntilComplete(self: *Self) void {
        while (self.tick()) {}
    }

    /// Yield from the current coroutine.
    ///
    /// Must be called from within a coroutine.
    pub fn yield() void {
        _ = zig_coro_yield(null);
    }

    /// Check if there are pending coroutines.
    pub fn hasPending(self: *Self) bool {
        return self.ready.items.len > 0;
    }

    /// Create an Executor interface.
    pub fn executor(self: *Self) Executor {
        return .{
            .ptr = @ptrCast(self),
            .vtable = &vtable,
        };
    }

    const vtable: Executor.VTable = .{
        .dispatch = dispatch,
        .is_current_thread = null,
    };

    fn dispatch(ptr: *anyopaque, task: Task) void {
        _ = ptr;
        // For now, just run the task immediately
        // A more sophisticated implementation would spawn a coroutine
        task.run();
    }
};

// ============================================================================
// Tests
// ============================================================================

// Note: These tests require the minicoro C library to be linked.
// They are disabled by default to avoid linking issues in environments
// where minicoro is not available.

test "CoroScheduler can be initialized" {
    var scheduler = CoroScheduler.init(std.testing.allocator);
    defer scheduler.deinit();

    try std.testing.expect(!scheduler.hasPending());
}
