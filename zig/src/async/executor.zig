//! Executor - An execution context that can run tasks.
//!
//! ## Comptime vs Runtime Polymorphism
//!
//! This module provides both:
//! 1. **Direct methods** on implementations (comptime, zero overhead)
//! 2. **Executor vtable** for runtime polymorphism (when needed)
//!
//! Prefer using implementations directly with comptime generics:
//! ```zig
//! fn doWork(executor: anytype) void {
//!     executor.dispatch(my_task);
//! }
//! ```
//!
//! Use the vtable `Executor` type only when you need runtime polymorphism.
//!
//! ## Required Interface (comptime)
//!
//! Any type implementing Executor must have:
//! - `dispatch(self: *T, task: Task) void`
//!
//! Optional:
//! - `dispatchFn(self: *T, comptime C: type, ctx: *C, comptime method: fn(*C) void) void`
//! - `isCurrentThread(self: *T) bool`

const std = @import("std");
const Task = @import("task.zig").Task;

// ============================================================================
// Runtime Polymorphism (vtable-based) - for legacy/FFI use
// ============================================================================

/// Executor - Runtime polymorphic executor interface.
///
/// Use this when you need to store executors of different types in the same
/// variable or pass them through FFI boundaries. For comptime polymorphism,
/// use implementations directly with `anytype`.
pub const Executor = struct {
    /// Opaque pointer to platform-specific executor state
    ptr: *anyopaque,
    /// Virtual function table
    vtable: *const VTable,

    pub const VTable = struct {
        dispatch: *const fn (ptr: *anyopaque, task: Task) void,
        is_current_thread: ?*const fn (ptr: *anyopaque) bool = null,
    };

    /// Dispatch a task to be executed on this executor.
    pub fn dispatch(self: Executor, task: Task) void {
        self.vtable.dispatch(self.ptr, task);
    }

    /// Dispatch a typed context with a method to be called.
    pub fn dispatchFn(
        self: Executor,
        comptime T: type,
        context: *T,
        comptime method: fn (*T) void,
    ) void {
        self.dispatch(Task.init(T, context, method));
    }

    /// Check if the current thread is the executor's thread.
    pub fn isCurrentThread(self: Executor) bool {
        if (self.vtable.is_current_thread) |check| {
            return check(self.ptr);
        }
        return false;
    }

    /// A null executor that panics on dispatch.
    pub const null_executor: Executor = .{
        .ptr = undefined,
        .vtable = &.{
            .dispatch = struct {
                fn panic(_: *anyopaque, _: Task) void {
                    @panic("dispatch called on null executor");
                }
            }.panic,
        },
    };
};

// ============================================================================
// Implementations
// ============================================================================

/// InlineExecutor - Executes tasks immediately on the calling thread.
///
/// This is a simple executor implementation useful for testing and
/// single-threaded scenarios. Tasks are executed synchronously when dispatched.
///
/// ## Direct Usage (comptime, zero overhead)
/// ```zig
/// var exec = InlineExecutor{};
/// exec.dispatch(my_task);
/// ```
///
/// ## Runtime Polymorphism
/// ```zig
/// var exec = InlineExecutor{};
/// const executor: Executor = exec.executor();
/// executor.dispatch(my_task);
/// ```
pub const InlineExecutor = struct {
    /// Dispatch a task to be executed immediately.
    ///
    /// Direct method - use this for comptime polymorphism.
    pub fn dispatch(_: *InlineExecutor, task: Task) void {
        task.run();
    }

    /// Dispatch a typed context with a method to be called.
    pub fn dispatchFn(
        self: *InlineExecutor,
        comptime T: type,
        context: *T,
        comptime method: fn (*T) void,
    ) void {
        self.dispatch(Task.init(T, context, method));
    }

    /// Check if the current thread is the executor's thread.
    pub fn isCurrentThread(_: *InlineExecutor) bool {
        return true;
    }

    /// Create an Executor interface from this InlineExecutor.
    ///
    /// Use this only when runtime polymorphism is needed.
    pub fn executor(self: *InlineExecutor) Executor {
        return .{
            .ptr = @ptrCast(self),
            .vtable = &vtable,
        };
    }

    const vtable: Executor.VTable = .{
        .dispatch = dispatchVtable,
        .is_current_thread = isCurrentThreadVtable,
    };

    fn dispatchVtable(_: *anyopaque, task: Task) void {
        task.run();
    }

    fn isCurrentThreadVtable(_: *anyopaque) bool {
        return true;
    }
};

/// QueuedExecutor - Queues tasks for later execution.
///
/// This executor stores tasks in a queue and executes them when `runAll()` is called.
/// Useful for testing and for controlling when tasks execute.
///
/// ## Direct Usage (comptime, zero overhead)
/// ```zig
/// var exec = QueuedExecutor.init(allocator);
/// exec.dispatch(my_task);
/// _ = exec.runAll();
/// ```
pub const QueuedExecutor = struct {
    const TaskQueue = std.ArrayListAligned(Task, null);

    queue: TaskQueue,
    allocator: std.mem.Allocator,
    mutex: std.Thread.Mutex = .{},

    pub fn init(allocator: std.mem.Allocator) QueuedExecutor {
        return .{
            .queue = .{},
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *QueuedExecutor) void {
        self.queue.deinit(self.allocator);
    }

    /// Dispatch a task to be queued for later execution.
    ///
    /// Direct method - use this for comptime polymorphism.
    pub fn dispatch(self: *QueuedExecutor, task: Task) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        self.queue.append(self.allocator, task) catch {};
    }

    /// Dispatch a typed context with a method to be called.
    pub fn dispatchFn(
        self: *QueuedExecutor,
        comptime T: type,
        context: *T,
        comptime method: fn (*T) void,
    ) void {
        self.dispatch(Task.init(T, context, method));
    }

    /// Run all queued tasks.
    ///
    /// Returns the number of tasks executed.
    pub fn runAll(self: *QueuedExecutor) usize {
        self.mutex.lock();
        const tasks = self.queue.toOwnedSlice(self.allocator) catch {
            self.mutex.unlock();
            return 0;
        };
        self.mutex.unlock();

        defer self.allocator.free(tasks);

        for (tasks) |task| {
            task.run();
        }

        return tasks.len;
    }

    /// Get the number of pending tasks.
    pub fn pendingCount(self: *QueuedExecutor) usize {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.queue.items.len;
    }

    /// Create an Executor interface from this QueuedExecutor.
    ///
    /// Use this only when runtime polymorphism is needed.
    pub fn executor(self: *QueuedExecutor) Executor {
        return .{
            .ptr = @ptrCast(self),
            .vtable = &vtable,
        };
    }

    const vtable: Executor.VTable = .{
        .dispatch = dispatchVtable,
    };

    fn dispatchVtable(ptr: *anyopaque, task: Task) void {
        const self: *QueuedExecutor = @ptrCast(@alignCast(ptr));
        self.dispatch(task);
    }
};

// ============================================================================
// Tests
// ============================================================================

test "InlineExecutor direct dispatch (comptime)" {
    var exec = InlineExecutor{};
    var counter: u32 = 0;

    const Counter = struct {
        count: *u32,
        fn increment(self: *@This()) void {
            self.count.* += 1;
        }
    };

    var ctx = Counter{ .count = &counter };

    // Direct dispatch - comptime polymorphism
    exec.dispatch(Task.init(Counter, &ctx, Counter.increment));
    try std.testing.expectEqual(@as(u32, 1), counter);

    // dispatchFn convenience
    exec.dispatchFn(Counter, &ctx, Counter.increment);
    try std.testing.expectEqual(@as(u32, 2), counter);
}

test "InlineExecutor vtable dispatch (runtime)" {
    var inline_exec = InlineExecutor{};
    const exec = inline_exec.executor();

    var counter: u32 = 0;

    const Counter = struct {
        count: *u32,
        fn increment(self: *@This()) void {
            self.count.* += 1;
        }
    };

    var ctx = Counter{ .count = &counter };

    exec.dispatchFn(Counter, &ctx, Counter.increment);
    try std.testing.expectEqual(@as(u32, 1), counter);
    try std.testing.expect(exec.isCurrentThread());
}

test "QueuedExecutor direct dispatch (comptime)" {
    var exec = QueuedExecutor.init(std.testing.allocator);
    defer exec.deinit();

    var counter: u32 = 0;

    const Counter = struct {
        count: *u32,
        fn increment(self: *@This()) void {
            self.count.* += 1;
        }
    };

    var ctx = Counter{ .count = &counter };

    // Direct dispatch
    exec.dispatch(Task.init(Counter, &ctx, Counter.increment));
    exec.dispatch(Task.init(Counter, &ctx, Counter.increment));

    try std.testing.expectEqual(@as(u32, 0), counter);
    try std.testing.expectEqual(@as(usize, 2), exec.pendingCount());

    const executed = exec.runAll();
    try std.testing.expectEqual(@as(usize, 2), executed);
    try std.testing.expectEqual(@as(u32, 2), counter);
}

test "QueuedExecutor vtable dispatch (runtime)" {
    var queued_exec = QueuedExecutor.init(std.testing.allocator);
    defer queued_exec.deinit();

    const exec = queued_exec.executor();

    var counter: u32 = 0;

    const Counter = struct {
        count: *u32,
        fn increment(self: *@This()) void {
            self.count.* += 1;
        }
    };

    var ctx = Counter{ .count = &counter };

    exec.dispatchFn(Counter, &ctx, Counter.increment);
    exec.dispatchFn(Counter, &ctx, Counter.increment);
    exec.dispatchFn(Counter, &ctx, Counter.increment);

    try std.testing.expectEqual(@as(u32, 0), counter);

    const executed = queued_exec.runAll();
    try std.testing.expectEqual(@as(usize, 3), executed);
    try std.testing.expectEqual(@as(u32, 3), counter);
}

test "Executor.null_executor" {
    _ = Executor.null_executor;
}
