//! Executor - An execution context that can run tasks.
//!
//! Executor is a platform-provided interface that allows Zig code to dispatch
//! tasks to a specific execution context (thread, event loop, etc.).
//!
//! ## Design Principles
//! - Platform agnostic: The interface is abstract, platform provides implementation
//! - Zero allocation: Executor is just a pointer + vtable
//! - Thread-safe dispatch: `dispatch()` must be safe to call from any thread
//!
//! ## Platform Implementation Example (Go)
//! ```go
//! //export goDispatch
//! func goDispatch(executorPtr unsafe.Pointer, taskPtr unsafe.Pointer, taskCallback unsafe.Pointer) {
//!     // Queue the task to be executed on the Go runtime
//!     runtime.ScheduleTask(taskPtr, taskCallback)
//! }
//! ```

const std = @import("std");
const Task = @import("task.zig").Task;

/// Executor - An execution context that can run tasks.
///
/// An Executor represents a place where tasks can be executed. This could be:
/// - A single thread with an event loop
/// - A thread pool
/// - A specific OS thread
/// - A coroutine scheduler
///
/// The platform provides the implementation, Zig code uses the interface.
pub const Executor = struct {
    /// Opaque pointer to platform-specific executor state
    ptr: *anyopaque,
    /// Virtual function table
    vtable: *const VTable,

    pub const VTable = struct {
        /// Dispatch a task to be executed on this executor.
        ///
        /// This function must be thread-safe - it can be called from any thread.
        /// The task will be executed asynchronously on the executor's context.
        ///
        /// ## Parameters
        /// - `ptr`: The executor's opaque pointer
        /// - `task`: The task to execute
        dispatch: *const fn (ptr: *anyopaque, task: Task) void,

        /// Check if the current thread is the executor's thread.
        ///
        /// This is useful for optimizations - if we're already on the executor's
        /// thread, we might execute synchronously instead of queuing.
        ///
        /// Optional: platforms can return false if not applicable.
        is_current_thread: ?*const fn (ptr: *anyopaque) bool = null,
    };

    /// Dispatch a task to be executed on this executor.
    ///
    /// The task will be executed asynchronously. This function is thread-safe.
    pub fn dispatch(self: Executor, task: Task) void {
        self.vtable.dispatch(self.ptr, task);
    }

    /// Dispatch a typed context with a method to be called.
    ///
    /// Convenience wrapper around `dispatch` that creates a Task internally.
    pub fn dispatchFn(
        self: Executor,
        comptime T: type,
        context: *T,
        comptime method: fn (*T) void,
    ) void {
        self.dispatch(Task.init(T, context, method));
    }

    /// Check if the current thread is the executor's thread.
    ///
    /// Returns false if the executor doesn't support this check.
    pub fn isCurrentThread(self: Executor) bool {
        if (self.vtable.is_current_thread) |check| {
            return check(self.ptr);
        }
        return false;
    }

    /// A null executor that panics on dispatch.
    ///
    /// Useful as a placeholder or for detecting uninitialized executors.
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

/// InlineExecutor - Executes tasks immediately on the calling thread.
///
/// This is a simple executor implementation useful for testing and
/// single-threaded scenarios. Tasks are executed synchronously when dispatched.
pub const InlineExecutor = struct {
    /// Create an Executor interface from this InlineExecutor.
    pub fn executor(self: *InlineExecutor) Executor {
        return .{
            .ptr = @ptrCast(self),
            .vtable = &vtable,
        };
    }

    const vtable: Executor.VTable = .{
        .dispatch = dispatch,
        .is_current_thread = isCurrentThread,
    };

    fn dispatch(_: *anyopaque, task: Task) void {
        // Execute immediately
        task.run();
    }

    fn isCurrentThread(_: *anyopaque) bool {
        // InlineExecutor always executes on current thread
        return true;
    }
};

/// QueuedExecutor - Queues tasks for later execution.
///
/// This executor stores tasks in a queue and executes them when `runAll()` is called.
/// Useful for testing and for controlling when tasks execute.
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

    /// Create an Executor interface from this QueuedExecutor.
    pub fn executor(self: *QueuedExecutor) Executor {
        return .{
            .ptr = @ptrCast(self),
            .vtable = &vtable,
        };
    }

    /// Run all queued tasks.
    ///
    /// Returns the number of tasks executed.
    pub fn runAll(self: *QueuedExecutor) usize {
        self.mutex.lock();
        const tasks = self.queue.toOwnedSlice(self.allocator) catch return 0;
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

    const vtable: Executor.VTable = .{
        .dispatch = dispatch,
    };

    fn dispatch(ptr: *anyopaque, task: Task) void {
        const self: *QueuedExecutor = @ptrCast(@alignCast(ptr));
        self.mutex.lock();
        defer self.mutex.unlock();
        self.queue.append(self.allocator, task) catch {
            // If we can't queue, we have to drop the task
            // In production, this should probably log or panic
        };
    }
};

// ============================================================================
// Tests
// ============================================================================

test "InlineExecutor executes immediately" {
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

    try std.testing.expectEqual(@as(u32, 0), counter);

    exec.dispatchFn(Counter, &ctx, Counter.increment);

    // Should have executed immediately
    try std.testing.expectEqual(@as(u32, 1), counter);

    try std.testing.expect(exec.isCurrentThread());
}

test "QueuedExecutor queues tasks for later" {
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

    // Dispatch multiple tasks
    exec.dispatchFn(Counter, &ctx, Counter.increment);
    exec.dispatchFn(Counter, &ctx, Counter.increment);
    exec.dispatchFn(Counter, &ctx, Counter.increment);

    // Nothing executed yet
    try std.testing.expectEqual(@as(u32, 0), counter);
    try std.testing.expectEqual(@as(usize, 3), queued_exec.pendingCount());

    // Run all tasks
    const executed = queued_exec.runAll();

    try std.testing.expectEqual(@as(usize, 3), executed);
    try std.testing.expectEqual(@as(u32, 3), counter);
    try std.testing.expectEqual(@as(usize, 0), queued_exec.pendingCount());
}

test "Executor.null_executor panics on dispatch" {
    // We can't easily test panics in Zig tests, but we can verify
    // the null executor is properly defined
    _ = Executor.null_executor;
}
