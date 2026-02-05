//! Task - A callable unit of work.
//!
//! Task is a type-erased callable that can be dispatched to an Executor.
//! It's designed to be zero-allocation when used with stack-allocated contexts.
//!
//! ## Design Principles
//! - Zero allocation: Task itself doesn't allocate, context lifetime is caller's responsibility
//! - Type-safe: Uses comptime to create type-safe callbacks
//! - Platform agnostic: No OS dependencies
//!
//! ## Usage
//! ```zig
//! const MyContext = struct {
//!     value: u32,
//!     pub fn execute(self: *MyContext) void {
//!         // Do work with self.value
//!     }
//! };
//!
//! var ctx = MyContext{ .value = 42 };
//! const task = Task.init(&ctx, MyContext.execute);
//! task.run(); // Calls ctx.execute()
//! ```

const std = @import("std");

/// Task - A type-erased callable unit of work.
///
/// A Task wraps a pointer and a callback function, allowing any context
/// to be executed through a uniform interface. The caller is responsible
/// for ensuring the context outlives the task.
pub const Task = struct {
    /// Opaque pointer to the context
    ptr: *anyopaque,
    /// Callback function that will be invoked with the context pointer
    callback: *const fn (ptr: *anyopaque) void,

    /// Create a task from a typed context and method.
    ///
    /// This is the recommended way to create a Task, as it provides
    /// compile-time type safety.
    ///
    /// ## Parameters
    /// - `context`: Pointer to the context object
    /// - `method`: Method to call on the context (or a free function taking the context type)
    ///
    /// ## Example
    /// ```zig
    /// const task = Task.init(&my_ctx, MyContext.doWork);
    /// ```
    pub fn init(
        comptime T: type,
        context: *T,
        comptime method: fn (*T) void,
    ) Task {
        return .{
            .ptr = @ptrCast(context),
            .callback = struct {
                fn wrapper(ptr: *anyopaque) void {
                    const ctx: *T = @ptrCast(@alignCast(ptr));
                    method(ctx);
                }
            }.wrapper,
        };
    }

    /// Create a task from a raw pointer and callback.
    ///
    /// This is a low-level API for advanced use cases where you already
    /// have a type-erased callback.
    pub fn initRaw(
        ptr: *anyopaque,
        callback: *const fn (ptr: *anyopaque) void,
    ) Task {
        return .{
            .ptr = ptr,
            .callback = callback,
        };
    }

    /// Execute the task.
    ///
    /// Invokes the callback with the stored context pointer.
    pub fn run(self: Task) void {
        self.callback(self.ptr);
    }

    /// A no-op task that does nothing when run.
    pub const noop: Task = .{
        .ptr = undefined,
        .callback = struct {
            fn noopCallback(_: *anyopaque) void {}
        }.noopCallback,
    };
};

// ============================================================================
// Tests
// ============================================================================

test "Task.init creates callable task" {
    const Context = struct {
        called: bool = false,
        value: u32 = 0,

        fn execute(self: *@This()) void {
            self.called = true;
            self.value = 42;
        }
    };

    var ctx = Context{};
    const task = Task.init(Context, &ctx, Context.execute);

    try std.testing.expect(!ctx.called);
    try std.testing.expectEqual(@as(u32, 0), ctx.value);

    task.run();

    try std.testing.expect(ctx.called);
    try std.testing.expectEqual(@as(u32, 42), ctx.value);
}

test "Task.initRaw creates task from raw pointer" {
    const Context = struct {
        value: u32 = 0,
    };

    var ctx = Context{};

    const task = Task.initRaw(
        @ptrCast(&ctx),
        struct {
            fn callback(ptr: *anyopaque) void {
                const c: *Context = @ptrCast(@alignCast(ptr));
                c.value = 123;
            }
        }.callback,
    );

    task.run();
    try std.testing.expectEqual(@as(u32, 123), ctx.value);
}

test "Task.noop does nothing" {
    // Should not crash
    Task.noop.run();
    Task.noop.run();
}

test "Task can be stored and executed later" {
    const Counter = struct {
        count: u32 = 0,

        fn increment(self: *@This()) void {
            self.count += 1;
        }
    };

    var counter = Counter{};

    // Create multiple tasks pointing to same context
    var tasks: [3]Task = undefined;
    for (&tasks) |*t| {
        t.* = Task.init(Counter, &counter, Counter.increment);
    }

    try std.testing.expectEqual(@as(u32, 0), counter.count);

    // Execute all tasks
    for (tasks) |t| {
        t.run();
    }

    try std.testing.expectEqual(@as(u32, 3), counter.count);
}
