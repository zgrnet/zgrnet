//! Async Runtime Primitives
//!
//! This module provides platform-agnostic async runtime primitives that allow
//! Zig code to be driven by external executors and timers.
//!
//! ## Design Philosophy
//!
//! Zig is often used in embedded or library scenarios where:
//! - The host application has its own event loop (Go, Rust, C with libuv, etc.)
//! - Zig should not create threads or run its own scheduler
//! - All timing and scheduling should be delegated to the platform
//!
//! This module defines the **interfaces** (traits), and the platform provides
//! the **implementations**.
//!
//! ## Core Primitives
//!
//! - `Task` - A type-erased callable unit of work
//! - `Executor` - An execution context that can run tasks
//! - `TimerService` - A service for scheduling delayed tasks
//! - `Actor` - A state machine with a message queue (single-threaded execution)
//!
//! ## Implementations
//!
//! Two implementation backends are provided:
//!
//! - `thread` - std.Thread based implementations (ThreadExecutor, EventLoop)
//! - `minicoro` - C coroutine based implementation (CoroScheduler)
//!
//! ## Usage Example
//!
//! ```zig
//! const async_mod = @import("async");
//!
//! // Using thread-based executor
//! var loop = async_mod.thread.EventLoop.init(allocator);
//! defer loop.deinit();
//! loop.executor().dispatch(my_task);
//!
//! // Using minicoro-based coroutines (requires C linkage)
//! var scheduler = async_mod.minicoro.CoroScheduler.init(allocator);
//! defer scheduler.deinit();
//! ```
//!
//! ## Testing Utilities
//!
//! The module also provides simple implementations for testing:
//! - `InlineExecutor` - Executes tasks immediately
//! - `QueuedExecutor` - Queues tasks for manual execution
//! - `SimpleTimerService` - Manual time advancement for testing

const std = @import("std");

// Core primitives (platform-independent interfaces)
pub const task = @import("task.zig");
pub const executor = @import("executor.zig");
pub const timer = @import("timer.zig");
pub const io = @import("io.zig");
pub const mpsc = @import("mpsc.zig");
pub const channel = @import("channel.zig");
pub const actor = @import("actor.zig");
pub const concepts = @import("concepts.zig");

// Implementation backends
pub const thread = @import("thread/mod.zig");
pub const minicoro = @import("minicoro/mod.zig");
pub const kqueue = if (@import("builtin").os.tag == .macos or
    @import("builtin").os.tag == .freebsd or
    @import("builtin").os.tag == .netbsd or
    @import("builtin").os.tag == .openbsd)
    @import("kqueue/mod.zig")
else
    struct {};

// Re-export main types for convenience
pub const Task = task.Task;
pub const Executor = executor.Executor;
pub const TimerService = timer.TimerService;
pub const TimerHandle = timer.TimerHandle;

// Re-export testing utilities
pub const InlineExecutor = executor.InlineExecutor;
pub const QueuedExecutor = executor.QueuedExecutor;
pub const SimpleTimerService = timer.SimpleTimerService;

// Re-export actor types
pub const Actor = actor.Actor;
pub const ActorHandle = actor.ActorHandle;

// Re-export MPSC queue
pub const MpscQueue = mpsc.MpscQueue;

// Re-export Channel types
pub const Channel = channel.Channel;
pub const Signal = channel.Signal;

// Re-export comptime concepts
pub const isExecutor = concepts.isExecutor;
pub const isTimerService = concepts.isTimerService;
pub const isIOService = concepts.isIOService;
pub const assertExecutor = concepts.assertExecutor;
pub const assertTimerService = concepts.assertTimerService;
pub const assertIOService = concepts.assertIOService;

// Re-export IO types
pub const ReadyCallback = io.ReadyCallback;
pub const Interest = io.Interest;
pub const Registration = io.Registration;
pub const IOService = io.IOService;

// Convenience re-exports from thread backend (most common usage)
pub const ThreadExecutor = thread.ThreadExecutor;
pub const ThreadExecutorWithTimers = thread.ThreadExecutorWithTimers;
pub const EventLoop = thread.EventLoop;
pub const Coroutine = thread.Coroutine;

// Re-export kqueue IO backend (macOS/BSD only)
pub const KqueueIO = if (@hasDecl(kqueue, "KqueueIO")) kqueue.KqueueIO else struct {};

// Tests
test {
    _ = task;
    _ = executor;
    _ = timer;
    _ = io;
    _ = mpsc;
    _ = channel;
    _ = actor;
    _ = thread;
    _ = concepts;
    if (@hasDecl(kqueue, "KqueueIO")) _ = kqueue;
    // Note: minicoro tests require C linkage, tested separately
}
