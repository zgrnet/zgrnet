//! OS Abstraction Layer for zgrnet.
//!
//! Provides comptime-selected platform-specific implementations of:
//! - Reactor: Event-driven I/O (kqueue/epoll/io_uring)
//! - Event: One-shot/resettable signal (like Go's close(chan))
//! - Channel: Thread-safe bounded queue with blocking
//! - Mutex: Mutual exclusion lock
//! - Semaphore: Counting semaphore
//!
//! Usage:
//! ```zig
//! const os = @import("os/mod.zig");
//! const Os = os.Os;  // Default based on build option
//!
//! var event = try Os.Event.init();
//! defer event.deinit();
//! event.set();  // Wake up waiters
//! ```

const std = @import("std");
const builtin = @import("builtin");
const build_options = @import("build_options");

/// Platform implementations
pub const Darwin = @import("darwin.zig");
pub const None = @import("none.zig").None;
// pub const Linux = @import("linux.zig");       // TODO
// pub const FreeRtos = @import("freertos.zig"); // TODO

/// Build-time selected OS backend
pub const OsBackend = build_options.os_backend;

/// OS Abstraction Layer - validates and re-exports platform primitives.
///
/// comptime Impl must provide:
/// - Reactor: Event loop for I/O multiplexing
/// - Event: Signal primitive for thread synchronization
/// - Channel(T): Generic bounded thread-safe queue
/// - Mutex: Mutual exclusion lock
/// - Semaphore: Counting semaphore
pub fn OsLayer(comptime Impl: type) type {
    // Compile-time interface validation
    comptime {
        // Validate Reactor
        if (!@hasDecl(Impl, "Reactor")) @compileError("Impl must have Reactor");
        const R = Impl.Reactor;
        if (!@hasDecl(R, "init")) @compileError("Reactor must have init()");
        if (!@hasDecl(R, "deinit")) @compileError("Reactor must have deinit()");

        // Validate Event
        if (!@hasDecl(Impl, "Event")) @compileError("Impl must have Event");
        const E = Impl.Event;
        if (!@hasDecl(E, "init")) @compileError("Event must have init()");
        if (!@hasDecl(E, "deinit")) @compileError("Event must have deinit()");
        if (!@hasDecl(E, "set")) @compileError("Event must have set()");
        if (!@hasDecl(E, "wait")) @compileError("Event must have wait()");
        if (!@hasDecl(E, "reset")) @compileError("Event must have reset()");

        // Validate Channel (generic)
        if (!@hasDecl(Impl, "Channel")) @compileError("Impl must have Channel");

        // Validate Mutex
        if (!@hasDecl(Impl, "Mutex")) @compileError("Impl must have Mutex");
        const M = Impl.Mutex;
        if (!@hasDecl(M, "lock")) @compileError("Mutex must have lock()");
        if (!@hasDecl(M, "unlock")) @compileError("Mutex must have unlock()");

        // Validate Semaphore
        if (!@hasDecl(Impl, "Semaphore")) @compileError("Impl must have Semaphore");
        const S = Impl.Semaphore;
        if (!@hasDecl(S, "wait")) @compileError("Semaphore must have wait()");
        if (!@hasDecl(S, "post")) @compileError("Semaphore must have post()");
    }

    return struct {
        /// Event-driven I/O reactor (kqueue/epoll/io_uring).
        ///
        /// Methods:
        /// - init() !Reactor
        /// - deinit() void
        /// - register(fd, filter, flags) !void
        /// - wait(timeout_ms) ![]const KEvent
        pub const Reactor = Impl.Reactor;

        /// One-shot or resettable event signal.
        /// Similar to Go's close(chan) for signaling completion.
        ///
        /// Methods:
        /// - init() !Event
        /// - deinit() void
        /// - set() void       - Signal the event (wake waiters)
        /// - wait() void      - Block until signaled
        /// - reset() void     - Reset to unsignaled state
        /// - isSet() bool     - Check if signaled (non-blocking)
        pub const Event = Impl.Event;

        /// Thread-safe bounded channel/queue.
        /// Similar to Go channels with blocking send/recv.
        ///
        /// Methods:
        /// - init(allocator, capacity) !Channel(T)
        /// - deinit() void
        /// - send(item) !void  - Block if full
        /// - trySend(item) bool - Non-blocking
        /// - recv() ?T         - Block if empty, null if closed
        /// - tryRecv() ?T      - Non-blocking
        /// - close() void      - Close channel
        pub const Channel = Impl.Channel;

        /// Mutual exclusion lock.
        ///
        /// Methods:
        /// - lock() void
        /// - tryLock() bool
        /// - unlock() void
        pub const Mutex = Impl.Mutex;

        /// Counting semaphore.
        ///
        /// Methods:
        /// - init(permits) Semaphore
        /// - wait() void       - P operation (decrement, block if 0)
        /// - tryWait() bool    - Non-blocking P
        /// - post() void       - V operation (increment)
        pub const Semaphore = Impl.Semaphore;
    };
}

/// Default OS layer based on build option (-Dos_backend=darwin|none)
pub const Os = OsLayer(Darwin);  // Note: None requires allocator, use None(alloc) directly

test "OsLayer comptime validation" {
    // This just checks that Darwin implements all required interfaces
    const TestOs = OsLayer(Darwin);
    _ = TestOs.Reactor;
    _ = TestOs.Event;
    _ = TestOs.Channel;
    _ = TestOs.Mutex;
    _ = TestOs.Semaphore;
}
