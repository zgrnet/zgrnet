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

/// Platform implementations (conditionally imported to avoid compile errors)
/// Named by I/O mechanism, not OS: kqueue (BSD), epoll (Linux), io_uring (Linux 5.1+)
pub const Kqueue = if (builtin.os.tag == .macos or builtin.os.tag == .ios or
    builtin.os.tag == .tvos or builtin.os.tag == .watchos or
    builtin.os.tag == .freebsd or builtin.os.tag == .netbsd or builtin.os.tag == .openbsd)
    @import("kqueue.zig")
else
    struct {}; // Empty struct on non-kqueue platforms
pub const none = @import("none.zig");
pub const None = none.None;
// pub const Epoll = @import("epoll.zig");       // TODO: Linux epoll
// pub const IoUring = @import("io_uring.zig");  // TODO: Linux io_uring
// pub const FreeRtos = @import("freertos.zig"); // TODO: FreeRTOS

/// IOService implementations
pub const KqueueIO = if (@hasDecl(Kqueue, "KqueueIO")) Kqueue.KqueueIO else struct {};
pub const BusyPollIO = if (@hasDecl(Kqueue, "BusyPollIO")) Kqueue.BusyPollIO else struct {};

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

/// Default OS layer based on build option and target OS.
/// Falls back to None on platforms without kqueue/epoll support.
pub const Os = switch (builtin.os.tag) {
    .macos, .ios, .tvos, .watchos, .freebsd, .netbsd, .openbsd => OsLayer(Kqueue),
    // TODO: .linux => OsLayer(Epoll),
    else => OsLayer(None(std.heap.page_allocator)),
};

test "OsLayer comptime validation" {
    // This checks that the selected platform implements all required interfaces
    _ = Os.Reactor;
    _ = Os.Event;
    _ = Os.Channel;
    _ = Os.Mutex;
    _ = Os.Semaphore;
}
