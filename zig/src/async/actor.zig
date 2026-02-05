//! Actor - A state machine with single-threaded message processing.
//!
//! An Actor encapsulates state and processes messages sequentially on a single
//! executor. Messages can be sent from any thread, but processing always happens
//! on the actor's bound executor, eliminating the need for internal locking.
//!
//! ## Design
//!
//! ```
//! ┌─────────────────────────────────────────────────────┐
//! │                      Actor                          │
//! │  ┌─────────┐    ┌───────────┐    ┌──────────────┐  │
//! │  │  MPSC   │───>│  Process  │───>│    State     │  │
//! │  │  Queue  │    │  (single  │    │  (no locks)  │  │
//! │  └─────────┘    │  thread)  │    └──────────────┘  │
//! │       ▲         └───────────┘                      │
//! │       │                                            │
//! └───────┼────────────────────────────────────────────┘
//!         │
//!    send() from any thread
//! ```
//!
//! ## Usage
//!
//! Define your state type with a `handle` method:
//!
//! ```zig
//! const MyState = struct {
//!     counter: u32 = 0,
//!
//!     pub fn handle(self: *MyState, msg: MyMessage) void {
//!         switch (msg) {
//!             .increment => self.counter += 1,
//!             .reset => self.counter = 0,
//!         }
//!     }
//! };
//!
//! const MyMessage = union(enum) {
//!     increment,
//!     reset,
//! };
//!
//! const MyActor = Actor(MyState, MyMessage);
//! ```

const std = @import("std");
const Task = @import("task.zig").Task;
const Executor = @import("executor.zig").Executor;
const MpscQueue = @import("mpsc.zig").MpscQueue;

/// Actor - A state machine with message-based concurrency.
///
/// ## Type Parameters
/// - `State`: The internal state type. Must have a `handle(msg: Message) void` method.
/// - `Message`: The message type that the actor can receive.
///
/// ## Thread Safety
/// - `send()` is thread-safe and can be called from any thread
/// - Message processing happens exclusively on the bound executor
/// - State is never accessed concurrently - no locks needed inside State
pub fn Actor(comptime State: type, comptime Message: type) type {
    // Validate that State has the required handle method
    comptime {
        if (!@hasDecl(State, "handle")) {
            @compileError("Actor State must have a 'handle' method with signature: fn(*State, Message) void");
        }
    }

    return struct {
        const Self = @This();

        /// The internal state - only accessed on the executor thread
        state: State,

        /// Message queue - producers push, executor pops
        queue: MpscQueue(Message),

        /// The executor this actor is bound to
        executor: Executor,

        /// Allocator for internal use
        allocator: std.mem.Allocator,

        /// Flag to track if we have a pending process task
        processing: std.atomic.Value(bool),

        /// Initialize a new actor.
        ///
        /// ## Parameters
        /// - `allocator`: Allocator for message queue nodes
        /// - `state`: Initial state
        /// - `executor`: The executor to run on
        pub fn init(allocator: std.mem.Allocator, state: State, executor: Executor) Self {
            return .{
                .state = state,
                .queue = MpscQueue(Message).init(allocator),
                .executor = executor,
                .allocator = allocator,
                .processing = std.atomic.Value(bool).init(false),
            };
        }

        /// Deinitialize the actor.
        ///
        /// WARNING: This is not thread-safe. Ensure no other threads are
        /// sending messages when calling deinit.
        pub fn deinit(self: *Self) void {
            self.queue.deinit();
        }

        /// Send a message to the actor.
        ///
        /// This is thread-safe and can be called from any thread.
        /// The message will be processed asynchronously on the actor's executor.
        ///
        /// Returns false if the message could not be enqueued (allocation failure).
        pub fn send(self: *Self, msg: Message) bool {
            // Enqueue the message
            if (!self.queue.push(msg)) {
                return false;
            }

            // Schedule processing if not already scheduled
            self.scheduleProcessing();
            return true;
        }

        /// Get a handle to this actor that can be used to send messages.
        ///
        /// The handle is a lightweight reference that can be cloned and
        /// passed around freely.
        pub fn handle(self: *Self) ActorHandle(Message) {
            return ActorHandle(Message).init(State, self);
        }

        /// Process all pending messages.
        ///
        /// This is called by the executor and should not be called directly.
        fn process(self: *Self) void {
            // Process messages until queue is empty
            while (self.queue.pop()) |msg| {
                self.state.handle(msg);
            }

            // Clear processing flag
            self.processing.store(false, .release);

            // Check if more messages arrived while we were processing
            if (!self.queue.isEmpty()) {
                self.scheduleProcessing();
            }
        }

        /// Schedule the process task on the executor.
        fn scheduleProcessing(self: *Self) void {
            // Only schedule if not already processing
            const was_processing = self.processing.swap(true, .acq_rel);
            if (!was_processing) {
                self.executor.dispatch(Task.init(Self, self, Self.process));
            }
        }
    };
}

/// A lightweight handle to an actor for sending messages.
///
/// ActorHandle can be freely copied and passed to other threads.
/// It only holds a pointer to the actor and can send messages.
pub fn ActorHandle(comptime Message: type) type {
    return struct {
        const Self = @This();

        ptr: *anyopaque,
        send_fn: *const fn (ptr: *anyopaque, msg: Message) bool,

        /// Create a handle from an actor.
        pub fn init(comptime State: type, actor: *Actor(State, Message)) Self {
            return .{
                .ptr = @ptrCast(actor),
                .send_fn = struct {
                    fn send(ptr: *anyopaque, msg: Message) bool {
                        const a: *Actor(State, Message) = @ptrCast(@alignCast(ptr));
                        return a.send(msg);
                    }
                }.send,
            };
        }

        /// Send a message to the actor.
        pub fn send(self: Self, msg: Message) bool {
            return self.send_fn(self.ptr, msg);
        }
    };
}

// ============================================================================
// Tests
// ============================================================================

test "Actor processes messages sequentially" {
    const ValueList = std.ArrayListAligned(u32, null);

    const TestState = struct {
        values: ValueList,
        allocator: std.mem.Allocator,

        pub fn handle(self: *@This(), msg: u32) void {
            self.values.append(self.allocator, msg) catch {};
        }
    };

    const TestActor = Actor(TestState, u32);

    var inline_exec = @import("executor.zig").InlineExecutor{};

    var actor = TestActor.init(
        std.testing.allocator,
        TestState{ .values = .{}, .allocator = std.testing.allocator },
        inline_exec.executor(),
    );
    defer {
        actor.state.values.deinit(std.testing.allocator);
        actor.deinit();
    }

    // Send messages
    try std.testing.expect(actor.send(1));
    try std.testing.expect(actor.send(2));
    try std.testing.expect(actor.send(3));

    // With InlineExecutor, messages are processed immediately
    try std.testing.expectEqualSlices(u32, &[_]u32{ 1, 2, 3 }, actor.state.values.items);
}

test "Actor with union messages" {
    const Message = union(enum) {
        increment: u32,
        decrement: u32,
        reset,
    };

    const Counter = struct {
        value: i32 = 0,

        pub fn handle(self: *@This(), msg: Message) void {
            switch (msg) {
                .increment => |n| self.value += @intCast(n),
                .decrement => |n| self.value -= @intCast(n),
                .reset => self.value = 0,
            }
        }
    };

    const CounterActor = Actor(Counter, Message);

    var inline_exec = @import("executor.zig").InlineExecutor{};

    var actor = CounterActor.init(
        std.testing.allocator,
        Counter{},
        inline_exec.executor(),
    );
    defer actor.deinit();

    try std.testing.expectEqual(@as(i32, 0), actor.state.value);

    _ = actor.send(.{ .increment = 10 });
    try std.testing.expectEqual(@as(i32, 10), actor.state.value);

    _ = actor.send(.{ .decrement = 3 });
    try std.testing.expectEqual(@as(i32, 7), actor.state.value);

    _ = actor.send(.reset);
    try std.testing.expectEqual(@as(i32, 0), actor.state.value);
}

test "ActorHandle can send messages" {
    const State = struct {
        received: bool = false,

        pub fn handle(self: *@This(), _: u32) void {
            self.received = true;
        }
    };

    var inline_exec = @import("executor.zig").InlineExecutor{};

    var actor = Actor(State, u32).init(
        std.testing.allocator,
        State{},
        inline_exec.executor(),
    );
    defer actor.deinit();

    // Get a handle
    const actor_handle = actor.handle();

    try std.testing.expect(!actor.state.received);

    // Send via handle
    try std.testing.expect(actor_handle.send(42));

    try std.testing.expect(actor.state.received);
}

test "Actor with QueuedExecutor defers processing" {
    const State = struct {
        count: u32 = 0,

        pub fn handle(self: *@This(), _: void) void {
            self.count += 1;
        }
    };

    var queued_exec = @import("executor.zig").QueuedExecutor.init(std.testing.allocator);
    defer queued_exec.deinit();

    var actor = Actor(State, void).init(
        std.testing.allocator,
        State{},
        queued_exec.executor(),
    );
    defer actor.deinit();

    // Send messages - they should be queued, not processed yet
    _ = actor.send({});
    _ = actor.send({});
    _ = actor.send({});

    // Nothing processed yet
    try std.testing.expectEqual(@as(u32, 0), actor.state.count);

    // Run the executor
    _ = queued_exec.runAll();

    // Now messages should be processed
    try std.testing.expectEqual(@as(u32, 3), actor.state.count);
}
