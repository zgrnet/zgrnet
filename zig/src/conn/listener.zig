//! Listener for accepting incoming connections.
//!
//! This module provides a `Listener` type that accepts incoming connections
//! on a transport and provides established connections through `accept()`.

const std = @import("std");
const noise = @import("../noise/root.zig");
const conn_mod = @import("conn.zig");
const manager_mod = @import("manager.zig");

const Key = noise.Key;
const KeyPair = noise.KeyPair;
const Transport = noise.Transport;
const Addr = noise.Addr;
const Session = noise.Session;

const Conn = conn_mod.Conn;
const ConnConfig = conn_mod.ConnConfig;
const SessionManager = manager_mod.SessionManager;

/// Listener errors.
pub const ListenerError = error{
    /// Missing local key pair.
    MissingLocalKey,
    /// Missing transport.
    MissingTransport,
    /// Listener is closed.
    Closed,
    /// Out of memory.
    OutOfMemory,
};

/// Configuration for creating a listener.
pub const ListenerConfig = struct {
    /// Local static key pair.
    local_key: KeyPair,
    /// Underlying datagram transport.
    transport: Transport,
    /// Size of the accept queue (default: 16).
    accept_queue_size: usize = 16,
};

/// A listener that accepts incoming connections.
///
/// The listener handles the handshake process for incoming connections
/// and provides accepted connections through the `accept()` method.
pub const Listener = struct {
    allocator: std.mem.Allocator,
    mutex: std.Thread.Mutex = .{},

    local_key: KeyPair,
    transport: Transport,

    // Active connections indexed by local session index
    conns: std.AutoHashMap(u32, *Conn),

    // Session manager
    manager: *SessionManager,

    // Closed flag
    closed: bool = false,

    /// Creates a new listener with the given configuration.
    pub fn init(allocator: std.mem.Allocator, cfg: ListenerConfig) ListenerError!*Listener {
        const manager = allocator.create(SessionManager) catch return ListenerError.OutOfMemory;
        manager.* = SessionManager.init(allocator);

        const self = allocator.create(Listener) catch {
            allocator.destroy(manager);
            return ListenerError.OutOfMemory;
        };
        self.* = Listener{
            .allocator = allocator,
            .local_key = cfg.local_key,
            .transport = cfg.transport,
            .conns = std.AutoHashMap(u32, *Conn).init(allocator),
            .manager = manager,
        };

        return self;
    }

    /// Closes the listener and frees resources.
    pub fn deinit(self: *Listener) void {
        self.close();

        // Free all connections
        var it = self.conns.iterator();
        while (it.next()) |entry| {
            self.allocator.destroy(entry.value_ptr.*);
        }
        self.conns.deinit();

        // Free manager
        self.manager.deinit();
        self.allocator.destroy(self.manager);

        self.allocator.destroy(self);
    }

    /// Closes the listener.
    pub fn close(self: *Listener) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.closed) {
            return;
        }

        self.closed = true;

        // Close all connections
        var it = self.conns.iterator();
        while (it.next()) |entry| {
            entry.value_ptr.*.close();
        }
    }

    /// Returns the local key pair.
    pub fn getLocalKey(self: *Listener) KeyPair {
        return self.local_key;
    }

    /// Returns the session manager.
    pub fn getSessionManager(self: *Listener) *SessionManager {
        return self.manager;
    }

    /// Returns whether the listener is closed.
    pub fn isClosed(self: *Listener) bool {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.closed;
    }
};

test "listener init and deinit" {
    const allocator = std.testing.allocator;
    const transport = try noise.transport.MockTransport.init(allocator, "test");
    defer transport.deinit();

    const listener = try Listener.init(allocator, .{
        .local_key = KeyPair.generate(),
        .transport = .{ .mock = transport },
    });
    defer listener.deinit();

    try std.testing.expect(!listener.isClosed());
}

test "listener close" {
    const allocator = std.testing.allocator;
    const transport = try noise.transport.MockTransport.init(allocator, "test");
    defer transport.deinit();

    const listener = try Listener.init(allocator, .{
        .local_key = KeyPair.generate(),
        .transport = .{ .mock = transport },
    });
    defer listener.deinit();

    listener.close();
    try std.testing.expect(listener.isClosed());

    // Double close should be safe
    listener.close();
    try std.testing.expect(listener.isClosed());
}
