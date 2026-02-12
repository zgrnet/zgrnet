//! Listener for accepting incoming connections.
//!
//! This module provides a `Listener` type that accepts incoming connections
//! on a transport and provides established connections through `accept()`.
//! Generic over Crypto and Runtime.

const std = @import("std");
const mem = std.mem;

const noise = @import("../noise/mod.zig");
const conn_mod = @import("conn.zig");
const manager_mod = @import("manager.zig");

const Key = noise.Key;
const key_size = noise.key_size;
const Transport = noise.Transport;
const Addr = noise.Addr;
const message = noise.message;

const ConnState = conn_mod.ConnState;
const InboundPacket = conn_mod.InboundPacket;

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

/// A listener that accepts incoming connections.
/// Generic over Crypto and Runtime.
pub fn Listener(comptime Crypto: type, comptime Rt: type) type {
    const P = noise.Protocol(Crypto);
    const KeyPair = P.KeyPair;
    const ConnType = conn_mod.Conn(Crypto, Rt);
    const ManagerType = manager_mod.SessionManager(Crypto, Rt);

    // Configuration for creating a listener.
    const ListenerConfig = struct {
        // Local static key pair.
        local_key: KeyPair,
        // Underlying datagram transport.
        transport: Transport,
        // Size of the accept queue (default: 16).
        accept_queue_size: usize = 16,
    };

    return struct {
        const Self = @This();

        pub const Config = ListenerConfig;

        allocator: mem.Allocator,
        mutex: Rt.Mutex = Rt.Mutex.init(),

        local_key: KeyPair,
        transport: Transport,

        // Active connections indexed by local session index
        conns: std.AutoHashMap(u32, *ConnType),

        // Completed connections ready to be accepted
        ready_queue: std.ArrayListUnmanaged(*ConnType),
        ready_signal: Rt.Condition = Rt.Condition.init(),

        // Session manager
        manager: *ManagerType,

        // Closed flag
        closed: bool = false,

        // Receive thread handle (joinable)
        recv_thread: ?Rt.Thread = null,

        /// Creates a new listener with the given configuration.
        /// Call `start()` to begin accepting connections.
        pub fn init(allocator: mem.Allocator, cfg: ListenerConfig) ListenerError!*Self {
            const manager = allocator.create(ManagerType) catch return ListenerError.OutOfMemory;
            manager.* = ManagerType.init(allocator);

            const self = allocator.create(Self) catch {
                allocator.destroy(manager);
                return ListenerError.OutOfMemory;
            };
            self.* = Self{
                .allocator = allocator,
                .local_key = cfg.local_key,
                .transport = cfg.transport,
                .conns = std.AutoHashMap(u32, *ConnType).init(allocator),
                .ready_queue = .{},
                .manager = manager,
            };

            return self;
        }

        /// Starts the receive loop in a background thread.
        /// This must be called after creating the listener.
        pub fn start(self: *Self) void {
            self.recv_thread = Rt.Thread.spawnFn(receiveLoopWrapper, .{self}) catch null;
        }

        /// Wrapper for receive loop to work with thread spawn
        fn receiveLoopWrapper(self: *Self) void {
            self.receiveLoop();
        }

        /// Closes the listener and frees resources.
        pub fn deinit(self: *Self) void {
            self.close();

            // Wait for receive thread to finish
            if (self.recv_thread) |thread| {
                thread.join();
            }

            // Free all connections
            var it = self.conns.iterator();
            while (it.next()) |entry| {
                entry.value_ptr.*.deinit();
                self.allocator.destroy(entry.value_ptr.*);
            }
            self.conns.deinit();

            // Free ready queue connections
            for (self.ready_queue.items) |conn| {
                conn.deinit();
                self.allocator.destroy(conn);
            }
            self.ready_queue.deinit(self.allocator);

            // Free manager
            self.manager.deinit();
            self.allocator.destroy(self.manager);

            self.allocator.destroy(self);
        }

        /// Accepts the next incoming connection.
        /// This is a blocking call.
        pub fn accept(self: *Self) ListenerError!*ConnType {
            self.mutex.lock();
            defer self.mutex.unlock();

            // Wait for a connection to be ready
            while (self.ready_queue.items.len == 0 and !self.closed) {
                self.ready_signal.wait(&self.mutex);
            }

            if (self.closed) {
                return ListenerError.Closed;
            }

            if (self.ready_queue.items.len == 0) {
                return ListenerError.Closed;
            }

            // Pop connection from ready queue
            return self.ready_queue.orderedRemove(0);
        }

        /// Closes the listener.
        pub fn close(self: *Self) void {
            self.mutex.lock();
            defer self.mutex.unlock();

            if (self.closed) {
                return;
            }

            self.closed = true;

            // Signal any waiting accept() calls
            self.ready_signal.broadcast();

            // Close all connections
            var it = self.conns.iterator();
            while (it.next()) |entry| {
                entry.value_ptr.*.close();
            }
        }

        /// Removes a connection from the listener.
        /// This should be called when a connection is closed.
        pub fn removeConn(self: *Self, local_idx: u32) void {
            self.mutex.lock();
            defer self.mutex.unlock();
            _ = self.conns.remove(local_idx);
        }

        /// Returns the local key pair.
        pub fn getLocalKey(self: *Self) KeyPair {
            return self.local_key;
        }

        /// Returns the local public key.
        pub fn getLocalPublicKey(self: *Self) Key {
            return self.local_key.public;
        }

        /// Returns the session manager.
        pub fn getSessionManager(self: *Self) *ManagerType {
            return self.manager;
        }

        /// Returns whether the listener is closed.
        pub fn isClosed(self: *Self) bool {
            self.mutex.lock();
            defer self.mutex.unlock();
            return self.closed;
        }

        /// The main receive loop that handles incoming packets.
        fn receiveLoop(self: *Self) void {
            var buf: [message.max_packet_size]u8 = undefined;

            while (true) {
                // Check if closed
                {
                    self.mutex.lock();
                    const closed = self.closed;
                    self.mutex.unlock();
                    if (closed) {
                        return;
                    }
                }

                // Receive packet
                const result = self.transport.recvFrom(&buf) catch {
                    // Check if closed during recv
                    self.mutex.lock();
                    const closed = self.closed;
                    self.mutex.unlock();
                    if (closed) {
                        return;
                    }
                    continue;
                };

                if (result.bytes_read < 1) {
                    continue;
                }

                const msg_type = message.getMessageType(buf[0..result.bytes_read]) catch continue;

                switch (msg_type) {
                    .handshake_init => {
                        self.handleHandshakeInit(buf[0..result.bytes_read], result.from_addr);
                    },
                    .transport => {
                        self.handleTransport(buf[0..result.bytes_read], result.from_addr);
                    },
                    // TODO: Handle other message types (HandshakeResp for rekey)
                    else => {
                        // Unknown message type, ignore
                    },
                }
            }
        }

        /// Processes an incoming handshake initiation.
        fn handleHandshakeInit(self: *Self, data: []const u8, addr: Addr) void {
            // Parse handshake init
            const msg = message.parseHandshakeInit(data) catch return;

            // Create a new connection for this peer
            const conn = self.allocator.create(ConnType) catch return;
            conn.* = ConnType.init(self.allocator, .{
                .local_key = self.local_key,
                .remote_pk = null, // Will be set during accept
                .transport = self.transport,
                .remote_addr = addr,
            });

            // Set up inbound queue for the connection
            conn.setupInbound();

            // Process the handshake
            const resp = conn.accept(&msg) catch {
                conn.deinit();
                self.allocator.destroy(conn);
                return;
            };

            // Send the response
            self.transport.sendTo(&resp, addr) catch {
                conn.deinit();
                self.allocator.destroy(conn);
                return;
            };

            // Register the connection
            const local_idx = conn.getLocalIndex();
            {
                self.mutex.lock();
                defer self.mutex.unlock();

                self.conns.put(local_idx, conn) catch {
                    conn.deinit();
                    self.allocator.destroy(conn);
                    return;
                };

                // Queue the connection for acceptance
                self.ready_queue.append(self.allocator, conn) catch {
                    _ = self.conns.remove(local_idx);
                    conn.deinit();
                    self.allocator.destroy(conn);
                    return;
                };

                // Signal waiting accept() calls
                self.ready_signal.signal();
            }
        }

        /// Processes an incoming transport message.
        fn handleTransport(self: *Self, data: []const u8, addr: Addr) void {
            // Parse transport message
            const tmsg = message.parseTransportMessage(data) catch return;

            // Look up connection by receiver index
            const conn = blk: {
                self.mutex.lock();
                defer self.mutex.unlock();
                break :blk self.conns.get(tmsg.receiver_index);
            };

            const c = conn orelse return; // Unknown connection

            // Create owned InboundPacket (copy ciphertext since buffer will be reused)
            const ciphertext_copy = self.allocator.alloc(u8, tmsg.ciphertext.len) catch return;
            @memcpy(ciphertext_copy, tmsg.ciphertext);

            const pkt = InboundPacket{
                .receiver_index = tmsg.receiver_index,
                .counter = tmsg.counter,
                .ciphertext = ciphertext_copy,
                .addr = addr,
                .allocator = self.allocator,
            };

            // Deliver to connection
            if (!c.deliverPacket(pkt)) {
                // Delivery failed, free the ciphertext
                self.allocator.free(ciphertext_copy);
            }
        }
    };
}

// Tests
const transport_mod = noise.transport;
const MockTransport = transport_mod.MockTransport;
const UdpTransport = transport_mod.UdpTransport;
const zgrnet_runtime = @import("../runtime.zig");
const StdCrypto = noise.test_crypto;
const StdRt = zgrnet_runtime;
const TestP = noise.Protocol(StdCrypto);
const TestKeyPair = TestP.KeyPair;
const TestListener = Listener(StdCrypto, StdRt);
const TestConn = conn_mod.Conn(StdCrypto, StdRt);
const dial_mod = @import("dial.zig");

test "listener init and deinit" {
    const allocator = std.testing.allocator;
    const transport = try UdpTransport.init("127.0.0.1:0");
    defer transport.close();

    const listener = try TestListener.init(allocator, .{
        .local_key = TestKeyPair.generate(),
        .transport = .{ .udp = @constCast(&transport) },
    });
    defer listener.deinit();

    try std.testing.expect(!listener.isClosed());
}

test "listener close" {
    const allocator = std.testing.allocator;
    const transport = try UdpTransport.init("127.0.0.1:0");
    defer transport.close();

    const listener = try TestListener.init(allocator, .{
        .local_key = TestKeyPair.generate(),
        .transport = .{ .udp = @constCast(&transport) },
    });
    defer listener.deinit();

    listener.close();
    try std.testing.expect(listener.isClosed());

    // Double close should be safe
    listener.close();
    try std.testing.expect(listener.isClosed());
}

test "listener accept connection" {
    const allocator = std.testing.allocator;

    // Create server with real UDP
    const server_key = TestKeyPair.generate();
    var server_transport = try UdpTransport.init("127.0.0.1:0");
    defer server_transport.close();
    // Set recv timeout to prevent infinite blocking
    try server_transport.setRecvTimeout(5000); // 5 second timeout
    const server_addr = server_transport.getLocalAddr();

    const listener = try TestListener.init(allocator, .{
        .local_key = server_key,
        .transport = .{ .udp = &server_transport },
    });
    defer listener.deinit();

    // Start the listener
    listener.start();

    // Create client with real UDP
    const client_key = TestKeyPair.generate();
    var client_transport = try UdpTransport.init("127.0.0.1:0");
    defer client_transport.close();

    // Spawn client dial in separate thread
    const ClientDialResult = struct {
        conn: ?*TestConn = null,
    };
    var client_result = ClientDialResult{};

    const client_thread = try std.Thread.spawn(.{}, struct {
        fn run(result: *ClientDialResult, key: TestKeyPair, remote_pk: Key, transport: *UdpTransport, addr: transport_mod.UdpAddr, alloc: mem.Allocator) void {
            result.conn = dial_mod.dial(StdCrypto, StdRt, .{
                .allocator = alloc,
                .local_key = key,
                .remote_pk = remote_pk,
                .transport = .{ .udp = transport },
                .remote_addr = .{ .udp = addr },
            }) catch null;
        }
    }.run, .{ &client_result, client_key, server_key.public, &client_transport, server_addr, allocator });

    // Accept connection on server
    const server_conn = listener.accept() catch null;
    try std.testing.expect(server_conn != null);

    // Wait for client dial to complete
    client_thread.join();
    try std.testing.expect(client_result.conn != null);

    // Verify both sides are established
    try std.testing.expectEqual(server_conn.?.getState(), ConnState.established);
    try std.testing.expectEqual(client_result.conn.?.getState(), ConnState.established);

    // Clean up client connection
    if (client_result.conn) |c| {
        c.deinit();
        allocator.destroy(c);
    }

    listener.close();
}
