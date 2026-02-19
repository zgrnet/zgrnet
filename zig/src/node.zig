//! Embeddable zgrnet network node without TUN.
//!
//! `Node` wraps UDP/noise/KCP into a high-level API for apps and embedded
//! devices. Unlike Host, Node does not require TUN or root privileges.
//!
//! Generic over Crypto, Rt, IOBackend, and SocketImpl — works on any
//! platform (desktop with std, ESP32 with hardware crypto, etc.).

const noise = @import("noise/mod.zig");
const net_mod = @import("net/mod.zig");
const kcp_mod = @import("kcp/mod.zig");
const channel_pkg = @import("channel");

const Key = noise.Key;
const message = noise.message;

/// Node — generic embeddable network node.
///
/// Parameterized over:
/// - `Crypto`: Noise Protocol crypto primitives (Blake2s, ChaCha20-Poly1305, X25519)
/// - `Rt`: Runtime (Mutex, Thread, Condition, nowMs, sleepMs)
/// - `IOBackend`: IO polling backend (kqueue/epoll)
/// - `SocketImpl`: UDP socket (posix/lwIP)
pub fn Node(comptime Crypto: type, comptime Rt: type, comptime IOBackend: type, comptime SocketImpl: type) type {
    const UDPType = net_mod.udp.UDP(Crypto, Rt, IOBackend, SocketImpl);
    const KcpStream = kcp_mod.Stream(Rt);
    const Endpoint = net_mod.endpoint_mod.Endpoint;
    const UdpError = net_mod.UdpError;
    const P = noise.Protocol(Crypto);
    const KeyPair = P.KeyPair;
    const mem = @import("std").mem;
    const Allocator = mem.Allocator;
    const Atomic = @import("std").atomic.Value;
    const fmt = @import("std").fmt;

    return struct {
        const Self = @This();

        pub const KcpStreamType = KcpStream;

        /// Lifecycle state.
        pub const State = enum(u8) {
            stopped = 0,
            running = 1,
            suspended = 2,
        };

        /// Configuration for creating a Node.
        pub const Config = struct {
            key: *const KeyPair,
            listen_port: u16 = 0,
            allow_unknown: bool = false,
            allocator: Allocator,
        };

        /// Configuration for adding a peer.
        pub const PeerConfig = struct {
            public_key: Key,
            endpoint: ?Endpoint = null,
        };

        /// A KCP stream with the remote peer's public key.
        pub const NodeStream = struct {
            stream: *KcpStream,
            remote_pk: Key,

            pub fn remotePubkey(self: *const NodeStream) Key {
                return self.remote_pk;
            }

            pub fn proto(self: *const NodeStream) u8 {
                return self.stream.getProto();
            }

            pub fn metadata(self: *const NodeStream) []const u8 {
                return self.stream.getMetadata();
            }

            pub fn read(self: *const NodeStream, buf: []u8) !usize {
                return self.stream.read(buf);
            }

            pub fn write(self: *const NodeStream, data: []const u8) !usize {
                return self.stream.write(data);
            }

            pub fn close(self: *const NodeStream) void {
                self.stream.shutdown();
            }
        };

        const ChannelT = channel_pkg.Channel;

        /// Proto-specific KCP stream listener. Created by Node.listen(proto).
        pub const StreamListener = struct {
            proto_byte: u8,
            ch: ChannelT(NodeStream, 64, Rt),

            pub fn init(proto_val: u8) StreamListener {
                return .{
                    .proto_byte = proto_val,
                    .ch = ChannelT(NodeStream, 64, Rt).init(),
                };
            }

            pub fn deinit(self: *StreamListener) void {
                self.ch.deinit();
            }

            /// Accept the next incoming KCP stream. Returns null when closed.
            pub fn accept(self: *StreamListener) ?NodeStream {
                return self.ch.recv();
            }

            /// Close the listener (signals no more streams).
            pub fn close(self: *StreamListener) void {
                self.ch.close();
            }

            pub fn proto(self: *const StreamListener) u8 {
                return self.proto_byte;
            }
        };

        // ── Fields ────────────────────────────────────────────────────

        allocator: Allocator,
        udp: *UDPType,
        state: Atomic(u8),

        // Global accept: ring buffer of NodeStream, protected by mutex + cond.
        accept_buf: [64]NodeStream,
        accept_head: usize,
        accept_tail: usize,
        accept_count: usize,
        accept_mutex: Rt.Mutex,
        accept_cond: Rt.Condition,

        // Per-proto stream listeners: proto(u8) → optional pointer to StreamListener.
        // Protected by listener_mutex for concurrent access from accept loops.
        proto_listeners: [256]?*StreamListener,
        listener_mutex: Rt.Mutex,

        // Per-peer accept forwarder threads
        peer_keys: [16]Key, // registered peer keys
        peer_stops: [16]Atomic(bool), // stop signals per peer
        peer_count: usize,
        peer_mutex: Rt.Mutex,

        // Background threads
        recv_thread: ?Rt.Thread,

        // ── Public API ────────────────────────────────────────────────

        /// Initialize a new Node. Call deinit() to release resources.
        pub fn init(cfg: Config) !*Self {
            // Format bind address string on the stack.
            var addr_buf: [32]u8 = undefined;
            const bind_addr = fmt.bufPrint(&addr_buf, "127.0.0.1:{}", .{cfg.listen_port}) catch "127.0.0.1:0";

            const udp_opts = net_mod.UdpOptions{
                .bind_addr = bind_addr,
                .allow_unknown = cfg.allow_unknown,
            };

            const udp = UDPType.init(cfg.allocator, cfg.key, udp_opts) catch return error.UdpInitFailed;

            const self = cfg.allocator.create(Self) catch return error.OutOfMemory;
            self.* = Self{
                .allocator = cfg.allocator,
                .udp = udp,
                .state = Atomic(u8).init(@intFromEnum(State.running)),
                .accept_buf = undefined,
                .accept_head = 0,
                .accept_tail = 0,
                .accept_count = 0,
                .accept_mutex = Rt.Mutex.init(),
                .accept_cond = Rt.Condition.init(),
                .proto_listeners = .{null} ** 256,
                .listener_mutex = Rt.Mutex.init(),
                .peer_keys = undefined,
                .peer_stops = undefined,
                .peer_count = 0,
                .peer_mutex = Rt.Mutex.init(),
                .recv_thread = null,
            };

            // Initialize stop signals
            for (&self.peer_stops) |*s| {
                s.* = Atomic(bool).init(false);
            }

            // Start background receive loop.
            self.recv_thread = Rt.Thread.spawn(.{}, recvLoop, .{self}) catch null;

            return self;
        }

        /// Shut down and release all resources.
        pub fn deinit(self: *Self) void {
            // Signal all loops to stop.
            self.state.store(@intFromEnum(State.stopped), .release);

            self.peer_mutex.lock();
            const count = self.peer_count;
            self.peer_mutex.unlock();
            for (0..count) |i| {
                self.peer_stops[i].store(true, .release);
            }
            self.accept_cond.broadcast();

            // Close all proto listeners.
            self.listener_mutex.lock();
            for (&self.proto_listeners) |*slot| {
                if (slot.*) |ln| {
                    ln.close();
                    ln.deinit();
                    self.allocator.destroy(ln);
                    slot.* = null;
                }
            }
            self.listener_mutex.unlock();

            // Close UDP (unblocks IO threads).
            self.udp.close();

            // Join recv thread.
            if (self.recv_thread) |t| {
                t.join();
            }

            // Now safe to deallocate.
            self.udp.deinit();
            self.accept_mutex.deinit();
            self.accept_cond.deinit();
            self.listener_mutex.deinit();
            self.peer_mutex.deinit();
            self.allocator.destroy(self);
        }

        /// Stop the node (signals shutdown without joining/deallocating).
        pub fn stop(self: *Self) void {
            self.state.store(@intFromEnum(State.stopped), .release);

            // Close all proto listeners.
            self.listener_mutex.lock();
            for (&self.proto_listeners) |*slot| {
                if (slot.*) |ln| {
                    ln.close();
                }
            }
            self.listener_mutex.unlock();

            self.peer_mutex.lock();
            const count = self.peer_count;
            self.peer_mutex.unlock();
            for (0..count) |i| {
                self.peer_stops[i].store(true, .release);
            }
            self.accept_cond.broadcast();
        }

        /// Returns the current lifecycle state.
        pub fn getState(self: *Self) State {
            return @enumFromInt(self.state.load(.acquire));
        }

        /// Returns this node's public key.
        pub fn publicKey(self: *Self) Key {
            return self.udp.local_key.public_key;
        }

        /// Add a peer.
        pub fn addPeer(self: *Self, cfg: PeerConfig) !void {
            if (self.getState() != .running) return error.NotRunning;

            if (cfg.endpoint) |ep| {
                self.udp.setPeerEndpoint(cfg.public_key, ep);
            } else {
                self.udp.setPeerEndpoint(cfg.public_key, Endpoint.zero);
            }

            // Start accept forwarder for this peer.
            self.startAcceptLoop(cfg.public_key);
        }

        /// Remove a peer (stops the accept forwarder).
        pub fn removePeer(self: *Self, pk: Key) void {
            self.peer_mutex.lock();
            for (0..self.peer_count) |i| {
                if (mem.eql(u8, &self.peer_keys[i].data, &pk.data)) {
                    self.peer_stops[i].store(true, .release);
                    break;
                }
            }
            self.peer_mutex.unlock();
        }

        /// Connect to a peer (initiate handshake).
        pub fn connect(self: *Self, pk: *const Key) !void {
            if (self.getState() != .running) return error.NotRunning;
            return self.udp.connect(pk);
        }

        /// Dial: connect + open stream (proto=TCP_PROXY, addr=127.0.0.1:port).
        pub fn dial(self: *Self, pk: *const Key, port: u16) !NodeStream {
            if (self.getState() != .running) return error.NotRunning;

            // Ensure connected.
            self.udp.connect(pk) catch {};

            // Build metadata: ATYP_IPV4(1) + IPv4(4 bytes) + port(2 bytes big-endian).
            var meta_buf: [7]u8 = undefined;
            meta_buf[0] = 0x01; // ATYP_IPV4
            meta_buf[1] = 127;
            meta_buf[2] = 0;
            meta_buf[3] = 0;
            meta_buf[4] = 1;
            meta_buf[5] = @intCast(port >> 8);
            meta_buf[6] = @intCast(port & 0xff);

            const stream = self.udp.openStream(pk, @intFromEnum(message.Protocol.tcp_proxy), &meta_buf) catch
                return error.OpenStreamFailed;

            return NodeStream{
                .stream = stream,
                .remote_pk = pk.*,
            };
        }

        /// Open a raw KCP stream with custom proto and metadata.
        pub fn openStream(self: *Self, pk: *const Key, proto_byte: u8, meta: []const u8) !NodeStream {
            if (self.getState() != .running) return error.NotRunning;

            self.udp.connect(pk) catch {};

            const stream = self.udp.openStream(pk, proto_byte, meta) catch
                return error.OpenStreamFailed;

            return NodeStream{
                .stream = stream,
                .remote_pk = pk.*,
            };
        }

        /// Connect to a remote peer through a relay and open a KCP stream.
        pub fn dialRelay(self: *Self, dst: *const Key, relay_pk: *const Key, port: u16) !NodeStream {
            if (self.getState() != .running) return error.NotRunning;

            if (self.udp.getRouteTable()) |rt| {
                rt.addRoute(dst.data, relay_pk.data);
            }

            try self.addPeer(.{ .public_key = dst.*, .endpoint = null });

            return self.dial(dst, port);
        }

        /// Returns the node's route table, or null if none.
        pub fn routeTable(self: *Self) ?*@import("relay/route.zig").RouteTable {
            return self.udp.getRouteTable();
        }

        /// Register a proto-specific stream listener. All incoming KCP streams
        /// with the given proto are routed to this listener. Returns error if
        /// the proto is already registered.
        pub fn listen(self: *Self, proto_byte: u8) !*StreamListener {
            self.listener_mutex.lock();
            defer self.listener_mutex.unlock();

            if (self.proto_listeners[proto_byte] != null) return error.ProtoRegistered;

            const ln = self.allocator.create(StreamListener) catch return error.OutOfMemory;
            ln.* = StreamListener.init(proto_byte);
            self.proto_listeners[proto_byte] = ln;
            return ln;
        }

        /// Unregister a proto listener. Subsequent streams fall through to acceptStream.
        pub fn closeListen(self: *Self, proto_byte: u8) void {
            self.listener_mutex.lock();
            const ln = self.proto_listeners[proto_byte];
            self.proto_listeners[proto_byte] = null;
            self.listener_mutex.unlock();

            if (ln) |l| {
                l.close();
                l.deinit();
                self.allocator.destroy(l);
            }
        }

        /// Accept a stream from any peer (blocking).
        /// Streams with a registered listen() proto are NOT delivered here.
        pub fn acceptStream(self: *Self) ?NodeStream {
            self.accept_mutex.lock();
            defer self.accept_mutex.unlock();

            while (self.accept_count == 0) {
                if (self.getState() == .stopped) return null;
                self.accept_cond.wait(&self.accept_mutex);
                if (self.getState() == .stopped) return null;
            }

            const ns = self.accept_buf[self.accept_tail];
            self.accept_tail = (self.accept_tail + 1) % self.accept_buf.len;
            self.accept_count -= 1;
            return ns;
        }

        /// Send raw data to a peer (no stream).
        pub fn writeTo(self: *Self, data: []const u8, protocol: u8, pk: *const Key) !void {
            if (self.getState() != .running) return error.NotRunning;
            return self.udp.writeToProtocol(pk, protocol, data);
        }

        /// Returns the underlying UDP instance (advanced use).
        pub fn getUdp(self: *Self) *UDPType {
            return self.udp;
        }

        // ── Internal ──────────────────────────────────────────────────

        fn recvLoop(self: *Self) void {
            var buf: [65535]u8 = undefined;
            while (self.getState() != .stopped) {
                _ = self.udp.readFrom(&buf) catch |err| {
                    if (err == UdpError.Closed) return;
                    continue;
                };
            }
        }

        fn startAcceptLoop(self: *Self, pk: Key) void {
            self.peer_mutex.lock();
            defer self.peer_mutex.unlock();

            if (self.peer_count >= self.peer_keys.len) return; // max peers

            const idx = self.peer_count;
            self.peer_keys[idx] = pk;
            self.peer_stops[idx].store(false, .release);
            self.peer_count += 1;

            // Spawn accept forwarder thread.
            _ = Rt.Thread.spawn(.{}, acceptLoopFn, .{ self, pk, idx }) catch return;
        }

        fn acceptLoopFn(self: *Self, pk: Key, idx: usize) void {
            while (!self.peer_stops[idx].load(.acquire) and self.getState() != .stopped) {
                if (self.udp.acceptStream(&pk)) |stream| {
                    const ns = NodeStream{
                        .stream = stream,
                        .remote_pk = pk,
                    };

                    // Route to proto-specific listener if registered.
                    // Hold lock during send to prevent closeListen from
                    // destroying the listener between lookup and use.
                    const proto_byte = stream.getProto();
                    self.listener_mutex.lock();
                    if (self.proto_listeners[proto_byte]) |l| {
                        l.ch.send(ns) catch {
                            stream.shutdown();
                        };
                        self.listener_mutex.unlock();
                    } else {
                        self.listener_mutex.unlock();
                        self.pushAccept(ns);
                    }
                } else {
                    Rt.sleepMs(50);
                }
            }
        }

        fn pushAccept(self: *Self, ns: NodeStream) void {
            self.accept_mutex.lock();
            defer self.accept_mutex.unlock();

            if (self.accept_count < self.accept_buf.len) {
                self.accept_buf[self.accept_head] = ns;
                self.accept_head = (self.accept_head + 1) % self.accept_buf.len;
                self.accept_count += 1;
                self.accept_cond.signal();
            } else {
                // Accept queue full — drop stream.
                ns.stream.shutdown();
            }
        }
    };
}

// Convenience: std import for mem.eql in generic code
const std = @import("std");
