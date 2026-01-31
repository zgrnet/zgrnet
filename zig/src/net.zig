//! Unified UDP networking layer for zgrnet.
//!
//! Provides a single `UDP` type that manages multiple peers, handles
//! Noise Protocol handshakes, and supports roaming.

const std = @import("std");
const Allocator = std.mem.Allocator;
const Mutex = std.Thread.Mutex;
const Atomic = std.atomic.Value;
const posix = std.posix;

const keypair = @import("keypair.zig");
const handshake_mod = @import("handshake.zig");
const message = @import("message.zig");
const session_mod = @import("session.zig");

pub const Key = keypair.Key;
pub const KeyPair = keypair.KeyPair;
pub const key_size = keypair.key_size;
pub const Session = session_mod.Session;
pub const SessionConfig = session_mod.SessionConfig;
pub const HandshakeState = handshake_mod.HandshakeState;
pub const Config = handshake_mod.Config;
pub const Pattern = handshake_mod.Pattern;

/// Peer connection state.
pub const PeerState = enum {
    /// Newly registered peer.
    new,
    /// Performing handshake.
    connecting,
    /// Session established.
    established,
    /// Connection failed.
    failed,

    pub fn format(
        self: PeerState,
        comptime _: []const u8,
        _: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        try writer.writeAll(switch (self) {
            .new => "new",
            .connecting => "connecting",
            .established => "established",
            .failed => "failed",
        });
    }
};


/// Information about a peer.
pub const PeerInfo = struct {
    public_key: Key,
    endpoint_port: u16,
    endpoint_addr: u32, // IPv4 address in network byte order
    has_endpoint: bool,
    state: PeerState,
    rx_bytes: u64,
    tx_bytes: u64,
    last_seen_ns: i64,
};

/// A peer with its info.
pub const Peer = struct {
    info: PeerInfo,
};

/// Errors from UDP operations.
pub const UdpError = error{
    /// UDP socket is closed.
    Closed,
    /// Peer not found.
    PeerNotFound,
    /// Peer has no endpoint.
    NoEndpoint,
    /// Peer has no established session.
    NoSession,
    /// Handshake failed.
    HandshakeFailed,
    /// Handshake timeout.
    HandshakeTimeout,
    /// Socket bind failed.
    BindFailed,
    /// Socket receive failed.
    ReceiveFailed,
    /// Socket send failed.
    SendFailed,
    /// Encryption failed.
    EncryptFailed,
    /// Decryption failed.
    DecryptFailed,
    /// Out of memory.
    OutOfMemory,
    /// Message too short.
    MessageTooShort,
};

/// Internal peer state.
const PeerStateInternal = struct {
    mutex: Mutex = .{},
    pk: Key,
    endpoint: ?posix.sockaddr,
    endpoint_len: posix.socklen_t,
    session: ?Session,
    state: PeerState,
    rx_bytes: u64,
    tx_bytes: u64,
    last_seen: ?i128,
};

/// Pending handshake tracking.
const PendingHandshake = struct {
    peer_pk: Key,
    hs_state: HandshakeState,
    local_idx: u32,
    done: bool,
    result: ?UdpError,
    created_at: i128,
};

/// Options for creating a UDP instance.
pub const UdpOptions = struct {
    /// Address to bind to. Default is "0.0.0.0:0".
    bind_addr: ?[]const u8 = null,
    /// Port to bind to (overrides bind_addr port).
    port: u16 = 0,
    /// Allow connections from unknown peers.
    allow_unknown: bool = false,
};

/// UDP-based network using the Noise Protocol.
///
/// Manages multiple peers, handles handshakes, and supports roaming.
pub const UDP = struct {
    allocator: Allocator,
    socket: posix.socket_t,
    local_key: KeyPair,
    allow_unknown: bool,

    // Peer management
    peers_mutex: Mutex = .{},
    peers_map: std.AutoHashMap(Key, *PeerStateInternal),
    by_index: std.AutoHashMap(u32, Key),

    // Pending handshakes (as initiator)
    pending_mutex: Mutex = .{},
    pending: std.AutoHashMap(u32, *PendingHandshake),

    // Statistics
    total_rx: Atomic(u64) = Atomic(u64).init(0),
    total_tx: Atomic(u64) = Atomic(u64).init(0),
    last_seen: Atomic(i128) = Atomic(i128).init(0),

    // State
    closed: Atomic(bool) = Atomic(bool).init(false),

    // Local address
    local_addr: posix.sockaddr,
    local_addr_len: posix.socklen_t,
    local_port: u16,

    /// Creates a new UDP network.
    pub fn init(allocator: Allocator, key: KeyPair, opts: UdpOptions) UdpError!*UDP {
        const self = allocator.create(UDP) catch return UdpError.OutOfMemory;
        errdefer allocator.destroy(self);

        // Create socket
        const socket = posix.socket(posix.AF.INET, posix.SOCK.DGRAM, 0) catch return UdpError.BindFailed;
        errdefer posix.close(socket);

        // Set socket to non-blocking mode
        const current_flags = posix.fcntl(socket, posix.F.GETFL, 0) catch 0;
        var o_flags: posix.O = @bitCast(@as(u32, @truncate(current_flags)));
        o_flags.NONBLOCK = true;
        _ = posix.fcntl(socket, posix.F.SETFL, @as(usize, @as(u32, @bitCast(o_flags)))) catch {};

        // Bind address
        var addr: posix.sockaddr.in = .{
            .family = posix.AF.INET,
            .port = std.mem.nativeToBig(u16, opts.port),
            .addr = 0, // INADDR_ANY
        };

        posix.bind(socket, @ptrCast(&addr), @sizeOf(posix.sockaddr.in)) catch return UdpError.BindFailed;

        // Get actual bound address (reuse addr which is properly aligned)
        var bound_addr_len: posix.socklen_t = @sizeOf(posix.sockaddr.in);
        posix.getsockname(socket, @ptrCast(&addr), &bound_addr_len) catch return UdpError.BindFailed;

        // Extract the actual port after binding
        const local_port = std.mem.bigToNative(u16, addr.port);

        self.* = .{
            .allocator = allocator,
            .socket = socket,
            .local_key = key,
            .allow_unknown = opts.allow_unknown,
            .peers_map = std.AutoHashMap(Key, *PeerStateInternal).init(allocator),
            .by_index = std.AutoHashMap(u32, Key).init(allocator),
            .pending = std.AutoHashMap(u32, *PendingHandshake).init(allocator),
            .local_addr = @as(*posix.sockaddr, @ptrCast(&addr)).*,
            .local_addr_len = bound_addr_len,
            .local_port = local_port,
        };

        return self;
    }

    /// Cleanup and release all resources.
    pub fn deinit(self: *UDP) void {
        self.closed.store(true, .seq_cst);

        // Close socket
        posix.close(self.socket);

        // Free peers
        var peer_iter = self.peers_map.valueIterator();
        while (peer_iter.next()) |peer_ptr| {
            self.allocator.destroy(peer_ptr.*);
        }
        self.peers_map.deinit();
        self.by_index.deinit();

        // Free pending
        var pending_iter = self.pending.valueIterator();
        while (pending_iter.next()) |p_ptr| {
            self.allocator.destroy(p_ptr.*);
        }
        self.pending.deinit();

        self.allocator.destroy(self);
    }

    /// Sets or updates a peer's endpoint address.
    pub fn setPeerEndpoint(self: *UDP, pk: Key, addr: posix.sockaddr, addr_len: posix.socklen_t) void {
        if (self.closed.load(.seq_cst)) {
            return;
        }

        self.peers_mutex.lock();
        defer self.peers_mutex.unlock();

        if (self.peers_map.get(pk)) |peer| {
            peer.mutex.lock();
            defer peer.mutex.unlock();
            peer.endpoint = addr;
            peer.endpoint_len = addr_len;
        } else {
            const peer = self.allocator.create(PeerStateInternal) catch return;
            peer.* = .{
                .pk = pk,
                .endpoint = addr,
                .endpoint_len = addr_len,
                .session = null,
                .state = .new,
                .rx_bytes = 0,
                .tx_bytes = 0,
                .last_seen = null,
            };
            self.peers_map.put(pk, peer) catch {
                self.allocator.destroy(peer);
            };
        }
    }

    /// Removes a peer.
    pub fn removePeer(self: *UDP, pk: *const Key) void {
        self.peers_mutex.lock();
        defer self.peers_mutex.unlock();

        if (self.peers_map.fetchRemove(pk.*)) |kv| {
            const peer = kv.value;
            peer.mutex.lock();
            if (peer.session) |*session| {
                _ = self.by_index.remove(session.localIndex());
            }
            peer.mutex.unlock();
            self.allocator.destroy(peer);
        }
    }

    /// Returns the local public key.
    pub fn publicKey(self: *UDP) Key {
        return self.local_key.public;
    }

    /// Returns the local port.
    pub fn port(self: *UDP) u16 {
        return self.local_port;
    }

    /// Returns the peer count.
    pub fn peerCount(self: *UDP) usize {
        self.peers_mutex.lock();
        defer self.peers_mutex.unlock();
        return self.peers_map.count();
    }

    /// Returns the total received bytes.
    pub fn rxBytes(self: *UDP) u64 {
        return self.total_rx.load(.seq_cst);
    }

    /// Returns the total transmitted bytes.
    pub fn txBytes(self: *UDP) u64 {
        return self.total_tx.load(.seq_cst);
    }

    /// Returns information about a specific peer.
    pub fn peerInfo(self: *UDP, pk: *const Key) ?PeerInfo {
        self.peers_mutex.lock();
        const peer = self.peers_map.get(pk.*) orelse {
            self.peers_mutex.unlock();
            return null;
        };
        self.peers_mutex.unlock();

        peer.mutex.lock();
        defer peer.mutex.unlock();

        var endpoint_port: u16 = 0;
        var endpoint_addr: u32 = 0;
        const has_endpoint = peer.endpoint != null;
        if (peer.endpoint) |ep| {
            const addr_in: *const posix.sockaddr.in = @ptrCast(@alignCast(&ep));
            endpoint_port = std.mem.bigToNative(u16, addr_in.port);
            endpoint_addr = addr_in.addr;
        }

        const last_seen_ns: i64 = if (peer.last_seen) |ls| @as(i64, @truncate(@mod(ls, std.math.maxInt(i64)))) else 0;

        return .{
            .public_key = peer.pk,
            .endpoint_port = endpoint_port,
            .endpoint_addr = endpoint_addr,
            .has_endpoint = has_endpoint,
            .state = peer.state,
            .rx_bytes = peer.rx_bytes,
            .tx_bytes = peer.tx_bytes,
            .last_seen_ns = last_seen_ns,
        };
    }

    /// Returns all peers.
    pub fn peers(self: *UDP, allocator: Allocator) ![]Peer {
        self.peers_mutex.lock();
        defer self.peers_mutex.unlock();

        var result = std.ArrayList(Peer).init(allocator);
        errdefer result.deinit();

        var iter = self.peers_map.valueIterator();
        while (iter.next()) |peer_ptr| {
            const peer = peer_ptr.*;
            peer.mutex.lock();
            defer peer.mutex.unlock();

            var endpoint_port: u16 = 0;
            var endpoint_addr: u32 = 0;
            const has_endpoint = peer.endpoint != null;
            if (peer.endpoint) |ep| {
                const addr_in: *const posix.sockaddr.in = @ptrCast(&ep);
                endpoint_port = std.mem.bigToNative(u16, addr_in.port);
                endpoint_addr = addr_in.addr;
            }

            const last_seen_ns: i64 = if (peer.last_seen) |ls| @as(i64, @truncate(@mod(ls, std.math.maxInt(i64)))) else 0;

            try result.append(.{
                .info = .{
                    .public_key = peer.pk,
                    .endpoint_port = endpoint_port,
                    .endpoint_addr = endpoint_addr,
                    .has_endpoint = has_endpoint,
                    .state = peer.state,
                    .rx_bytes = peer.rx_bytes,
                    .tx_bytes = peer.tx_bytes,
                    .last_seen_ns = last_seen_ns,
                },
            });
        }

        return result.toOwnedSlice();
    }

    /// Sends encrypted data to a peer.
    pub fn writeTo(self: *UDP, pk: *const Key, data: []const u8) UdpError!void {
        if (self.closed.load(.seq_cst)) {
            return UdpError.Closed;
        }

        self.peers_mutex.lock();
        const peer = self.peers_map.get(pk.*) orelse {
            self.peers_mutex.unlock();
            return UdpError.PeerNotFound;
        };
        self.peers_mutex.unlock();

        peer.mutex.lock();
        defer peer.mutex.unlock();

        const endpoint = peer.endpoint orelse return UdpError.NoEndpoint;
        var session = peer.session orelse return UdpError.NoSession;

        // Encrypt the data
        var ciphertext: [message.max_packet_size]u8 = undefined;
        const nonce = session.encrypt(data, ciphertext[0 .. data.len + 16]) catch return UdpError.EncryptFailed;

        // Build transport message
        const header = message.buildTransportHeader(session.remoteIndex(), nonce);
        var msg: [message.max_packet_size]u8 = undefined;
        @memcpy(msg[0..message.transport_header_size], &header);
        @memcpy(msg[message.transport_header_size..][0 .. data.len + 16], ciphertext[0 .. data.len + 16]);

        const msg_len = message.transport_header_size + data.len + 16;

        // Send
        const n = posix.sendto(self.socket, msg[0..msg_len], 0, &endpoint, peer.endpoint_len) catch return UdpError.SendFailed;

        // Update stats
        _ = self.total_tx.fetchAdd(@intCast(n), .seq_cst);
        peer.tx_bytes += @intCast(n);
        peer.session = session;
    }

    /// Reads the next decrypted message from any peer.
    /// Handles handshakes internally and only returns transport data.
    /// Returns (sender_pk, bytes_read).
    pub fn readFrom(self: *UDP, buf: []u8) UdpError!struct { pk: Key, n: usize } {
        if (self.closed.load(.seq_cst)) {
            return UdpError.Closed;
        }

        var recv_buf: [message.max_packet_size]u8 = undefined;

        while (true) {
            if (self.closed.load(.seq_cst)) {
                return UdpError.Closed;
            }

            // Read from socket (non-blocking)
            var from_addr: posix.sockaddr = undefined;
            var from_addr_len: posix.socklen_t = @sizeOf(posix.sockaddr);

            const nr = posix.recvfrom(self.socket, &recv_buf, 0, &from_addr, &from_addr_len) catch |err| {
                if (err == error.WouldBlock) {
                    // Non-blocking, sleep a bit
                    std.time.sleep(1 * std.time.ns_per_ms);
                    continue;
                }
                if (self.closed.load(.seq_cst)) {
                    return UdpError.Closed;
                }
                return UdpError.ReceiveFailed;
            };

            if (nr < 1) {
                continue;
            }

            // Update stats
            _ = self.total_rx.fetchAdd(@intCast(nr), .seq_cst);
            self.last_seen.store(std.time.nanoTimestamp(), .seq_cst);

            // Parse message type
            const msg_type: message.MessageType = @enumFromInt(recv_buf[0]);

            switch (msg_type) {
                .handshake_init => {
                    self.handleHandshakeInit(recv_buf[0..nr], from_addr, from_addr_len);
                    continue;
                },
                .handshake_resp => {
                    self.handleHandshakeResp(recv_buf[0..nr], from_addr, from_addr_len);
                    continue;
                },
                .transport => {
                    if (self.handleTransport(recv_buf[0..nr], from_addr, from_addr_len, buf)) |result| {
                        return result;
                    }
                    continue;
                },
                else => continue,
            }
        }
    }

    /// Initiates a handshake with a peer.
    pub fn connect(self: *UDP, pk: *const Key) UdpError!void {
        return self.connectTimeout(pk, 5 * std.time.ns_per_s);
    }

    /// Initiates a handshake with a peer with timeout.
    pub fn connectTimeout(self: *UDP, pk: *const Key, timeout_ns: i128) UdpError!void {
        if (self.closed.load(.seq_cst)) {
            return UdpError.Closed;
        }

        self.peers_mutex.lock();
        const peer = self.peers_map.get(pk.*) orelse {
            self.peers_mutex.unlock();
            return UdpError.PeerNotFound;
        };
        self.peers_mutex.unlock();

        peer.mutex.lock();
        const endpoint = peer.endpoint orelse {
            peer.mutex.unlock();
            return UdpError.NoEndpoint;
        };
        const endpoint_len = peer.endpoint_len;
        peer.state = .connecting;
        peer.mutex.unlock();

        // Generate local index
        const local_idx = session_mod.generateIndex();

        // Create handshake state
        var hs = HandshakeState.init(.{
            .pattern = .IK,
            .initiator = true,
            .local_static = self.local_key,
            .remote_static = pk.*,
        }) catch return UdpError.HandshakeFailed;

        // Write handshake initiation
        var msg_buf: [256]u8 = undefined;
        const msg_len = hs.writeMessage(&.{}, &msg_buf) catch return UdpError.HandshakeFailed;

        // Build wire message
        const ephemeral = hs.local_ephemeral orelse return UdpError.HandshakeFailed;
        const wire_msg = message.buildHandshakeInit(local_idx, &ephemeral.public, msg_buf[key_size..msg_len]);

        // Register pending handshake
        const pending = self.allocator.create(PendingHandshake) catch return UdpError.OutOfMemory;
        pending.* = .{
            .peer_pk = pk.*,
            .hs_state = hs,
            .local_idx = local_idx,
            .done = false,
            .result = null,
            .created_at = std.time.nanoTimestamp(),
        };

        self.pending_mutex.lock();
        self.pending.put(local_idx, pending) catch {
            self.pending_mutex.unlock();
            self.allocator.destroy(pending);
            return UdpError.OutOfMemory;
        };
        self.pending_mutex.unlock();

        // Send handshake initiation
        _ = posix.sendto(self.socket, &wire_msg, 0, &endpoint, endpoint_len) catch {
            self.pending_mutex.lock();
            _ = self.pending.remove(local_idx);
            self.pending_mutex.unlock();
            self.allocator.destroy(pending);
            return UdpError.SendFailed;
        };

        // Wait for response with timeout
        const start = std.time.nanoTimestamp();
        while (true) {
            self.pending_mutex.lock();
            const p = self.pending.get(local_idx);
            if (p) |pend| {
                if (pend.done) {
                    const result = pend.result;
                    _ = self.pending.remove(local_idx);
                    self.pending_mutex.unlock();
                    self.allocator.destroy(pend);
                    if (result) |err| {
                        return err;
                    }
                    return;
                }
            } else {
                // Already removed (completed)
                self.pending_mutex.unlock();
                return;
            }
            self.pending_mutex.unlock();

            const elapsed = std.time.nanoTimestamp() - start;
            if (elapsed > timeout_ns) {
                self.pending_mutex.lock();
                _ = self.pending.remove(local_idx);
                self.pending_mutex.unlock();
                self.allocator.destroy(pending);

                peer.mutex.lock();
                peer.state = .failed;
                peer.mutex.unlock();
                return UdpError.HandshakeTimeout;
            }

            std.time.sleep(10 * std.time.ns_per_ms);
        }
    }

    /// Closes the UDP network.
    pub fn close(self: *UDP) void {
        self.closed.store(true, .seq_cst);
    }

    /// Returns true if the UDP network is closed.
    pub fn isClosed(self: *UDP) bool {
        return self.closed.load(.seq_cst);
    }

    // Internal: handle incoming handshake initiation
    fn handleHandshakeInit(self: *UDP, data: []const u8, from: posix.sockaddr, from_len: posix.socklen_t) void {
        const msg = message.parseHandshakeInit(data) catch return;

        // Create handshake state to process the init
        var hs = HandshakeState.init(.{
            .pattern = .IK,
            .initiator = false,
            .local_static = self.local_key,
        }) catch return;

        // Build Noise message from wire format
        var noise_msg: [key_size + 48]u8 = undefined;
        @memcpy(noise_msg[0..key_size], msg.ephemeral.asBytes());
        @memcpy(noise_msg[key_size..][0..48], &msg.static_encrypted);

        // Read the handshake message
        var payload_buf: [64]u8 = undefined;
        _ = hs.readMessage(&noise_msg, &payload_buf) catch return;

        // Get the remote's public key
        const remote_pk = hs.getRemoteStatic();

        // Check if peer is known or if we allow unknown peers
        self.peers_mutex.lock();
        if (self.peers_map.get(remote_pk) == null) {
            if (!self.allow_unknown) {
                self.peers_mutex.unlock();
                return;
            }
            const peer = self.allocator.create(PeerStateInternal) catch {
                self.peers_mutex.unlock();
                return;
            };
            peer.* = .{
                .pk = remote_pk,
                .endpoint = from,
                .endpoint_len = from_len,
                .session = null,
                .state = .new,
                .rx_bytes = 0,
                .tx_bytes = 0,
                .last_seen = null,
            };
            self.peers_map.put(remote_pk, peer) catch {
                self.peers_mutex.unlock();
                self.allocator.destroy(peer);
                return;
            };
        }
        self.peers_mutex.unlock();

        // Generate local index for response
        const local_idx = session_mod.generateIndex();

        // Write response message
        var resp_buf: [256]u8 = undefined;
        const resp_len = hs.writeMessage(&.{}, &resp_buf) catch return;

        // Build wire message
        const ephemeral = hs.local_ephemeral orelse return;
        const wire_msg = message.buildHandshakeResp(local_idx, msg.sender_index, &ephemeral.public, resp_buf[key_size..resp_len]);

        // Send response
        _ = posix.sendto(self.socket, &wire_msg, 0, &from, from_len) catch return;

        // Complete handshake and create session
        const cipher_pair = hs.split() catch return;
        const send_cs = cipher_pair[0];
        const recv_cs = cipher_pair[1];

        const session = Session.init(.{
            .local_index = local_idx,
            .remote_index = msg.sender_index,
            .send_key = send_cs.key().*,
            .recv_key = recv_cs.key().*,
            .remote_pk = remote_pk,
        });

        // Update peer state
        self.peers_mutex.lock();
        if (self.peers_map.get(remote_pk)) |peer| {
            peer.mutex.lock();
            peer.endpoint = from;
            peer.endpoint_len = from_len;
            peer.session = session;
            peer.state = .established;
            peer.last_seen = std.time.nanoTimestamp();
            peer.mutex.unlock();
        }

        // Register in index map
        self.by_index.put(local_idx, remote_pk) catch {};
        self.peers_mutex.unlock();
    }

    // Internal: handle incoming handshake response
    fn handleHandshakeResp(self: *UDP, data: []const u8, from: posix.sockaddr, from_len: posix.socklen_t) void {
        const msg = message.parseHandshakeResp(data) catch return;

        // Find the pending handshake
        self.pending_mutex.lock();
        const pending = self.pending.get(msg.receiver_index) orelse {
            self.pending_mutex.unlock();
            return;
        };
        self.pending_mutex.unlock();

        // Build Noise message from wire format
        var noise_msg: [key_size + 16]u8 = undefined;
        @memcpy(noise_msg[0..key_size], msg.ephemeral.asBytes());
        @memcpy(noise_msg[key_size..][0..16], &msg.empty_encrypted);

        // Read the handshake response
        var payload_buf: [64]u8 = undefined;
        _ = pending.hs_state.readMessage(&noise_msg, &payload_buf) catch {
            self.peers_mutex.lock();
            if (self.peers_map.get(pending.peer_pk)) |peer| {
                peer.mutex.lock();
                peer.state = .failed;
                peer.mutex.unlock();
            }
            self.peers_mutex.unlock();
            pending.done = true;
            pending.result = UdpError.HandshakeFailed;
            return;
        };

        // Complete handshake and create session
        const cipher_pair = pending.hs_state.split() catch {
            pending.done = true;
            pending.result = UdpError.HandshakeFailed;
            return;
        };
        const send_cs = cipher_pair[0];
        const recv_cs = cipher_pair[1];

        const session = Session.init(.{
            .local_index = pending.local_idx,
            .remote_index = msg.sender_index,
            .send_key = send_cs.key().*,
            .recv_key = recv_cs.key().*,
            .remote_pk = pending.peer_pk,
        });

        // Update peer state
        self.peers_mutex.lock();
        if (self.peers_map.get(pending.peer_pk)) |peer| {
            peer.mutex.lock();
            peer.endpoint = from;
            peer.endpoint_len = from_len;
            peer.session = session;
            peer.state = .established;
            peer.last_seen = std.time.nanoTimestamp();
            peer.mutex.unlock();
        }

        // Register in index map
        self.by_index.put(pending.local_idx, pending.peer_pk) catch {};
        self.peers_mutex.unlock();

        // Signal completion
        pending.done = true;
        pending.result = null;
    }

    // Internal: handle incoming transport message
    fn handleTransport(self: *UDP, data: []const u8, from: posix.sockaddr, from_len: posix.socklen_t, out_buf: []u8) ?struct { pk: Key, n: usize } {
        const msg = message.parseTransportMessage(data) catch return null;

        // Find peer by receiver index
        self.peers_mutex.lock();
        const peer_pk = self.by_index.get(msg.receiver_index) orelse {
            self.peers_mutex.unlock();
            return null;
        };
        const peer = self.peers_map.get(peer_pk) orelse {
            self.peers_mutex.unlock();
            return null;
        };
        self.peers_mutex.unlock();

        peer.mutex.lock();
        defer peer.mutex.unlock();

        var session = peer.session orelse return null;

        // Decrypt
        const n = session.decrypt(msg.ciphertext, msg.counter, out_buf) catch return null;

        // Update peer state (roaming + stats)
        peer.endpoint = from;
        peer.endpoint_len = from_len;
        peer.rx_bytes += @intCast(data.len);
        peer.last_seen = std.time.nanoTimestamp();
        peer.session = session;

        return .{ .pk = peer_pk, .n = n };
    }
};

// =============================================================================
// Tests
// =============================================================================

test "new udp" {
    const allocator = std.testing.allocator;
    const key = KeyPair.generate();
    const udp = try UDP.init(allocator, key, .{});
    defer udp.deinit();
    try std.testing.expect(!udp.isClosed());
    udp.close();
    try std.testing.expect(udp.isClosed());
}

test "set peer endpoint" {
    const allocator = std.testing.allocator;
    const key = KeyPair.generate();
    const udp = try UDP.init(allocator, key, .{});
    defer udp.deinit();

    const peer_key = KeyPair.generate();
    var endpoint: posix.sockaddr.in = .{
        .family = posix.AF.INET,
        .port = std.mem.nativeToBig(u16, 12345),
        .addr = 0x7F000001, // 127.0.0.1
    };

    udp.setPeerEndpoint(peer_key.public, @as(*posix.sockaddr, @ptrCast(&endpoint)).*, @sizeOf(posix.sockaddr.in));

    const info = udp.peerInfo(&peer_key.public);
    try std.testing.expect(info != null);
    try std.testing.expectEqual(PeerState.new, info.?.state);
}

test "remove peer" {
    const allocator = std.testing.allocator;
    const key = KeyPair.generate();
    const udp = try UDP.init(allocator, key, .{});
    defer udp.deinit();

    const peer_key = KeyPair.generate();
    var endpoint: posix.sockaddr.in = .{
        .family = posix.AF.INET,
        .port = std.mem.nativeToBig(u16, 12345),
        .addr = 0x7F000001,
    };

    udp.setPeerEndpoint(peer_key.public, @as(*posix.sockaddr, @ptrCast(&endpoint)).*, @sizeOf(posix.sockaddr.in));
    try std.testing.expect(udp.peerInfo(&peer_key.public) != null);

    udp.removePeer(&peer_key.public);
    try std.testing.expect(udp.peerInfo(&peer_key.public) == null);
}

test "host info methods" {
    const allocator = std.testing.allocator;
    const key = KeyPair.generate();
    const udp = try UDP.init(allocator, key, .{});
    defer udp.deinit();

    try std.testing.expect(std.mem.eql(u8, &udp.publicKey().data, &key.public.data));
    try std.testing.expectEqual(@as(usize, 0), udp.peerCount());
}
