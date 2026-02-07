//! Host: bridges TUN virtual network device with encrypted UDP transport.
//!
//! The Host reads IP packets from a TUN device, strips the IP header,
//! encrypts the payload using the Noise Protocol, and sends it via UDP.
//! Incoming encrypted packets are decrypted, reassembled with a new IP header,
//! and written to the TUN device.
//!
//! ## Architecture
//!
//! ```text
//! Outbound: TUN.Read -> parse dst IP -> lookup peer -> strip IP header -> encrypt -> UDP send
//! Inbound:  UDP recv -> decrypt -> lookup src IP -> rebuild IP header -> TUN.Write
//! ```

const std = @import("std");
const posix = std.posix;
const Allocator = std.mem.Allocator;
const Thread = std.Thread;
const Atomic = std.atomic.Value;

const noise = @import("../noise/mod.zig");
const message = noise.message;
const Key = noise.Key;
const KeyPair = noise.KeyPair;

pub const ipalloc = @import("ipalloc.zig");
pub const packet = @import("packet.zig");
pub const IPAllocator = ipalloc.IPAllocator;
pub const AllocError = ipalloc.AllocError;
pub const PacketInfo = packet.PacketInfo;
pub const PacketError = packet.PacketError;
pub const parseIpPacket = packet.parseIpPacket;
pub const buildIpv4Packet = packet.buildIpv4Packet;
pub const buildIpv6Packet = packet.buildIpv6Packet;

// ============================================================================
// TunDevice interface
// ============================================================================

/// Abstraction over a TUN device for reading/writing IP packets.
/// The real tun.Tun satisfies this interface (via wrapper).
/// For testing, a mock implementation can be provided.
pub const TunDevice = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        read: *const fn (ptr: *anyopaque, buf: []u8) ReadError!usize,
        write: *const fn (ptr: *anyopaque, data: []const u8) WriteError!usize,
        close: *const fn (ptr: *anyopaque) void,
    };

    pub const ReadError = error{
        Closed,
        IoError,
        WouldBlock,
    };

    pub const WriteError = error{
        Closed,
        IoError,
    };

    pub fn read(self: TunDevice, buf: []u8) ReadError!usize {
        return self.vtable.read(self.ptr, buf);
    }

    pub fn write(self: TunDevice, data: []const u8) WriteError!usize {
        return self.vtable.write(self.ptr, data);
    }

    pub fn close(self: TunDevice) void {
        return self.vtable.close(self.ptr);
    }

    /// Helper to create a TunDevice from a concrete type implementing read/write/close.
    pub fn init(pointer: anytype) TunDevice {
        const Ptr = @TypeOf(pointer);
        const ptr_info = @typeInfo(Ptr);
        if (ptr_info != .pointer) @compileError("Expected pointer, got " ++ @typeName(Ptr));

        const Child = ptr_info.pointer.child;

        const gen = struct {
            fn readFn(p: *anyopaque, buf: []u8) ReadError!usize {
                const self: *Child = @ptrCast(@alignCast(p));
                return self.read(buf);
            }
            fn writeFn(p: *anyopaque, data: []const u8) WriteError!usize {
                const self: *Child = @ptrCast(@alignCast(p));
                return self.write(data);
            }
            fn closeFn(p: *anyopaque) void {
                const self: *Child = @ptrCast(@alignCast(p));
                self.close();
            }

            const vtable = VTable{
                .read = readFn,
                .write = writeFn,
                .close = closeFn,
            };
        };

        return .{
            .ptr = @ptrCast(pointer),
            .vtable = &gen.vtable,
        };
    }
};

// ============================================================================
// Config
// ============================================================================

/// Configuration for creating a Host.
pub const Config = struct {
    /// Local keypair for Noise Protocol handshakes.
    private_key: *const KeyPair,
    /// Local IPv4 address assigned to the TUN device (CGNAT range).
    tun_ipv4: [4]u8,
    /// Maximum Transmission Unit. Default: 1400.
    mtu: usize = 1400,
    /// UDP port to listen on. 0 for random.
    listen_port: u16 = 0,
};

/// Configuration for a peer.
pub const PeerConfig = struct {
    /// Peer's Curve25519 public key.
    public_key: Key,
    /// Peer's UDP endpoint (sockaddr + length). null = no known endpoint.
    endpoint: ?posix.sockaddr = null,
    endpoint_len: posix.socklen_t = 0,
    /// Optional static IPv4 assignment. null = auto-allocate.
    ipv4: ?[4]u8 = null,
};

// ============================================================================
// Host
// ============================================================================

pub const HostError = error{
    InitFailed,
    PeerError,
    AllocError,
};

/// Host bridges a TUN virtual network device with encrypted UDP transport.
/// Generic over `UDPType` to support different IO backends.
pub fn Host(comptime UDPType: type) type {
    return struct {
        const Self = @This();

        allocator: Allocator,
        tun: TunDevice,
        udp: *UDPType,
        ip_alloc: *IPAllocator,
        tun_ipv4: [4]u8,
        mtu: usize,
        closed: Atomic(bool),

        // Threads
        outbound_thread: ?Thread,
        inbound_thread: ?Thread,

        pub fn init(
            allocator: Allocator,
            cfg: Config,
            tun_dev: TunDevice,
        ) HostError!*Self {
            // Create UDP transport
            var bind_buf: [32]u8 = undefined;
            const bind_addr = std.fmt.bufPrint(&bind_buf, "0.0.0.0:{d}", .{cfg.listen_port}) catch
                return HostError.InitFailed;

            const udp = UDPType.init(allocator, cfg.private_key, .{
                .bind_addr = bind_addr,
                .allow_unknown = true,
            }) catch return HostError.InitFailed;

            const ip_alloc = allocator.create(IPAllocator) catch {
                udp.deinit();
                return HostError.InitFailed;
            };
            ip_alloc.* = IPAllocator.init(allocator);

            const self = allocator.create(Self) catch {
                ip_alloc.deinit();
                allocator.destroy(ip_alloc);
                udp.deinit();
                return HostError.InitFailed;
            };
            self.* = .{
                .allocator = allocator,
                .tun = tun_dev,
                .udp = udp,
                .ip_alloc = ip_alloc,
                .tun_ipv4 = cfg.tun_ipv4,
                .mtu = cfg.mtu,
                .closed = Atomic(bool).init(false),
                .outbound_thread = null,
                .inbound_thread = null,
            };

            return self;
        }

        /// Add a peer with optional static IP.
        pub fn addPeerWithIp(self: *Self, pk: Key, endpoint: ?posix.sockaddr, endpoint_len: posix.socklen_t, ipv4: ?[4]u8) HostError!void {
            // Assign IP
            if (ipv4) |ip| {
                self.ip_alloc.assignStatic(pk, ip) catch return HostError.AllocError;
            } else {
                _ = self.ip_alloc.assign(pk) catch return HostError.AllocError;
            }

            // Set endpoint in UDP layer
            if (endpoint) |ep| {
                self.udp.setPeerEndpoint(pk, ep, endpoint_len);
            }
        }

        /// Add a peer with auto-allocated IP.
        pub fn addPeer(self: *Self, pk: Key, endpoint: ?posix.sockaddr, endpoint_len: posix.socklen_t) HostError!void {
            return self.addPeerWithIp(pk, endpoint, endpoint_len, null);
        }

        /// Initiate a Noise handshake with the specified peer.
        pub fn connect(self: *Self, pk: *const Key) !void {
            self.udp.connect(pk) catch return error.InitFailed;
        }

        /// Start the outbound and inbound forwarding loops.
        pub fn run(self: *Self) void {
            self.outbound_thread = Thread.spawn(.{}, outboundLoop, .{self}) catch null;
            self.inbound_thread = Thread.spawn(.{}, inboundLoop, .{self}) catch null;
        }

        /// Gracefully shut down the host.
        pub fn close(self: *Self) void {
            if (self.closed.swap(true, .seq_cst)) return;

            // Close TUN and UDP to unblock the loops
            self.tun.close();
            self.udp.close();

            // Wait for threads to finish
            if (self.outbound_thread) |t| t.join();
            if (self.inbound_thread) |t| t.join();
        }

        /// Destroy the host and free all resources.
        pub fn deinit(self: *Self) void {
            if (!self.closed.load(.acquire)) {
                self.close();
            }
            self.ip_alloc.deinit();
            self.allocator.destroy(self.ip_alloc);
            self.allocator.destroy(self);
        }

        /// Returns the local UDP port.
        pub fn getLocalPort(self: *Self) u16 {
            return self.udp.getLocalPort();
        }

        /// Returns the host's public key.
        pub fn getPublicKey(self: *Self) Key {
            return self.udp.local_key.public;
        }

        // ====================================================================
        // Forwarding loops
        // ====================================================================

        fn outboundLoop(self: *Self) void {
            var buf: [1500 + 40]u8 = undefined; // MTU + extra room

            while (!self.closed.load(.acquire)) {
                // TODO(async-tun): Replace blocking read with async I/O
                // (kqueue/io_uring). Currently TUN read is blocking, so
                // WouldBlock never triggers. See design/14-async-tun.md.
                const n = self.tun.read(&buf) catch |err| {
                    if (self.closed.load(.acquire)) return;
                    std.debug.print("host: tun read error: {}\n", .{err});
                    continue;
                };

                if (n == 0) continue;

                self.handleOutbound(buf[0..n]);
            }
        }

        fn handleOutbound(self: *Self, ip_pkt: []const u8) void {
            const info = parseIpPacket(ip_pkt) catch return;

            // Look up peer by destination IP
            if (info.dst_ip.len == 4) {
                const dst4: [4]u8 = info.dst_ip[0..4].*;
                const pk = self.ip_alloc.lookupByIp(dst4) orelse return;

                // Map IP protocol number to noise protocol byte
                switch (info.protocol) {
                    1 => self.udp.writeToProtocol(&pk, @intFromEnum(message.Protocol.icmp), info.payload) catch {},
                    6 => self.udp.writeToProtocol(&pk, @intFromEnum(message.Protocol.tcp), info.payload) catch {},
                    17 => self.udp.writeToProtocol(&pk, @intFromEnum(message.Protocol.udp), info.payload) catch {},
                    else => {
                        // For unrecognized protocols, send as ProtocolIP (complete IP packet)
                        self.udp.writeToProtocol(&pk, @intFromEnum(message.Protocol.ip), ip_pkt) catch {};
                    },
                }
            }
        }

        fn inboundLoop(self: *Self) void {
            var buf: [message.max_packet_size]u8 = undefined;

            while (!self.closed.load(.acquire)) {
                const result = self.udp.readPacket(&buf) catch |err| {
                    if (self.closed.load(.acquire)) return;
                    std.debug.print("host: udp read error: {}\n", .{err});
                    continue;
                };

                if (result.n == 0) continue;

                self.handleInbound(result.pk, result.protocol, buf[0..result.n]);
            }
        }

        fn handleInbound(self: *Self, pk: Key, proto: u8, payload: []const u8) void {
            if (proto == @intFromEnum(message.Protocol.ip)) {
                // Complete IP packet — write directly to TUN
                _ = self.tun.write(payload) catch {};
                return;
            }

            if (proto == @intFromEnum(message.Protocol.icmp) or
                proto == @intFromEnum(message.Protocol.tcp) or
                proto == @intFromEnum(message.Protocol.udp))
            {
                // Transport payload without IP header — rebuild and write to TUN
                const src_ip = self.ip_alloc.lookupByPubkey(pk) orelse return;

                const ip_pkt = buildIpv4Packet(self.allocator, src_ip, self.tun_ipv4, proto, payload) catch return;
                defer self.allocator.free(ip_pkt);

                _ = self.tun.write(ip_pkt) catch {};
            }
            // Unknown protocol — ignore
        }
    };
}

// Import tests
test {
    _ = ipalloc;
    _ = packet;
    _ = @import("tests.zig");
}
