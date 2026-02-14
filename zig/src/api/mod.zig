//! RESTful API server for zgrnetd (Zig implementation).
//!
//! Provides HTTP endpoints for managing peers, lans, inbound policy, routes,
//! and querying node status. Write operations persist changes to config.json
//! and trigger a config reload.
//!
//! Uses a minimal HTTP/1.1 parser (std.net.Stream, no external deps).

const std = @import("std");
const mem = std.mem;
const fmt = std.fmt;
const net = std.net;
const posix = std.posix;
const Allocator = std.mem.Allocator;

const noise_mod = @import("../noise/mod.zig");
const Key = noise_mod.Key;
const host_mod = @import("../host/mod.zig");
const IPAllocator = host_mod.IPAllocator;
const config_types = @import("../config/types.zig");
const config_manager = @import("../config/manager.zig");

// ============================================================================
// Server
// ============================================================================

/// Configuration for the API server. Uses opaque pointers to avoid
/// generic type parameters leaking into the API module.
pub const ServerConfig = struct {
    listen_addr: []const u8,
    config_path: []const u8,
    /// Pointer to Host — used for public key, IP alloc, add/remove peer.
    /// Cast to the concrete Host type by the caller.
    host_ptr: *anyopaque,
    /// VTable for host operations (avoids generic leakage).
    host_vtable: *const HostVTable,
    /// Config manager for reload.
    config_mgr_ptr: *anyopaque,
    config_mgr_vtable: *const ConfigMgrVTable,
    /// TUN IPv4 address string for whoami response.
    tun_ipv4: []const u8,
    /// Hex-encoded public key.
    public_key_hex: []const u8,
};

/// VTable for host operations — lets the API server call Host methods
/// without knowing the concrete generic type.
pub const HostVTable = struct {
    addPeer: *const fn (ptr: *anyopaque, pk: Key, endpoint_str: []const u8) bool,
    removePeer: *const fn (ptr: *anyopaque, pk: Key) void,
    lookupIpByPubkey: *const fn (ptr: *anyopaque, pk: Key) ?[4]u8,
    lookupPubkeyByIp: *const fn (ptr: *anyopaque, ip: [4]u8) ?Key,
};

/// VTable for config manager operations.
pub const ConfigMgrVTable = struct {
    reload: *const fn (ptr: *anyopaque) bool,
};

pub const Server = struct {
    allocator: Allocator,
    config: ServerConfig,
    listener: ?posix.socket_t = null,

    pub fn init(allocator: Allocator, config: ServerConfig) Server {
        return .{
            .allocator = allocator,
            .config = config,
        };
    }

    /// Starts the server. Blocks until closed.
    pub fn serve(self: *Server) void {
        // Parse listen address
        const colon = mem.lastIndexOfScalar(u8, self.config.listen_addr, ':') orelse return;
        const host = self.config.listen_addr[0..colon];
        const port = fmt.parseInt(u16, self.config.listen_addr[colon + 1 ..], 10) catch return;

        var addr: [4]u8 = undefined;
        parseIpv4Simple(host, &addr) orelse return;

        const sa = net.Address.initIp4(addr, port);
        const sock = posix.socket(posix.AF.INET, posix.SOCK.STREAM, 0) catch return;
        self.listener = sock;

        // SO_REUSEADDR
        const one: c_int = 1;
        posix.setsockopt(sock, posix.SOL.SOCKET, posix.SO.REUSEADDR, mem.asBytes(&one)) catch {};

        posix.bind(sock, &sa.any, sa.getOsSockLen()) catch return;
        posix.listen(sock, 128) catch return;

        while (true) {
            var client_addr: posix.sockaddr.storage = undefined;
            var client_len: posix.socklen_t = @sizeOf(posix.sockaddr.storage);
            const client = posix.accept(sock, @ptrCast(&client_addr), &client_len, 0) catch {
                if (self.listener == null) return; // closed
                continue;
            };

            // Handle in a new thread
            _ = std.Thread.spawn(.{}, handleConnection, .{ self, client }) catch {
                posix.close(client);
                continue;
            };
        }
    }

    pub fn close(self: *Server) void {
        if (self.listener) |sock| {
            posix.close(sock);
            self.listener = null;
        }
    }

    // ========================================================================
    // Connection handling
    // ========================================================================

    fn handleConnection(self: *Server, client: posix.socket_t) void {
        defer posix.close(client);

        // Set read timeout
        const tv = posix.timeval{ .sec = 10, .usec = 0 };
        posix.setsockopt(client, posix.SOL.SOCKET, posix.SO.RCVTIMEO, mem.asBytes(&tv)) catch {};

        // Read request
        var buf: [8192]u8 = undefined;
        const n = posix.read(client, &buf) catch return;
        if (n == 0) return;

        const request = buf[0..n];

        // Parse method and path
        const first_line_end = mem.indexOf(u8, request, "\r\n") orelse return;
        const first_line = request[0..first_line_end];
        var parts = mem.splitScalar(u8, first_line, ' ');
        const method = parts.next() orelse return;
        const full_path = parts.next() orelse return;

        // Split path and query
        const q_idx = mem.indexOfScalar(u8, full_path, '?');
        const path = if (q_idx) |qi| full_path[0..qi] else full_path;
        const query = if (q_idx) |qi| full_path[qi + 1 ..] else "";

        // Extract body (after \r\n\r\n)
        const body_start = mem.indexOf(u8, request, "\r\n\r\n");
        const body = if (body_start) |bs| request[bs + 4 ..] else "";

        // Route and generate response
        const response = self.route(method, path, query, body);
        defer self.allocator.free(response);

        // Write response
        _ = writeAll(client, response) catch {};
    }

    fn route(self: *Server, method: []const u8, path: []const u8, query: []const u8, body: []const u8) []const u8 {
        // Read-only
        if (eql(method, "GET") and eql(path, "/api/whoami")) return self.handleWhoAmI();
        if (eql(method, "GET") and eql(path, "/api/config/net")) return self.handleConfigNet();
        if (eql(method, "GET") and eql(path, "/api/peers")) return self.handleListPeers();
        if (eql(method, "GET") and eql(path, "/api/lans")) return self.handleListLans();
        if (eql(method, "GET") and eql(path, "/api/policy")) return self.handleGetPolicy();
        if (eql(method, "GET") and eql(path, "/api/routes")) return self.handleListRoutes();
        if (eql(method, "GET") and eql(path, "/internal/identity")) return self.handleIdentity(query);
        if (eql(method, "POST") and eql(path, "/api/config/reload")) return self.handleConfigReload();
        if (eql(method, "POST") and eql(path, "/api/peers")) return self.handleAddPeer(body);
        if (eql(method, "POST") and eql(path, "/api/lans")) return self.handleAddLan(body);
        if (eql(method, "POST") and eql(path, "/api/policy/rules")) return self.handleAddPolicyRule(body);
        if (eql(method, "POST") and eql(path, "/api/routes")) return self.handleAddRoute(body);

        // Path-parameter routes
        if (eql(method, "GET") and mem.startsWith(u8, path, "/api/peers/")) return self.handleGetPeer(path["/api/peers/".len..]);
        if (eql(method, "DELETE") and mem.startsWith(u8, path, "/api/peers/")) return self.handleDeletePeer(path["/api/peers/".len..]);
        if (eql(method, "DELETE") and mem.startsWith(u8, path, "/api/lans/")) return self.handleDeleteLan(path["/api/lans/".len..]);
        if (eql(method, "DELETE") and mem.startsWith(u8, path, "/api/policy/rules/")) return self.handleDeletePolicyRule(path["/api/policy/rules/".len..]);
        if (eql(method, "DELETE") and mem.startsWith(u8, path, "/api/routes/")) return self.handleDeleteRoute(path["/api/routes/".len..]);

        return httpResponse(self.allocator, 404, "Not Found", "{\"error\":\"not found\"}");
    }

    // ========================================================================
    // Handlers
    // ========================================================================

    fn handleWhoAmI(self: *Server) []const u8 {
        const body = fmt.allocPrint(self.allocator,
            "{{\"pubkey\":\"{s}\",\"tun_ip\":\"{s}\"}}", .{
            self.config.public_key_hex, self.config.tun_ipv4,
        }) catch return httpResponse(self.allocator, 500, "Internal Server Error", "{\"error\":\"alloc\"}");
        defer self.allocator.free(body);
        return httpResponse(self.allocator, 200, "OK", body);
    }

    fn handleConfigNet(self: *Server) []const u8 {
        const cfg_data = readConfigFile(self.allocator, self.config.config_path) orelse
            return httpResponse(self.allocator, 500, "Internal Server Error", "{\"error\":\"read config\"}");
        defer self.allocator.free(cfg_data);

        // Extract "net" section from JSON
        const net_section = extractJsonSection(self.allocator, cfg_data, "net") orelse
            return httpResponse(self.allocator, 200, "OK", "{}");
        defer self.allocator.free(net_section);
        return httpResponse(self.allocator, 200, "OK", net_section);
    }

    fn handleListPeers(self: *Server) []const u8 {
        const cfg_data = readConfigFile(self.allocator, self.config.config_path) orelse
            return httpResponse(self.allocator, 200, "OK", "[]");
        defer self.allocator.free(cfg_data);
        const section = extractJsonSection(self.allocator, cfg_data, "peers") orelse
            return httpResponse(self.allocator, 200, "OK", "{}");
        defer self.allocator.free(section);
        return httpResponse(self.allocator, 200, "OK", section);
    }

    fn handleGetPeer(self: *Server, hex_pk: []const u8) []const u8 {
        _ = hex_pk;
        // For now, return the peers section. Full per-peer lookup would need
        // JSON path querying which is complex in Zig without a JSON DOM.
        return self.handleListPeers();
    }

    fn handleAddPeer(self: *Server, body: []const u8) []const u8 {
        // Parse pubkey from request body
        const pk_hex = extractJsonString(body, "pubkey") orelse
            return httpResponse(self.allocator, 400, "Bad Request", "{\"error\":\"pubkey is required\"}");

        var pk_bytes: [32]u8 = undefined;
        _ = fmt.hexToBytes(&pk_bytes, pk_hex) catch
            return httpResponse(self.allocator, 400, "Bad Request", "{\"error\":\"invalid pubkey hex\"}");

        const endpoint = extractJsonString(body, "endpoint") orelse "";

        // Add to runtime
        if (!self.config.host_vtable.addPeer(self.config.host_ptr, Key{ .data = pk_bytes }, endpoint)) {
            return httpResponse(self.allocator, 500, "Internal Server Error", "{\"error\":\"add peer failed\"}");
        }

        // Persist: append to config file
        if (self.appendToConfigArray("peers", pk_hex, body)) {
            // Reload config manager
            _ = self.config.config_mgr_vtable.reload(self.config.config_mgr_ptr);
        }

        return httpResponse(self.allocator, 201, "Created", body);
    }

    fn handleDeletePeer(self: *Server, hex_pk: []const u8) []const u8 {
        var pk_bytes: [32]u8 = undefined;
        _ = fmt.hexToBytes(&pk_bytes, hex_pk) catch
            return httpResponse(self.allocator, 400, "Bad Request", "{\"error\":\"invalid pubkey\"}");

        // Remove from runtime
        self.config.host_vtable.removePeer(self.config.host_ptr, Key{ .data = pk_bytes });

        // Persist: remove from config
        if (self.removeFromConfigObject("peers", hex_pk)) {
            _ = self.config.config_mgr_vtable.reload(self.config.config_mgr_ptr);
        }

        return httpResponse(self.allocator, 204, "No Content", "");
    }

    fn handleListLans(self: *Server) []const u8 {
        const cfg_data = readConfigFile(self.allocator, self.config.config_path) orelse
            return httpResponse(self.allocator, 200, "OK", "[]");
        defer self.allocator.free(cfg_data);
        const section = extractJsonSection(self.allocator, cfg_data, "lans") orelse
            return httpResponse(self.allocator, 200, "OK", "[]");
        defer self.allocator.free(section);
        return httpResponse(self.allocator, 200, "OK", section);
    }

    fn handleAddLan(self: *Server, body: []const u8) []const u8 {
        if (self.appendToConfigArraySimple("lans", body)) {
            _ = self.config.config_mgr_vtable.reload(self.config.config_mgr_ptr);
        }
        return httpResponse(self.allocator, 201, "Created", body);
    }

    fn handleDeleteLan(self: *Server, domain: []const u8) []const u8 {
        if (self.removeFromConfigArrayByField("lans", "domain", domain)) {
            _ = self.config.config_mgr_vtable.reload(self.config.config_mgr_ptr);
        }
        return httpResponse(self.allocator, 204, "No Content", "");
    }

    fn handleGetPolicy(self: *Server) []const u8 {
        const cfg_data = readConfigFile(self.allocator, self.config.config_path) orelse
            return httpResponse(self.allocator, 200, "OK", "{}");
        defer self.allocator.free(cfg_data);
        const section = extractJsonSection(self.allocator, cfg_data, "inbound_policy") orelse
            return httpResponse(self.allocator, 200, "OK", "{}");
        defer self.allocator.free(section);
        return httpResponse(self.allocator, 200, "OK", section);
    }

    fn handleAddPolicyRule(self: *Server, body: []const u8) []const u8 {
        // Append to inbound_policy.rules array
        if (self.appendToNestedArray("inbound_policy", "rules", body)) {
            _ = self.config.config_mgr_vtable.reload(self.config.config_mgr_ptr);
        }
        return httpResponse(self.allocator, 201, "Created", body);
    }

    fn handleDeletePolicyRule(self: *Server, name: []const u8) []const u8 {
        if (self.removeFromNestedArrayByField("inbound_policy", "rules", "name", name)) {
            _ = self.config.config_mgr_vtable.reload(self.config.config_mgr_ptr);
        }
        return httpResponse(self.allocator, 204, "No Content", "");
    }

    fn handleListRoutes(self: *Server) []const u8 {
        const cfg_data = readConfigFile(self.allocator, self.config.config_path) orelse
            return httpResponse(self.allocator, 200, "OK", "[]");
        defer self.allocator.free(cfg_data);
        const section = extractJsonSection(self.allocator, cfg_data, "route") orelse
            return httpResponse(self.allocator, 200, "OK", "{}");
        defer self.allocator.free(section);
        return httpResponse(self.allocator, 200, "OK", section);
    }

    fn handleAddRoute(self: *Server, body: []const u8) []const u8 {
        if (self.appendToNestedArray("route", "rules", body)) {
            _ = self.config.config_mgr_vtable.reload(self.config.config_mgr_ptr);
        }
        return httpResponse(self.allocator, 201, "Created", body);
    }

    fn handleDeleteRoute(self: *Server, id_str: []const u8) []const u8 {
        const id = fmt.parseInt(usize, id_str, 10) catch
            return httpResponse(self.allocator, 400, "Bad Request", "{\"error\":\"invalid route id\"}");
        if (self.removeFromNestedArrayByIndex("route", "rules", id)) {
            _ = self.config.config_mgr_vtable.reload(self.config.config_mgr_ptr);
        }
        return httpResponse(self.allocator, 204, "No Content", "");
    }

    fn handleIdentity(self: *Server, query: []const u8) []const u8 {
        const ip_str = getQueryParam(query, "ip") orelse
            return httpResponse(self.allocator, 400, "Bad Request", "{\"error\":\"ip parameter is required\"}");

        var ip: [4]u8 = undefined;
        parseIpv4Simple(ip_str, &ip) orelse
            return httpResponse(self.allocator, 400, "Bad Request", "{\"error\":\"invalid IP address\"}");

        const pk = self.config.host_vtable.lookupPubkeyByIp(self.config.host_ptr, ip) orelse
            return httpResponse(self.allocator, 404, "Not Found", "{\"error\":\"no peer found for IP\"}");

        var hex_buf: [64]u8 = undefined;
        for (pk.data, 0..) |b, idx| {
            const hex_chars = "0123456789abcdef";
            hex_buf[idx * 2] = hex_chars[b >> 4];
            hex_buf[idx * 2 + 1] = hex_chars[b & 0x0f];
        }

        const body = fmt.allocPrint(self.allocator, "{{\"pubkey\":\"{s}\",\"ip\":\"{s}\"}}", .{
            &hex_buf, ip_str,
        }) catch return httpResponse(self.allocator, 500, "Internal Server Error", "{\"error\":\"alloc\"}");
        defer self.allocator.free(body);
        return httpResponse(self.allocator, 200, "OK", body);
    }

    fn handleConfigReload(self: *Server) []const u8 {
        if (self.config.config_mgr_vtable.reload(self.config.config_mgr_ptr)) {
            return httpResponse(self.allocator, 200, "OK", "{\"status\":\"reloaded\"}");
        }
        return httpResponse(self.allocator, 200, "OK", "{\"status\":\"no changes\"}");
    }

    // ========================================================================
    // Config file mutation helpers
    // ========================================================================

    /// Read-modify-write the config JSON using std.json.
    /// These use std.json.parseFromSlice for dynamic manipulation.

    fn appendToConfigArray(self: *Server, section: []const u8, key: []const u8, value_json: []const u8) bool {
        const data = readConfigFile(self.allocator, self.config.config_path) orelse return false;
        defer self.allocator.free(data);

        var parsed = std.json.parseFromSlice(std.json.Value, self.allocator, data, .{}) catch return false;
        defer parsed.deinit();

        if (parsed.value.object.getPtr(section)) |obj| {
            if (obj.* == .object) {
                // Parse value_json
                var val = std.json.parseFromSlice(std.json.Value, self.allocator, value_json, .{}) catch return false;
                // Put key -> val into the section object
                obj.object.put(self.allocator.dupe(u8, key) catch return false, val.value) catch return false;
                _ = val; // ownership transferred
            }
        } else {
            // Create the section
            var new_obj = std.json.Value{ .object = std.json.ObjectMap.init(self.allocator) };
            var val = std.json.parseFromSlice(std.json.Value, self.allocator, value_json, .{}) catch return false;
            new_obj.object.put(self.allocator.dupe(u8, key) catch return false, val.value) catch return false;
            _ = val;
            parsed.value.object.put(self.allocator.dupe(u8, section) catch return false, new_obj) catch return false;
        }

        return writeJsonValue(self.allocator, self.config.config_path, parsed.value);
    }

    fn appendToConfigArraySimple(self: *Server, section: []const u8, value_json: []const u8) bool {
        const data = readConfigFile(self.allocator, self.config.config_path) orelse return false;
        defer self.allocator.free(data);

        var parsed = std.json.parseFromSlice(std.json.Value, self.allocator, data, .{}) catch return false;
        defer parsed.deinit();

        var val = std.json.parseFromSlice(std.json.Value, self.allocator, value_json, .{}) catch return false;

        if (parsed.value.object.getPtr(section)) |arr| {
            if (arr.* == .array) {
                arr.array.append(self.allocator, val.value) catch return false;
            }
        } else {
            var new_arr = std.json.Value{ .array = std.json.Array.init(self.allocator) };
            new_arr.array.append(self.allocator, val.value) catch return false;
            parsed.value.object.put(self.allocator.dupe(u8, section) catch return false, new_arr) catch return false;
        }
        _ = val;

        return writeJsonValue(self.allocator, self.config.config_path, parsed.value);
    }

    fn removeFromConfigObject(self: *Server, section: []const u8, key: []const u8) bool {
        const data = readConfigFile(self.allocator, self.config.config_path) orelse return false;
        defer self.allocator.free(data);

        var parsed = std.json.parseFromSlice(std.json.Value, self.allocator, data, .{}) catch return false;
        defer parsed.deinit();

        if (parsed.value.object.getPtr(section)) |obj| {
            if (obj.* == .object) {
                // Build domain key from hex pubkey
                const domain = fmt.allocPrint(self.allocator, "{s}.zigor.net", .{key}) catch return false;
                defer self.allocator.free(domain);
                _ = obj.object.orderedRemove(domain);
            }
        }

        return writeJsonValue(self.allocator, self.config.config_path, parsed.value);
    }

    fn removeFromConfigArrayByField(self: *Server, section: []const u8, field: []const u8, value: []const u8) bool {
        const data = readConfigFile(self.allocator, self.config.config_path) orelse return false;
        defer self.allocator.free(data);

        var parsed = std.json.parseFromSlice(std.json.Value, self.allocator, data, .{}) catch return false;
        defer parsed.deinit();

        if (parsed.value.object.getPtr(section)) |arr| {
            if (arr.* == .array) {
                var i: usize = 0;
                while (i < arr.array.items.len) {
                    if (arr.array.items[i] == .object) {
                        if (arr.array.items[i].object.get(field)) |v| {
                            if (v == .string and mem.eql(u8, v.string, value)) {
                                _ = arr.array.orderedRemove(i);
                                continue;
                            }
                        }
                    }
                    i += 1;
                }
            }
        }

        return writeJsonValue(self.allocator, self.config.config_path, parsed.value);
    }

    fn appendToNestedArray(self: *Server, section: []const u8, array_field: []const u8, value_json: []const u8) bool {
        const data = readConfigFile(self.allocator, self.config.config_path) orelse return false;
        defer self.allocator.free(data);

        var parsed = std.json.parseFromSlice(std.json.Value, self.allocator, data, .{}) catch return false;
        defer parsed.deinit();

        var val = std.json.parseFromSlice(std.json.Value, self.allocator, value_json, .{}) catch return false;

        if (parsed.value.object.getPtr(section)) |obj| {
            if (obj.* == .object) {
                if (obj.object.getPtr(array_field)) |arr| {
                    if (arr.* == .array) {
                        arr.array.append(self.allocator, val.value) catch return false;
                    }
                }
            }
        }
        _ = val;

        return writeJsonValue(self.allocator, self.config.config_path, parsed.value);
    }

    fn removeFromNestedArrayByField(self: *Server, section: []const u8, array_field: []const u8, field: []const u8, value: []const u8) bool {
        const data = readConfigFile(self.allocator, self.config.config_path) orelse return false;
        defer self.allocator.free(data);

        var parsed = std.json.parseFromSlice(std.json.Value, self.allocator, data, .{}) catch return false;
        defer parsed.deinit();

        if (parsed.value.object.getPtr(section)) |obj| {
            if (obj.* == .object) {
                if (obj.object.getPtr(array_field)) |arr| {
                    if (arr.* == .array) {
                        var i: usize = 0;
                        while (i < arr.array.items.len) {
                            if (arr.array.items[i] == .object) {
                                if (arr.array.items[i].object.get(field)) |v| {
                                    if (v == .string and mem.eql(u8, v.string, value)) {
                                        _ = arr.array.orderedRemove(i);
                                        continue;
                                    }
                                }
                            }
                            i += 1;
                        }
                    }
                }
            }
        }

        return writeJsonValue(self.allocator, self.config.config_path, parsed.value);
    }

    fn removeFromNestedArrayByIndex(self: *Server, section: []const u8, array_field: []const u8, index: usize) bool {
        const data = readConfigFile(self.allocator, self.config.config_path) orelse return false;
        defer self.allocator.free(data);

        var parsed = std.json.parseFromSlice(std.json.Value, self.allocator, data, .{}) catch return false;
        defer parsed.deinit();

        if (parsed.value.object.getPtr(section)) |obj| {
            if (obj.* == .object) {
                if (obj.object.getPtr(array_field)) |arr| {
                    if (arr.* == .array and index < arr.array.items.len) {
                        _ = arr.array.orderedRemove(index);
                    }
                }
            }
        }

        return writeJsonValue(self.allocator, self.config.config_path, parsed.value);
    }
};

// ============================================================================
// HTTP helpers
// ============================================================================

fn httpResponse(allocator: Allocator, status: u16, status_text: []const u8, body: []const u8) []const u8 {
    return fmt.allocPrint(allocator,
        "HTTP/1.1 {d} {s}\r\nContent-Type: application/json\r\nContent-Length: {d}\r\nConnection: close\r\n\r\n{s}", .{
        status, status_text, body.len, body,
    }) catch "";
}

fn writeAll(fd: posix.socket_t, data: []const u8) !void {
    var written: usize = 0;
    while (written < data.len) {
        const n = posix.write(fd, data[written..]) catch |e| return e;
        written += n;
    }
}

fn eql(a: []const u8, b: []const u8) bool {
    return mem.eql(u8, a, b);
}

fn readConfigFile(allocator: Allocator, path: []const u8) ?[]const u8 {
    return std.fs.cwd().readFileAlloc(allocator, path, 10 * 1024 * 1024) catch null;
}

fn writeJsonValue(allocator: Allocator, path: []const u8, value: std.json.Value) bool {
    var buf = std.ArrayList(u8).init(allocator);
    defer buf.deinit();
    std.json.stringify(value, .{ .whitespace = .indent_2 }, buf.writer()) catch return false;
    buf.append('\n') catch return false;
    std.fs.cwd().writeFile(.{ .sub_path = path, .data = buf.items }) catch return false;
    return true;
}

fn extractJsonSection(allocator: Allocator, data: []const u8, key: []const u8) ?[]const u8 {
    var parsed = std.json.parseFromSlice(std.json.Value, allocator, data, .{}) catch return null;
    defer parsed.deinit();

    const val = parsed.value.object.get(key) orelse return null;

    var buf = std.ArrayList(u8).init(allocator);
    std.json.stringify(val, .{ .whitespace = .indent_2 }, buf.writer()) catch return null;
    return buf.toOwnedSlice() catch null;
}

fn extractJsonString(data: []const u8, key: []const u8) ?[]const u8 {
    // Simple extraction: find "key":"value" pattern
    const search = fmt.comptimePrint("\"{s}\":\"", .{key});
    _ = search;
    // Use a simple search approach
    var i: usize = 0;
    while (i + key.len + 4 < data.len) : (i += 1) {
        if (data[i] == '"' and i + 1 + key.len < data.len and
            mem.eql(u8, data[i + 1 .. i + 1 + key.len], key) and
            data[i + 1 + key.len] == '"')
        {
            // Found the key, now find the value
            var j = i + 1 + key.len + 1; // past closing quote
            while (j < data.len and (data[j] == ':' or data[j] == ' ')) : (j += 1) {}
            if (j < data.len and data[j] == '"') {
                j += 1; // past opening quote
                const start = j;
                while (j < data.len and data[j] != '"') : (j += 1) {}
                return data[start..j];
            }
        }
    }
    return null;
}

fn getQueryParam(query: []const u8, key: []const u8) ?[]const u8 {
    var iter = mem.splitScalar(u8, query, '&');
    while (iter.next()) |pair| {
        if (mem.indexOfScalar(u8, pair, '=')) |eq| {
            if (mem.eql(u8, pair[0..eq], key)) {
                return pair[eq + 1 ..];
            }
        }
    }
    return null;
}

fn parseIpv4Simple(s: []const u8, out: *[4]u8) ?void {
    var parts = mem.splitScalar(u8, s, '.');
    var i: usize = 0;
    while (parts.next()) |part| {
        if (i >= 4) return null;
        out[i] = fmt.parseInt(u8, part, 10) catch return null;
        i += 1;
    }
    if (i != 4) return null;
}
