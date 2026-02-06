//! Windows TUN implementation using Wintun driver.
//!
//! Wintun is a high-performance user-space TUN driver for Windows.
//! This implementation can embed wintun.dll and load it at runtime.
//!
//! To embed the DLL, compile with:
//!   zig build -Dwintun_dll=path/to/wintun.dll
//!
//! See: https://www.wintun.net/

const std = @import("std");
const mod = @import("mod.zig");
const Tun = mod.Tun;
const TunError = mod.TunError;

const windows = std.os.windows;
const HANDLE = windows.HANDLE;
const DWORD = windows.DWORD;
const BOOL = windows.BOOL;
const HMODULE = windows.HMODULE;
const GUID = windows.GUID;
const LPCWSTR = windows.LPCWSTR;

// Build options for Wintun DLL embedding
const tun_build_options = @import("tun_build_options");

// Wintun DLL data - embedded at compile time if -Dwintun_dll is provided
const wintun_dll_data: ?[]const u8 = if (tun_build_options.has_wintun_dll)
    @embedFile("wintun_dll")
else
    null;

// Wintun types
const WINTUN_ADAPTER_HANDLE = *opaque {};
const WINTUN_SESSION_HANDLE = *opaque {};

// Wintun function types
const WintunCreateAdapterFn = *const fn (LPCWSTR, LPCWSTR, *const GUID) callconv(.C) ?WINTUN_ADAPTER_HANDLE;
const WintunCloseAdapterFn = *const fn (WINTUN_ADAPTER_HANDLE) callconv(.C) void;
const WintunStartSessionFn = *const fn (WINTUN_ADAPTER_HANDLE, DWORD) callconv(.C) ?WINTUN_SESSION_HANDLE;
const WintunEndSessionFn = *const fn (WINTUN_SESSION_HANDLE) callconv(.C) void;
const WintunGetReadWaitEventFn = *const fn (WINTUN_SESSION_HANDLE) callconv(.C) HANDLE;
const WintunReceivePacketFn = *const fn (WINTUN_SESSION_HANDLE, *DWORD) callconv(.C) ?[*]u8;
const WintunReleaseReceivePacketFn = *const fn (WINTUN_SESSION_HANDLE, [*]const u8) callconv(.C) void;
const WintunAllocateSendPacketFn = *const fn (WINTUN_SESSION_HANDLE, DWORD) callconv(.C) ?[*]u8;
const WintunSendPacketFn = *const fn (WINTUN_SESSION_HANDLE, [*]const u8) callconv(.C) void;
const WintunGetAdapterLUIDFn = *const fn (WINTUN_ADAPTER_HANDLE, *u64) callconv(.C) void;

// Global state for Wintun - protected by mutex for thread safety
var global_mutex: std.Thread.Mutex = .{};
var wintun_module: ?HMODULE = null;
var wintun_dll_path: ?[]u8 = null;
var init_done: bool = false;

var WintunCreateAdapter: ?WintunCreateAdapterFn = null;
var WintunCloseAdapter: ?WintunCloseAdapterFn = null;
var WintunStartSession: ?WintunStartSessionFn = null;
var WintunEndSession: ?WintunEndSessionFn = null;
var WintunGetReadWaitEvent: ?WintunGetReadWaitEventFn = null;
var WintunReceivePacket: ?WintunReceivePacketFn = null;
var WintunReleaseReceivePacket: ?WintunReleaseReceivePacketFn = null;
var WintunAllocateSendPacket: ?WintunAllocateSendPacketFn = null;
var WintunSendPacket: ?WintunSendPacketFn = null;
var WintunGetAdapterLUID: ?WintunGetAdapterLUIDFn = null;

// Windows TUN state (stored in opaque handle)
const WinTunState = struct {
    adapter: WINTUN_ADAPTER_HANDLE,
    session: WINTUN_SESSION_HANDLE,
    read_event: HANDLE,
    luid: u64,
    mtu: u32,
    non_blocking: bool,
};

var tun_states: std.AutoHashMap(usize, *WinTunState) = undefined;
var states_initialized: bool = false;

fn initStates() void {
    if (!states_initialized) {
        tun_states = std.AutoHashMap(usize, *WinTunState).init(std.heap.page_allocator);
        states_initialized = true;
    }
}

/// Initialize Wintun (extract and load DLL)
/// Thread-safe - can be called from multiple threads.
pub fn init() TunError!void {
    global_mutex.lock();
    defer global_mutex.unlock();

    if (init_done) return; // Already initialized

    initStates();

    // Check if embedded DLL is available
    const dll_data = wintun_dll_data orelse {
        // Try to load from System32 (secure location) or application directory
        // Use absolute path to prevent DLL hijacking
        var sys_path_buf: [std.fs.max_path_bytes]u8 = undefined;
        const sys_dll_path = std.fmt.bufPrintZ(&sys_path_buf, "C:\\Windows\\System32\\wintun.dll", .{}) catch {
            return TunError.WintunInitFailed;
        };
        wintun_module = windows.kernel32.LoadLibraryA(sys_dll_path.ptr);
        if (wintun_module == null) {
            // Fallback: try application directory with absolute path
            var exe_path_buf: [std.fs.max_path_bytes]u8 = undefined;
            const exe_path = std.fs.selfExePath(&exe_path_buf) catch {
                return TunError.WintunNotFound;
            };
            const exe_dir = std.fs.path.dirname(exe_path) orelse {
                return TunError.WintunNotFound;
            };
            var app_dll_buf: [std.fs.max_path_bytes]u8 = undefined;
            const app_dll_path = std.fmt.bufPrintZ(&app_dll_buf, "{s}\\wintun.dll", .{exe_dir}) catch {
                return TunError.WintunNotFound;
            };
            wintun_module = windows.kernel32.LoadLibraryA(app_dll_path.ptr);
            if (wintun_module == null) {
                return TunError.WintunNotFound;
            }
        }
        loadFunctions() catch return TunError.WintunInitFailed;
        init_done = true;
        return;
    };

    // Get the executable's directory for secure DLL extraction
    var exe_path_buf2: [std.fs.max_path_bytes]u8 = undefined;
    const exe_path2 = std.fs.selfExePath(&exe_path_buf2) catch {
        return TunError.WintunInitFailed;
    };
    const exe_dir2 = std.fs.path.dirname(exe_path2) orelse ".";

    // Build null-terminated path for LoadLibraryA
    var dll_path_buf: [std.fs.max_path_bytes:0]u8 = undefined;
    const dll_path_z = std.fmt.bufPrintZ(&dll_path_buf, "{s}\\wintun.dll", .{exe_dir2}) catch {
        return TunError.WintunInitFailed;
    };

    // Store path for cleanup (allocate with null terminator)
    const dll_path_alloc = std.heap.page_allocator.alloc(u8, dll_path_z.len + 1) catch {
        return TunError.WintunInitFailed;
    };
    @memcpy(dll_path_alloc[0..dll_path_z.len], dll_path_z);
    dll_path_alloc[dll_path_z.len] = 0;
    wintun_dll_path = dll_path_alloc;

    // Write DLL to file
    const file = std.fs.createFileAbsolute(dll_path_z, .{}) catch {
        return TunError.WintunInitFailed;
    };
    defer file.close();

    file.writeAll(dll_data) catch {
        return TunError.WintunInitFailed;
    };

    // Load the DLL from the extracted path (null-terminated)
    wintun_module = windows.kernel32.LoadLibraryA(dll_path_z.ptr);
    if (wintun_module == null) {
        return TunError.WintunNotFound;
    }

    loadFunctions() catch return TunError.WintunInitFailed;
    init_done = true;
}

fn loadFunctions() !void {
    const module = wintun_module orelse return error.NotLoaded;

    WintunCreateAdapter = @ptrCast(windows.kernel32.GetProcAddress(module, "WintunCreateAdapter"));
    WintunCloseAdapter = @ptrCast(windows.kernel32.GetProcAddress(module, "WintunCloseAdapter"));
    WintunStartSession = @ptrCast(windows.kernel32.GetProcAddress(module, "WintunStartSession"));
    WintunEndSession = @ptrCast(windows.kernel32.GetProcAddress(module, "WintunEndSession"));
    WintunGetReadWaitEvent = @ptrCast(windows.kernel32.GetProcAddress(module, "WintunGetReadWaitEvent"));
    WintunReceivePacket = @ptrCast(windows.kernel32.GetProcAddress(module, "WintunReceivePacket"));
    WintunReleaseReceivePacket = @ptrCast(windows.kernel32.GetProcAddress(module, "WintunReleaseReceivePacket"));
    WintunAllocateSendPacket = @ptrCast(windows.kernel32.GetProcAddress(module, "WintunAllocateSendPacket"));
    WintunSendPacket = @ptrCast(windows.kernel32.GetProcAddress(module, "WintunSendPacket"));
    WintunGetAdapterLUID = @ptrCast(windows.kernel32.GetProcAddress(module, "WintunGetAdapterLUID"));

    if (WintunCreateAdapter == null or
        WintunCloseAdapter == null or
        WintunStartSession == null or
        WintunEndSession == null or
        WintunReceivePacket == null or
        WintunSendPacket == null)
    {
        return error.FunctionNotFound;
    }
}

/// Cleanup Wintun
/// Thread-safe - should be called once when the application exits.
pub fn deinit() void {
    global_mutex.lock();
    defer global_mutex.unlock();

    if (wintun_module) |module| {
        _ = windows.kernel32.FreeLibrary(module);
        wintun_module = null;
    }

    // Delete extracted DLL file
    if (wintun_dll_path) |path| {
        std.fs.deleteFileAbsolute(path) catch {};
        std.heap.page_allocator.free(path);
        wintun_dll_path = null;
    }

    // Cleanup states
    if (states_initialized) {
        var it = tun_states.iterator();
        while (it.next()) |entry| {
            std.heap.page_allocator.destroy(entry.value_ptr.*);
        }
        tun_states.deinit();
        states_initialized = false;
    }
}

/// Create a new TUN device
pub fn create(name: ?[]const u8) TunError!Tun {
    if (wintun_module == null) {
        try init();
    }

    const createAdapter = WintunCreateAdapter orelse return TunError.WintunInitFailed;
    const startSession = WintunStartSession orelse return TunError.WintunInitFailed;
    const getReadEvent = WintunGetReadWaitEvent orelse return TunError.WintunInitFailed;
    const getAdapterLUID = WintunGetAdapterLUID orelse return TunError.WintunInitFailed;

    // Generate a random GUID for the adapter
    var guid: GUID = undefined;
    std.crypto.random.bytes(std.mem.asBytes(&guid));

    // Convert name to wide string - buffer must be in function scope to avoid dangling pointer
    var name_buf: [16]u8 = undefined;
    var name_len: u8 = 0;
    var wide_buf: [16]u16 = undefined; // Keep in function scope for lifetime

    const adapter_name: LPCWSTR = if (name) |n| blk: {
        const truncated_len = @min(n.len, 15);
        @memcpy(name_buf[0..truncated_len], n[0..truncated_len]);
        name_len = @intCast(truncated_len);
        name_buf[name_len] = 0;
        // Convert UTF-8 to UTF-16LE (handles full Unicode)
        const wide_len = std.unicode.utf8ToUtf16Le(&wide_buf, n[0..truncated_len]) catch {
            return TunError.InvalidArgument;
        };
        wide_buf[wide_len] = 0;
        break :blk @ptrCast(&wide_buf);
    } else blk: {
        const default_name = "ZigNet";
        @memcpy(name_buf[0..default_name.len], default_name);
        name_len = default_name.len;
        name_buf[name_len] = 0;
        break :blk std.unicode.utf8ToUtf16LeStringLiteral("ZigNet").ptr;
    };

    // Create adapter
    const adapter = createAdapter(adapter_name, std.unicode.utf8ToUtf16LeStringLiteral("ZigNet").ptr, &guid) orelse {
        return TunError.CreateFailed;
    };
    errdefer WintunCloseAdapter.?(adapter);

    // Start session with 4MB ring buffer
    const session = startSession(adapter, 0x400000) orelse {
        return TunError.CreateFailed;
    };
    errdefer WintunEndSession.?(session);

    // Get read event handle
    const read_event = getReadEvent(session);

    // Get adapter LUID
    var luid: u64 = 0;
    getAdapterLUID(adapter, &luid);

    // Allocate and store state
    const state = std.heap.page_allocator.create(WinTunState) catch {
        return TunError.SystemResources;
    };
    state.* = .{
        .adapter = adapter,
        .session = session,
        .read_event = read_event,
        .luid = luid,
        .mtu = 1400,
        .non_blocking = false,
    };

    // Use state pointer as handle
    const handle: HANDLE = @ptrCast(state);

    // Thread-safe access to tun_states
    global_mutex.lock();
    defer global_mutex.unlock();
    tun_states.put(@intFromPtr(state), state) catch {
        std.heap.page_allocator.destroy(state);
        return TunError.SystemResources;
    };

    return Tun{
        .handle = handle,
        .name_buf = name_buf,
        .name_len = name_len,
        .closed = false,
    };
}

fn getState(tun: *Tun) ?*WinTunState {
    const handle: *WinTunState = @ptrCast(@alignCast(tun.handle));
    global_mutex.lock();
    defer global_mutex.unlock();
    return tun_states.get(@intFromPtr(handle));
}

/// Read a packet from the TUN device
pub fn read(tun: *Tun, buf: []u8) TunError!usize {
    const state = getState(tun) orelse return TunError.AlreadyClosed;
    const receivePacket = WintunReceivePacket orelse return TunError.WintunInitFailed;
    const releasePacket = WintunReleaseReceivePacket orelse return TunError.WintunInitFailed;

    // Wait for packet if blocking mode
    if (!state.non_blocking) {
        _ = windows.kernel32.WaitForSingleObject(state.read_event, windows.INFINITE);
    }

    var packet_size: DWORD = 0;
    const packet = receivePacket(state.session, &packet_size) orelse {
        if (state.non_blocking) {
            return TunError.WouldBlock;
        }
        return TunError.IoError;
    };
    defer releasePacket(state.session, packet);

    const copy_size = @min(packet_size, buf.len);
    @memcpy(buf[0..copy_size], packet[0..copy_size]);

    return copy_size;
}

/// Write a packet to the TUN device
pub fn write(tun: *Tun, data: []const u8) TunError!usize {
    const state = getState(tun) orelse return TunError.AlreadyClosed;
    const allocateSendPacket = WintunAllocateSendPacket orelse return TunError.WintunInitFailed;
    const sendPacket = WintunSendPacket orelse return TunError.WintunInitFailed;

    if (data.len == 0) {
        return TunError.InvalidArgument;
    }

    const packet = allocateSendPacket(state.session, @intCast(data.len)) orelse {
        return TunError.SystemResources;
    };

    @memcpy(packet[0..data.len], data);
    sendPacket(state.session, packet);

    return data.len;
}

/// Close the TUN device
pub fn close(tun: *Tun) void {
    const state = getState(tun) orelse return;
    const endSession = WintunEndSession orelse return;
    const closeAdapter = WintunCloseAdapter orelse return;

    endSession(state.session);
    closeAdapter(state.adapter);

    // Thread-safe removal from tun_states
    global_mutex.lock();
    defer global_mutex.unlock();
    _ = tun_states.remove(@intFromPtr(state));
    std.heap.page_allocator.destroy(state);
}

/// Get MTU
pub fn getMtu(tun: *Tun) TunError!u32 {
    const state = getState(tun) orelse return TunError.AlreadyClosed;
    return state.mtu;
}

/// Set MTU
pub fn setMtu(tun: *Tun, mtu: u32) TunError!void {
    const state = getState(tun) orelse return TunError.AlreadyClosed;
    state.mtu = mtu;
    // Note: Wintun doesn't have a direct MTU setting API
    // The MTU is effectively determined by the ring buffer size
}

/// Set non-blocking mode
pub fn setNonBlocking(tun: *Tun, enabled: bool) TunError!void {
    const state = getState(tun) orelse return TunError.AlreadyClosed;
    state.non_blocking = enabled;
}

/// Bring interface up
pub fn setUp(tun: *Tun) TunError!void {
    _ = tun;
    // Wintun adapter is always "up" when session is active
}

/// Bring interface down
pub fn setDown(tun: *Tun) TunError!void {
    _ = tun;
    // Not directly supported - would need to end/restart session
}

/// Set IPv4 address and netmask
pub fn setIPv4(tun: *Tun, addr: [4]u8, netmask: [4]u8) TunError!void {
    const state = getState(tun) orelse return TunError.AlreadyClosed;

    // Use netsh to set IP address
    var addr_str: [16]u8 = undefined;
    const addr_len = std.fmt.bufPrint(&addr_str, "{d}.{d}.{d}.{d}", .{ addr[0], addr[1], addr[2], addr[3] }) catch {
        return TunError.InvalidArgument;
    };

    var mask_str: [16]u8 = undefined;
    const mask_len = std.fmt.bufPrint(&mask_str, "{d}.{d}.{d}.{d}", .{ netmask[0], netmask[1], netmask[2], netmask[3] }) catch {
        return TunError.InvalidArgument;
    };

    // Get interface index from LUID
    _ = state.luid;

    // Use explicit empty environment to avoid FFI issues with env inheritance
    var env_map = std.process.EnvMap.init(std.heap.page_allocator);
    defer env_map.deinit();

    // Use absolute path to prevent PATH hijacking
    const result = std.process.Child.run(.{
        .allocator = std.heap.page_allocator,
        .argv = &.{
            "C:\\Windows\\System32\\netsh.exe",
            "interface",
            "ip",
            "set",
            "address",
            tun.name_buf[0..tun.name_len],
            "static",
            addr_str[0..addr_len],
            mask_str[0..mask_len],
        },
        .env_map = &env_map,
    }) catch {
        return TunError.SetAddressFailed;
    };
    defer {
        std.heap.page_allocator.free(result.stdout);
        std.heap.page_allocator.free(result.stderr);
    }

    if (result.term.Exited != 0) {
        return TunError.SetAddressFailed;
    }
}

/// Set IPv6 address with prefix length
pub fn setIPv6(tun: *Tun, addr: [16]u8, prefix_len: u8) TunError!void {
    _ = getState(tun) orelse return TunError.AlreadyClosed;

    // Format IPv6 as standard notation: xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx
    var addr_str: [64]u8 = undefined;
    const addr_len = std.fmt.bufPrint(&addr_str, "{x:0>4}:{x:0>4}:{x:0>4}:{x:0>4}:{x:0>4}:{x:0>4}:{x:0>4}:{x:0>4}", .{
        @as(u16, addr[0]) << 8 | addr[1],
        @as(u16, addr[2]) << 8 | addr[3],
        @as(u16, addr[4]) << 8 | addr[5],
        @as(u16, addr[6]) << 8 | addr[7],
        @as(u16, addr[8]) << 8 | addr[9],
        @as(u16, addr[10]) << 8 | addr[11],
        @as(u16, addr[12]) << 8 | addr[13],
        @as(u16, addr[14]) << 8 | addr[15],
    }) catch {
        return TunError.InvalidArgument;
    };

    var prefix_str: [4]u8 = undefined;
    const prefix_len_str = std.fmt.bufPrint(&prefix_str, "{d}", .{prefix_len}) catch {
        return TunError.InvalidArgument;
    };

    // Use explicit empty environment to avoid FFI issues with env inheritance
    var env_map = std.process.EnvMap.init(std.heap.page_allocator);
    defer env_map.deinit();

    // Use absolute path to prevent PATH hijacking
    const result = std.process.Child.run(.{
        .allocator = std.heap.page_allocator,
        .argv = &.{
            "C:\\Windows\\System32\\netsh.exe",
            "interface",
            "ipv6",
            "add",
            "address",
            tun.name_buf[0..tun.name_len],
            addr_str[0..addr_len],
            prefix_len_str,
        },
        .env_map = &env_map,
    }) catch {
        return TunError.SetAddressFailed;
    };
    defer {
        std.heap.page_allocator.free(result.stdout);
        std.heap.page_allocator.free(result.stderr);
    }

    if (result.term.Exited != 0) {
        return TunError.SetAddressFailed;
    }
}
