// build.zig — For local development only (zig build / zig build test).
//
// Bazel builds use BUILD.bazel with embed-zig's Bazel-native rules
// (@embed_zig//bazel/zig:defs.bzl) and do NOT depend on this file.
// Build options are provided by build_options.zig and tun_build_options.zig
// as separate zig_library modules.

const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // KCP dependency - support both Bazel (external path) and native zig build (build.zig.zon)
    // Uses lazyDependency to avoid network fetch when external path is provided
    const kcp_path: std.Build.LazyPath = blk: {
        if (b.option([]const u8, "kcp_path", "External KCP path (from Bazel)")) |external_path| {
            // Bazel provides KCP via -Dkcp_path (absolute path)
            break :blk .{ .cwd_relative = external_path };
        } else if (b.lazyDependency("kcp", .{})) |kcp_dep| {
            // Native zig build uses build.zig.zon dependency (lazy - only fetches if needed)
            break :blk kcp_dep.path("");
        } else {
            // Dependency not available yet (being fetched)
            @panic("KCP dependency not available. Run 'zig build' again after fetch completes, or provide -Dkcp_path");
        }
    };

    const target_arch = target.result.cpu.arch;
    const target_os = target.result.os.tag;

    // Backend auto-selection based on architecture:
    // - ARM64: BoringSSL ASM (~13 Gbps)
    // - x86_64 Linux: AVX2/SSE4.1 ASM (~12 Gbps)
    // - Other: Pure Zig (~6 Gbps)
    const BackendEnum = enum { arm64_asm, x86_64_asm, simd, pure_zig };

    const default_backend: BackendEnum = if (target_arch == .aarch64)
        .arm64_asm
    else if (target_arch == .x86_64 and target_os == .linux)
        .x86_64_asm
    else
        .pure_zig;

    const backend_opt = b.option(BackendEnum, "backend", "Crypto backend: arm64_asm, x86_64_asm, simd, pure_zig") orelse default_backend;

    // Validate backend selection
    const effective_backend = blk: {
        if (backend_opt == .arm64_asm and target_arch != .aarch64) {
            std.log.warn("ARM64 ASM only available on aarch64, falling back", .{});
            break :blk if (target_arch == .x86_64 and target_os == .linux) BackendEnum.x86_64_asm else BackendEnum.pure_zig;
        }
        if (backend_opt == .x86_64_asm and (target_arch != .x86_64 or target_os != .linux)) {
            std.log.warn("x86_64 ASM only available on Linux x86_64, falling back", .{});
            break :blk BackendEnum.pure_zig;
        }
        break :blk backend_opt;
    };

    // Map to cipher.zig Backend enum
    const CipherBackend = enum { aarch64_asm, x86_64_asm, simd_zig, native_zig };
    const cipher_backend: CipherBackend = switch (effective_backend) {
        .arm64_asm => .aarch64_asm,
        .x86_64_asm => .x86_64_asm,
        .simd => .simd_zig,
        .pure_zig => .native_zig,
    };

    // Build options
    const options = b.addOptions();
    options.addOption(CipherBackend, "backend", cipher_backend);

    // Helper to add ARM64 ASM files
    const addArm64AsmFiles = struct {
        fn add(compile: *std.Build.Step.Compile, builder: *std.Build) void {
            compile.addAssemblyFile(builder.path("src/noise/chacha20_poly1305/aarch64/chacha20_poly1305_no_cfi.S"));
            compile.addCSourceFile(.{
                .file = builder.path("src/noise/chacha20_poly1305/aarch64/chacha20_poly1305_wrapper.c"),
                .flags = &.{ "-O3", "-I", "src/noise/chacha20_poly1305/aarch64" },
            });
        }
    }.add;

    // Helper to add x86_64 ASM files
    const addX86AsmFiles = struct {
        fn add(compile: *std.Build.Step.Compile, builder: *std.Build) void {
            compile.linkLibC();
            compile.addAssemblyFile(builder.path("src/noise/chacha20_poly1305/x86_64/chacha20_poly1305_x86_64.S"));
            compile.addCSourceFile(.{
                .file = builder.path("src/noise/chacha20_poly1305/x86_64/chacha20_poly1305_wrapper.c"),
                .flags = &.{ "-O3", "-mavx2", "-mbmi2" },
            });
        }
    }.add;

    // Helper to add KCP C files
    // Note: KCP uses offsetof-style macro with null pointer dereference ((TYPE*)0)->member
    // which triggers zig cc's undefined behavior sanitizer. We disable it with -fno-sanitize=undefined.
    const addKcpFiles = struct {
        fn add(compile: *std.Build.Step.Compile, kcp: std.Build.LazyPath) void {
            compile.linkLibC();
            compile.addCSourceFile(.{
                .file = kcp.path(compile.step.owner, "ikcp.c"),
                .flags = &.{ "-O3", "-DNDEBUG", "-fno-sanitize=undefined" },
            });
            compile.addIncludePath(kcp);
        }
    }.add;

    // Helper to add minicoro C files (optional, for coroutine support)
    const addMinicoroFiles = struct {
        fn add(compile: *std.Build.Step.Compile, builder: *std.Build) void {
            compile.linkLibC();
            compile.addCSourceFile(.{
                .file = builder.path("src/async/minicoro/wrapper.c"),
                .flags = &.{"-O3"},
            });
            compile.addIncludePath(builder.path("src/async/minicoro"));
        }
    }.add;

    // Minicoro option (disabled by default)
    const enable_minicoro = b.option(bool, "minicoro", "Enable minicoro coroutine support") orelse false;
    options.addOption(bool, "enable_minicoro", enable_minicoro);

    // Library module
    const lib_module = b.createModule(.{
        .root_source_file = b.path("src/noise.zig"),
        .target = target,
        .optimize = optimize,
    });
    lib_module.addOptions("build_options", options);

    // Library
    const lib = b.addLibrary(.{
        .name = "noise",
        .root_module = lib_module,
    });
    if (effective_backend == .arm64_asm) addArm64AsmFiles(lib, b);
    if (effective_backend == .x86_64_asm) addX86AsmFiles(lib, b);
    addKcpFiles(lib, kcp_path);
    if (enable_minicoro) addMinicoroFiles(lib, b);
    b.installArtifact(lib);

    // Export module for dependents (e.g., examples/kcp_test/zig)
    // This allows other packages to do: dep.module("noise")
    _ = b.addModule("noise", .{
        .root_source_file = b.path("src/noise.zig"),
        .imports = &.{
            .{ .name = "build_options", .module = options.createModule() },
        },
    });

    // Test module
    const test_module = b.createModule(.{
        .root_source_file = b.path("src/noise.zig"),
        .target = target,
        .optimize = optimize,
    });
    test_module.addOptions("build_options", options);

    // Tests
    const main_tests = b.addTest(.{
        .root_module = test_module,
    });
    if (effective_backend == .arm64_asm) addArm64AsmFiles(main_tests, b);
    if (effective_backend == .x86_64_asm) addX86AsmFiles(main_tests, b);
    addKcpFiles(main_tests, kcp_path);
    if (enable_minicoro) addMinicoroFiles(main_tests, b);

    const run_main_tests = b.addRunArtifact(main_tests);
    const test_step = b.step("test", "Run library tests");
    test_step.dependOn(&run_main_tests.step);

    // Bench module
    const bench_module = b.createModule(.{
        .root_source_file = b.path("src/bench.zig"),
        .target = target,
        .optimize = .ReleaseFast,
    });
    bench_module.addOptions("build_options", options);

    // Benchmarks
    const bench_exe = b.addExecutable(.{
        .name = "bench",
        .root_module = bench_module,
    });
    if (effective_backend == .arm64_asm) addArm64AsmFiles(bench_exe, b);
    if (effective_backend == .x86_64_asm) addX86AsmFiles(bench_exe, b);
    addKcpFiles(bench_exe, kcp_path);
    b.installArtifact(bench_exe);

    const run_bench = b.addRunArtifact(bench_exe);
    const bench_step = b.step("bench", "Run benchmarks");
    bench_step.dependOn(&run_bench.step);

    // Async module for benchmarks
    const async_module = b.createModule(.{
        .root_source_file = b.path("src/async/mod.zig"),
        .target = target,
        .optimize = .ReleaseFast,
    });
    async_module.addOptions("build_options", options);

    // Async runtime benchmarks
    const async_bench_module = b.createModule(.{
        .root_source_file = b.path("src/async/benchmark/zig/main.zig"),
        .target = target,
        .optimize = .ReleaseFast,
    });
    async_bench_module.addOptions("build_options", options);
    async_bench_module.addImport("async", async_module);

    const async_bench_exe = b.addExecutable(.{
        .name = "async_bench",
        .root_module = async_bench_module,
    });
    if (enable_minicoro) addMinicoroFiles(async_bench_exe, b);
    b.installArtifact(async_bench_exe);

    const run_async_bench = b.addRunArtifact(async_bench_exe);
    const async_bench_step = b.step("async_bench", "Run async runtime benchmarks");
    async_bench_step.dependOn(&run_async_bench.step);

    // UDP examples require kqueue backend (macOS/BSD only).
    // On other platforms these are skipped since no IO backend is available yet.
    const os_tag = target.result.os.tag;
    const has_kqueue = (os_tag == .macos or os_tag == .freebsd or
        os_tag == .netbsd or os_tag == .openbsd);

    if (has_kqueue) {
        // TUN module for host_test (native Zig, not C ABI)
        const tun_module_for_host = b.createModule(.{
            .root_source_file = b.path("src/tun/mod.zig"),
            .target = target,
            .optimize = optimize,
        });

        // Host test example (real TUN integration test)
        const host_test_module = b.createModule(.{
            .root_source_file = b.path("examples/host_test.zig"),
            .target = target,
            .optimize = optimize,
        });
        host_test_module.addOptions("build_options", options);
        host_test_module.addImport("noise", lib_module);
        host_test_module.addImport("tun", tun_module_for_host);

        const host_test_exe = b.addExecutable(.{
            .name = "host_test",
            .root_module = host_test_module,
        });
        host_test_exe.linkLibrary(lib);
        host_test_exe.linkLibC(); // for getuid()
        b.installArtifact(host_test_exe);

        const run_host_test = b.addRunArtifact(host_test_exe);
        if (b.args) |args| {
            run_host_test.addArgs(args);
        }
        const host_test_step = b.step("host_test", "Run host test example");
        host_test_step.dependOn(&run_host_test.step);

        // Throughput test example
        const throughput_test_module = b.createModule(.{
            .root_source_file = b.path("../examples/throughput/zig/main.zig"),
            .target = target,
            .optimize = optimize,
        });
        throughput_test_module.addOptions("build_options", options);
        throughput_test_module.addImport("noise", lib_module);

        const throughput_test_exe = b.addExecutable(.{
            .name = "throughput_test",
            .root_module = throughput_test_module,
        });
        throughput_test_exe.linkLibrary(lib);
        b.installArtifact(throughput_test_exe);

        const run_throughput_test = b.addRunArtifact(throughput_test_exe);
        if (b.args) |args| {
            run_throughput_test.addArgs(args);
        }
        const throughput_test_step = b.step("throughput", "Run throughput test");
        throughput_test_step.dependOn(&run_throughput_test.step);

        // KCP Stream test (source in examples/stream_test/zig/)
        const kcp_stream_test_module = b.createModule(.{
            .root_source_file = b.path("../examples/stream_test/zig/src/main.zig"),
            .target = target,
            .optimize = optimize,
        });
        kcp_stream_test_module.addOptions("build_options", options);
        kcp_stream_test_module.addImport("noise", lib_module);

        const kcp_stream_test_exe = b.addExecutable(.{
            .name = "stream_test",
            .root_module = kcp_stream_test_module,
        });
        kcp_stream_test_exe.linkLibrary(lib);
        b.installArtifact(kcp_stream_test_exe);

        const run_kcp_stream_test = b.addRunArtifact(kcp_stream_test_exe);
        if (b.args) |args| {
            run_kcp_stream_test.addArgs(args);
        }
        const kcp_stream_test_step = b.step("stream_test", "Run KCP stream throughput test");
        kcp_stream_test_step.dependOn(&run_kcp_stream_test.step);

        // KCP Interop test (source in examples/kcp_test/zig/)
        const kcp_interop_module = b.createModule(.{
            .root_source_file = b.path("../examples/kcp_test/zig/src/main.zig"),
            .target = target,
            .optimize = optimize,
        });
        kcp_interop_module.addOptions("build_options", options);
        kcp_interop_module.addImport("noise", lib_module);

        const kcp_interop_exe = b.addExecutable(.{
            .name = "kcp_test",
            .root_module = kcp_interop_module,
        });
        kcp_interop_exe.linkLibrary(lib);
        b.installArtifact(kcp_interop_exe);

        const run_kcp_interop = b.addRunArtifact(kcp_interop_exe);
        if (b.args) |args| {
            run_kcp_interop.addArgs(args);
        }
        const kcp_interop_step = b.step("kcp_test", "Run KCP interop test");
        kcp_interop_step.dependOn(&run_kcp_interop.step);

        // Proxy Interop test (source in examples/proxy_test/zig/)
        const proxy_test_module = b.createModule(.{
            .root_source_file = b.path("../examples/proxy_test/zig/src/main.zig"),
            .target = target,
            .optimize = optimize,
        });
        proxy_test_module.addOptions("build_options", options);
        proxy_test_module.addImport("noise", lib_module);

        const proxy_test_exe = b.addExecutable(.{
            .name = "proxy_test",
            .root_module = proxy_test_module,
        });
        proxy_test_exe.linkLibrary(lib);
        b.installArtifact(proxy_test_exe);

        const run_proxy_test = b.addRunArtifact(proxy_test_exe);
        if (b.args) |args| {
            run_proxy_test.addArgs(args);
        }
        const proxy_test_step = b.step("proxy_test", "Run proxy interop test");
        proxy_test_step.dependOn(&run_proxy_test.step);
    }

    // ========================================================================
    // TUN Module
    // ========================================================================

    // Wintun DLL path option (for Windows builds)
    // Usage: zig build -Dwintun_dll=path/to/wintun.dll
    const wintun_dll_path = b.option([]const u8, "wintun_dll", "Path to wintun.dll for embedding (Windows only)");

    // TUN build options
    const tun_options = b.addOptions();
    tun_options.addOption(bool, "has_wintun_dll", wintun_dll_path != null);

    // TUN library module (cross-platform TUN device abstraction)
    const tun_lib_module = b.createModule(.{
        .root_source_file = b.path("src/tun/cabi.zig"),
        .target = target,
        .optimize = optimize,
        .pic = true, // Required for linking with Go/Rust
    });
    tun_lib_module.addOptions("tun_build_options", tun_options);

    // Embed wintun.dll if provided
    if (wintun_dll_path) |dll_path| {
        tun_lib_module.addAnonymousImport("wintun_dll", .{
            .root_source_file = .{ .cwd_relative = dll_path },
        });
    }

    // TUN library (static library with C ABI)
    const tun_lib = b.addLibrary(.{
        .name = "tun",
        .root_module = tun_lib_module,
    });
    b.installArtifact(tun_lib);

    // Install C header
    b.installFile("include/tun.h", "include/tun.h");

    // Copy wintun.dll to output directory if provided (for runtime loading)
    if (wintun_dll_path) |dll_path| {
        b.installFile(dll_path, "bin/wintun.dll");
    }

    // TUN tests
    const tun_test_module = b.createModule(.{
        .root_source_file = b.path("src/tun/mod.zig"),
        .target = target,
        .optimize = optimize,
    });
    tun_test_module.addOptions("tun_build_options", tun_options);
    if (wintun_dll_path) |dll_path| {
        tun_test_module.addAnonymousImport("wintun_dll", .{
            .root_source_file = .{ .cwd_relative = dll_path },
        });
    }

    const tun_tests = b.addTest(.{
        .root_module = tun_test_module,
    });

    const run_tun_tests = b.addRunArtifact(tun_tests);
    const tun_test_step = b.step("test-tun", "Run TUN tests (requires root/admin)");
    tun_test_step.dependOn(&run_tun_tests.step);

    // Export TUN module for dependents
    _ = b.addModule("tun", .{
        .root_source_file = b.path("src/tun/mod.zig"),
    });
}
