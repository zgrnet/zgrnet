const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // KCP dependency
    const kcp_dep = b.dependency("kcp", .{});
    const kcp_path = kcp_dep.path("");

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

    // OS backend selection
    const OsBackend = enum { darwin, none };
    const default_os_backend: OsBackend = switch (target_os) {
        .macos, .ios, .tvos, .watchos => .darwin,
        else => .none,
    };
    const os_backend = b.option(OsBackend, "os_backend", "OS backend: darwin (kqueue), none (single-threaded)") orelse default_os_backend;

    // Build options
    const options = b.addOptions();
    options.addOption(CipherBackend, "backend", cipher_backend);
    options.addOption(OsBackend, "os_backend", os_backend);

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
    b.installArtifact(lib);

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

    // Host test example (for cross-language testing)
    const host_test_module = b.createModule(.{
        .root_source_file = b.path("examples/host_test.zig"),
        .target = target,
        .optimize = optimize,
    });
    host_test_module.addOptions("build_options", options);
    host_test_module.addImport("noise", lib_module);

    // Link against the library to avoid duplicate symbols
    const host_test_exe = b.addExecutable(.{
        .name = "host_test",
        .root_module = host_test_module,
    });
    host_test_exe.linkLibrary(lib);
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
}
