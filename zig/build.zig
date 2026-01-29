const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // Backend selection:
    // - "zig": Pure Zig implementation (default, portable, ~6 Gbps)
    // - "system": Link system crypto library (OpenSSL/BoringSSL, ~13 Gbps on ARM64)
    const backend = b.option([]const u8, "backend", "Crypto backend: 'zig' (default) or 'system'") orelse "zig";
    const use_system_crypto = std.mem.eql(u8, backend, "system");

    // Build options to pass to source code
    const options = b.addOptions();
    options.addOption(bool, "use_system_crypto", use_system_crypto);

    // System crypto library paths (only used when backend=system)
    const crypto_include = std.posix.getenv("CRYPTO_INCLUDE") orelse
        "/opt/homebrew/opt/openssl@3/include";
    const crypto_lib = std.posix.getenv("CRYPTO_LIB") orelse
        "/opt/homebrew/opt/openssl@3/lib";

    // Helper to configure system crypto linking
    const configureSystemCrypto = struct {
        fn configure(compile: *std.Build.Step.Compile, builder: *std.Build, include: []const u8, lib_path: []const u8) void {
            // Link libc for OpenSSL
            compile.linkLibC();
            
            // Add OpenSSL wrapper C source
            compile.addCSourceFile(.{
                .file = builder.path("src/openssl/openssl_wrapper.c"),
                .flags = &.{ "-O3", "-I", include },
            });
            
            // Add library search path and link OpenSSL
            compile.addLibraryPath(.{ .cwd_relative = lib_path });
            compile.linkSystemLibrary2("crypto", .{ .use_pkg_config = .no });
            
            // Add rpath for runtime library lookup
            compile.addRPath(.{ .cwd_relative = lib_path });
        }
    }.configure;

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
    if (use_system_crypto) {
        configureSystemCrypto(lib, b, crypto_include, crypto_lib);
    }
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
    if (use_system_crypto) {
        configureSystemCrypto(main_tests, b, crypto_include, crypto_lib);
    }

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
    if (use_system_crypto) {
        configureSystemCrypto(bench_exe, b, crypto_include, crypto_lib);
    }
    b.installArtifact(bench_exe);

    const run_bench = b.addRunArtifact(bench_exe);
    const bench_step = b.step("bench", "Run benchmarks");
    bench_step.dependOn(&run_bench.step);
}
