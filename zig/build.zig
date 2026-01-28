const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // BoringSSL paths (set via BORINGSSL_INCLUDE and BORINGSSL_LIB env vars, or use defaults)
    const boringssl_include = std.posix.getenv("BORINGSSL_INCLUDE") orelse
        "/opt/homebrew/opt/openssl@3/include"; // fallback to OpenSSL
    const boringssl_lib = std.posix.getenv("BORINGSSL_LIB") orelse
        "/opt/homebrew/opt/openssl@3/lib";

    // Library module
    const lib_module = b.createModule(.{
        .root_source_file = b.path("src/noise.zig"),
        .target = target,
        .optimize = optimize,
    });
    lib_module.addSystemIncludePath(.{ .cwd_relative = boringssl_include });
    lib_module.addLibraryPath(.{ .cwd_relative = boringssl_lib });

    // Try BoringSSL first, fallback to OpenSSL
    if (std.posix.getenv("BORINGSSL_LIB") != null) {
        lib_module.linkSystemLibrary("crypto_internal", .{});
    } else {
        lib_module.linkSystemLibrary("crypto", .{});
    }

    // Library
    const lib = b.addLibrary(.{
        .name = "noise",
        .root_module = lib_module,
    });
    b.installArtifact(lib);

    // Tests module
    const test_module = b.createModule(.{
        .root_source_file = b.path("src/noise.zig"),
        .target = target,
        .optimize = optimize,
    });
    test_module.addSystemIncludePath(.{ .cwd_relative = boringssl_include });
    test_module.addLibraryPath(.{ .cwd_relative = boringssl_lib });
    if (std.posix.getenv("BORINGSSL_LIB") != null) {
        test_module.linkSystemLibrary("crypto_internal", .{});
    } else {
        test_module.linkSystemLibrary("crypto", .{});
    }

    const main_tests = b.addTest(.{
        .root_module = test_module,
    });

    const run_main_tests = b.addRunArtifact(main_tests);
    const test_step = b.step("test", "Run library tests");
    test_step.dependOn(&run_main_tests.step);

    // Benchmarks module
    const bench_module = b.createModule(.{
        .root_source_file = b.path("src/bench.zig"),
        .target = target,
        .optimize = .ReleaseFast,
    });
    bench_module.addSystemIncludePath(.{ .cwd_relative = boringssl_include });
    bench_module.addLibraryPath(.{ .cwd_relative = boringssl_lib });
    if (std.posix.getenv("BORINGSSL_LIB") != null) {
        bench_module.linkSystemLibrary("crypto_internal", .{});
    } else {
        bench_module.linkSystemLibrary("crypto", .{});
    }

    const bench_exe = b.addExecutable(.{
        .name = "bench",
        .root_module = bench_module,
    });
    b.installArtifact(bench_exe);

    const run_bench = b.addRunArtifact(bench_exe);
    const bench_step = b.step("bench", "Run benchmarks");
    bench_step.dependOn(&run_bench.step);
}
