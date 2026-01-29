const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const target_arch = target.result.cpu.arch;

    // Backend auto-selection based on architecture:
    // - ARM64: BoringSSL ASM (~13 Gbps)
    // - x86_64: Pure Zig std.crypto (~6 Gbps) - TODO: add x86_64 ASM
    // - Other: Pure Zig (~6 Gbps)
    const BackendEnum = enum { arm64_asm, simd, pure_zig };
    
    const default_backend: BackendEnum = if (target_arch == .aarch64)
        .arm64_asm
    else
        .pure_zig;  // std.crypto is already optimized for most platforms

    const backend_opt = b.option(BackendEnum, "backend", "Crypto backend: arm64_asm, simd, pure_zig") orelse default_backend;

    // Warn if using ASM on non-ARM64
    if (backend_opt == .arm64_asm and target_arch != .aarch64) {
        std.log.warn("ASM backend only available on ARM64, falling back to SIMD/Zig", .{});
    }

    const effective_backend = if (backend_opt == .arm64_asm and target_arch != .aarch64)
        if (target_arch == .x86_64) BackendEnum.simd else BackendEnum.pure_zig
    else
        backend_opt;

    // Map to cipher.zig Backend enum
    const CipherBackend = enum { boringssl_asm, simd_zig, native_zig };
    const cipher_backend: CipherBackend = switch (effective_backend) {
        .arm64_asm => .boringssl_asm,
        .simd => .simd_zig,
        .pure_zig => .native_zig,
    };

    // Build options to pass to source code
    const options = b.addOptions();
    options.addOption(CipherBackend, "backend", cipher_backend);

    // Helper to add ASM files (ARM64 only)
    const addAsmFiles = struct {
        fn add(compile: *std.Build.Step.Compile, builder: *std.Build) void {
            compile.addAssemblyFile(builder.path("src/boringssl/chacha20_poly1305_no_cfi.S"));
            compile.addCSourceFile(.{
                .file = builder.path("src/boringssl/chacha20_poly1305_wrapper.c"),
                .flags = &.{ "-O3", "-I", "src/boringssl" },
            });
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
    if (effective_backend == .arm64_asm) addAsmFiles(lib, b);
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
    if (effective_backend == .arm64_asm) addAsmFiles(main_tests, b);

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
    if (effective_backend == .arm64_asm) addAsmFiles(bench_exe, b);
    b.installArtifact(bench_exe);

    const run_bench = b.addRunArtifact(bench_exe);
    const bench_step = b.step("bench", "Run benchmarks");
    bench_step.dependOn(&run_bench.step);
}
