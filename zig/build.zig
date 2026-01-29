const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

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
    const CipherBackend = enum { boringssl_asm, x86_64_asm, simd_zig, native_zig };
    const cipher_backend: CipherBackend = switch (effective_backend) {
        .arm64_asm => .boringssl_asm,
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
            compile.addAssemblyFile(builder.path("src/boringssl/chacha20_poly1305_no_cfi.S"));
            compile.addCSourceFile(.{
                .file = builder.path("src/boringssl/chacha20_poly1305_wrapper.c"),
                .flags = &.{ "-O3", "-I", "src/boringssl" },
            });
        }
    }.add;

    // Helper to add x86_64 ASM files
    const addX86AsmFiles = struct {
        fn add(compile: *std.Build.Step.Compile, builder: *std.Build) void {
            compile.addAssemblyFile(builder.path("src/asm_x86_64/chacha20_poly1305_x86_64.S"));
            compile.addCSourceFile(.{
                .file = builder.path("src/asm_x86_64/chacha20_poly1305_wrapper.c"),
                .flags = &.{ "-O3", "-mavx2", "-mbmi2" },
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
    if (effective_backend == .arm64_asm) addArm64AsmFiles(lib, b);
    if (effective_backend == .x86_64_asm) addX86AsmFiles(lib, b);
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
    b.installArtifact(bench_exe);

    const run_bench = b.addRunArtifact(bench_exe);
    const bench_step = b.step("bench", "Run benchmarks");
    bench_step.dependOn(&run_bench.step);
}
