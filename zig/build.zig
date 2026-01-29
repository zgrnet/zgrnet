const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // Backend selection:
    // - "zig": Pure Zig implementation (default, portable, ~6 Gbps)
    // - "asm": BoringSSL ARM64 assembly (fastest, ~13 Gbps on ARM64)
    const backend = b.option([]const u8, "backend", "Crypto backend: 'zig' (default) or 'asm'") orelse "zig";
    const use_asm = std.mem.eql(u8, backend, "asm");

    // Check if ASM is supported on target
    const target_arch = target.result.cpu.arch;
    const asm_supported = (target_arch == .aarch64);

    if (use_asm and !asm_supported) {
        std.log.warn("ASM backend only supported on ARM64, falling back to Zig", .{});
    }

    const effective_use_asm = use_asm and asm_supported;

    // Build options to pass to source code
    const options = b.addOptions();
    options.addOption(bool, "use_asm", effective_use_asm);

    // Helper to compile and link ASM files
    // Note: Using _no_cfi.S because Zig linker crashes on CFI directives
    const addAsmFiles = struct {
        fn add(compile: *std.Build.Step.Compile, builder: *std.Build) void {
            // Add ASM file (CFI stripped version to avoid Zig linker bug)
            compile.addAssemblyFile(builder.path("src/boringssl/chacha20_poly1305_no_cfi.S"));
            // Add C wrapper
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
    if (effective_use_asm) addAsmFiles(lib, b);
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
    if (effective_use_asm) addAsmFiles(main_tests, b);

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
    if (effective_use_asm) addAsmFiles(bench_exe, b);
    b.installArtifact(bench_exe);

    const run_bench = b.addRunArtifact(bench_exe);
    const bench_step = b.step("bench", "Run benchmarks");
    bench_step.dependOn(&run_bench.step);
}
