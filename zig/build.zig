const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // ASM support: opt-in via -Duse-asm=true (disabled by default until ASM bug is fixed)
    // ARM64 ASM is available for macOS and Linux
    const target_arch = target.result.cpu.arch;
    const target_os = target.result.os.tag;
    const asm_supported = (target_arch == .aarch64) and 
                          (target_os == .macos or target_os == .linux);
    
    // User can enable ASM via build option if supported
    const use_asm = b.option(bool, "use-asm", "Enable ARM64 ASM optimizations") orelse false;
    _ = asm_supported; // TODO: auto-enable when ASM bug is fixed

    // Build options to pass to source code
    const options = b.addOptions();
    options.addOption(bool, "use_asm", use_asm);

    // Helper to add ASM files to a compile step
    const addAsmFiles = struct {
        fn add(compile: *std.Build.Step.Compile, builder: *std.Build) void {
            compile.addAssemblyFile(builder.path("src/boringssl/chacha20_poly1305.S"));
            compile.addCSourceFile(.{
                .file = builder.path("src/boringssl/chacha20_poly1305_wrapper.c"),
                .flags = &.{"-O3"},
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
    if (use_asm) addAsmFiles(lib, b);
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
    if (use_asm) addAsmFiles(main_tests, b);

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
    if (use_asm) addAsmFiles(bench_exe, b);
    b.installArtifact(bench_exe);

    const run_bench = b.addRunArtifact(bench_exe);
    const bench_step = b.step("bench", "Run benchmarks");
    bench_step.dependOn(&run_bench.step);
}
