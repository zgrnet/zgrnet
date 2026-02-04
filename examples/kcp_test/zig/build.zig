const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // Get the noise library from the dependency
    const noise_dep = b.dependency("noise", .{
        .target = target,
        .optimize = optimize,
    });

    // Get KCP path from the noise dependency's sub-dependency
    const kcp_path = if (noise_dep.builder.lazyDependency("kcp", .{})) |kcp_lazy|
        kcp_lazy.path("")
    else
        @panic("KCP dependency not found");

    // Get the noise module and add KCP include path to it
    const noise_module = noise_dep.module("noise");
    noise_module.addIncludePath(kcp_path);

    // Create module for the executable
    const exe_module = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });
    exe_module.addImport("noise", noise_module);

    const exe = b.addExecutable(.{
        .name = "kcp_test",
        .root_module = exe_module,
    });

    // Link the pre-compiled noise library (which includes KCP)
    exe.linkLibrary(noise_dep.artifact("noise"));

    b.installArtifact(exe);

    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        run_cmd.addArgs(args);
    }

    const run_step = b.step("run", "Run the KCP interop test");
    run_step.dependOn(&run_cmd.step);
}
