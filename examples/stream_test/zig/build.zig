const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // Get the noise library from the dependency
    const noise_dep = b.dependency("noise", .{
        .target = target,
        .optimize = optimize,
    });

    // Create module for the executable
    const exe_module = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });
    exe_module.addImport("noise", noise_dep.module("noise"));

    const exe = b.addExecutable(.{
        .name = "stream_test",
        .root_module = exe_module,
    });
    b.installArtifact(exe);

    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        run_cmd.addArgs(args);
    }

    const run_step = b.step("run", "Run the stream throughput test");
    run_step.dependOn(&run_cmd.step);
}
