const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const noise_dep = b.dependency("noise", .{
        .target = target,
        .optimize = optimize,
    });

    const kcp_path = if (noise_dep.builder.lazyDependency("kcp", .{})) |kcp_lazy|
        kcp_lazy.path("")
    else
        @panic("KCP dependency not found");

    const noise_module = noise_dep.module("noise");
    noise_module.addIncludePath(kcp_path);

    const exe_module = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });
    exe_module.addImport("noise", noise_module);

    const exe = b.addExecutable(.{
        .name = "proxy_test",
        .root_module = exe_module,
    });

    exe.linkLibrary(noise_dep.artifact("noise"));

    b.installArtifact(exe);

    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        run_cmd.addArgs(args);
    }

    const run_step = b.step("run", "Run the proxy interop test");
    run_step.dependOn(&run_cmd.step);
}
