"""Zig build rules for Bazel.

Usage:
    load("//bazel/zig:defs.bzl", "zig_run")

    zig_run(
        name = "run",
        srcs = glob(["**/*"]),
        build_args = ["-Doptimize=ReleaseFast"],
    )

Run:
    bazel run //path/to/project:run
"""

def _zig_run_impl(ctx):
    """Run a standalone Zig project.
    
    Copies all source files to a temp directory preserving their relative paths,
    then runs zig build from the zig_root directory.
    """

    # Collect source files
    src_files = []
    for src in ctx.attr.srcs:
        src_files.extend(src.files.to_list())

    # Get Zig toolchain
    zig_files = ctx.attr._zig_toolchain.files.to_list()
    zig_bin = None
    for f in zig_files:
        if f.basename == "zig" and f.is_source:
            zig_bin = f
            break

    if not zig_bin:
        fail("Could not find zig binary in toolchain")

    # Create run script
    run_script = ctx.actions.declare_file("{}_run.sh".format(ctx.label.name))

    # Generate copy commands for source files
    # Preserve the full relative path from workspace root
    src_copy_commands = []
    for f in src_files:
        rel_path = f.short_path
        src_copy_commands.append('mkdir -p "$WORK/$(dirname {})" && cp "{}" "$WORK/{}"'.format(
            rel_path,
            f.path,
            rel_path,
        ))

    # Build arguments
    build_args = " ".join(ctx.attr.build_args) if ctx.attr.build_args else ""

    # Determine zig_root (directory containing build.zig)
    zig_root = ctx.attr.zig_root if ctx.attr.zig_root else "zig"

    script_content = """#!/bin/bash
set -e

WORK=$(mktemp -d)
trap "rm -rf $WORK" EXIT

# Copy source files (preserving directory structure)
{src_copy_commands}

# Set up Zig path
export PATH="{zig_dir}:$PATH"

# Run zig build from zig_root
cd "$WORK/{zig_root}"
echo "[zig_run] Building with: zig build {build_args}"
zig build {build_args}
""".format(
        zig_dir = zig_bin.dirname,
        zig_root = zig_root,
        src_copy_commands = "\n".join(src_copy_commands),
        build_args = build_args,
    )

    ctx.actions.write(
        output = run_script,
        content = script_content,
        is_executable = True,
    )

    return [
        DefaultInfo(
            executable = run_script,
            runfiles = ctx.runfiles(files = src_files + zig_files),
        ),
    ]

zig_run = rule(
    implementation = _zig_run_impl,
    executable = True,
    attrs = {
        "srcs": attr.label_list(
            allow_files = True,
            mandatory = True,
            doc = "Source files for the Zig project",
        ),
        "build_args": attr.string_list(
            doc = "Arguments to pass to zig build (e.g., -Doptimize=ReleaseFast)",
        ),
        "zig_root": attr.string(
            default = "zig",
            doc = "Directory containing build.zig (relative to workspace root)",
        ),
        "_zig_toolchain": attr.label(
            default = "@zig_toolchain//:zig_files",
            doc = "Zig compiler toolchain",
        ),
    },
    doc = "Run a standalone Zig project using zig build",
)
