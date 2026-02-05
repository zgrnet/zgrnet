"""Zig build rules for Bazel.

Usage:
    load("//bazel/zig:defs.bzl", "zig_run", "zig_binary")

    # Run a Zig project (builds in temp directory)
    zig_run(
        name = "run",
        srcs = glob(["**/*"]),
        build_args = ["-Doptimize=ReleaseFast"],
    )

    # Build a Zig binary (outputs to bazel-bin)
    zig_binary(
        name = "my_binary",
        srcs = [":srcs"],
        binary_name = "my_binary",
        target = "my_binary",  # zig build target name
    )

Run:
    bazel run //path/to/project:run
    bazel build //path/to/project:my_binary
"""

load("@bazel_skylib//lib:shell.bzl", "shell")

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

# =============================================================================
# zig_binary - Build a Zig binary and output to Bazel's output directory
# =============================================================================

def _zig_binary_impl(ctx):
    """Build a Zig binary and output it to Bazel's output directory.
    
    This rule compiles a Zig project and produces an executable binary
    that can be used as a dependency in other Bazel rules (e.g., sh_test).
    
    External dependencies (KCP) are downloaded by Bazel and passed to zig build
    via -Dkcp_path option, enabling fully hermetic builds.
    """

    # Declare the output binary
    out = ctx.actions.declare_file(ctx.attr.binary_name)

    # Collect source files
    src_files = []
    for src in ctx.attr.srcs:
        src_files.extend(src.files.to_list())

    # Get Zig binary and toolchain files
    zig_bin = ctx.file._zig
    zig_files = ctx.attr._zig_toolchain.files.to_list()

    # Get KCP files
    kcp_files = ctx.attr._kcp.files.to_list()

    # Generate copy commands for source files
    # Use shell.quote for all paths to prevent command injection
    # shell.quote wraps values in single quotes, making them safe from shell expansion
    src_copy_commands = []
    for f in src_files:
        quoted_rel_path = shell.quote(f.short_path)
        quoted_src_path = shell.quote(f.path)
        # Command: mkdir -p "$WORK/"$(dirname 'rel_path') && cp 'src' "$WORK/"'rel_path'
        src_copy_commands.append('mkdir -p "$WORK/"$(dirname {}) && cp {} "$WORK/"{}'.format(
            quoted_rel_path,             # shell.quote prevents injection in dirname
            quoted_src_path,             # shell.quote for cp source
            quoted_rel_path,             # shell.quote for destination
        ))

    # Generate copy commands for KCP files
    kcp_copy_commands = []
    for f in kcp_files:
        # KCP files go to $WORK/.deps/kcp/
        kcp_copy_commands.append('cp {} "$WORK/.deps/kcp/"'.format(shell.quote(f.path)))

    # Determine zig_root and target (with shell quoting for safety)
    zig_root = ctx.attr.zig_root if ctx.attr.zig_root else "zig"
    optimize = ctx.attr.optimize

    # Validate attribute values to prevent injection
    # These are from BUILD files, not user input, but we quote them for defense-in-depth
    quoted_zig_root = shell.quote(zig_root)
    quoted_optimize = shell.quote(optimize)
    quoted_binary_name = shell.quote(ctx.attr.binary_name)

    # Build command - use absolute path to zig binary
    # After cd to work directory, relative paths don't work anymore
    command = """
set -e

WORK=$(mktemp -d)
cleanup() {{ rm -rf "$WORK"; }}
trap cleanup EXIT

# Save absolute paths before we cd elsewhere
ZIG="$PWD/{zig_path}"
OUTPUT="$PWD/{output}"

if [ ! -x "$ZIG" ]; then
    echo "ERROR: Zig binary not found at $ZIG" >&2
    exit 1
fi

# Set zig cache directories (zig needs these to function)
export ZIG_LOCAL_CACHE_DIR="$WORK/.zig-cache"
export ZIG_GLOBAL_CACHE_DIR="$WORK/.zig-global-cache"
mkdir -p "$ZIG_LOCAL_CACHE_DIR" "$ZIG_GLOBAL_CACHE_DIR"

# Copy source files (preserving directory structure)
{src_copy_commands}

# Copy KCP dependency (downloaded by Bazel)
mkdir -p "$WORK/.deps/kcp"
{kcp_copy_commands}

# Build all artifacts with KCP path from Bazel
cd "$WORK"/{zig_root}
"$ZIG" build -Doptimize={optimize} -Dkcp_path="$WORK/.deps/kcp"

# Copy output to Bazel's output directory
cp "$WORK"/{zig_root}/zig-out/bin/{binary_name} "$OUTPUT"
""".format(
        zig_path = zig_bin.path,
        zig_root = quoted_zig_root,
        src_copy_commands = "\n".join(src_copy_commands),
        kcp_copy_commands = "\n".join(kcp_copy_commands),
        optimize = quoted_optimize,
        binary_name = quoted_binary_name,
        output = out.path,
    )

    ctx.actions.run_shell(
        outputs = [out],
        inputs = src_files + zig_files + kcp_files + [zig_bin],
        command = command,
        mnemonic = "ZigBuild",
        progress_message = "Building Zig binary %s" % ctx.attr.binary_name,
        # Hermetic build: all dependencies downloaded by Bazel
    )

    return [
        DefaultInfo(
            files = depset([out]),
            executable = out,
        ),
    ]

zig_binary = rule(
    implementation = _zig_binary_impl,
    executable = True,
    attrs = {
        "srcs": attr.label_list(
            allow_files = True,
            mandatory = True,
            doc = "Source files for the Zig project",
        ),
        "binary_name": attr.string(
            mandatory = True,
            doc = "Name of the output binary (must match zig-out/bin/<name>)",
        ),
        "optimize": attr.string(
            default = "ReleaseFast",
            doc = "Optimization level: Debug, ReleaseSafe, ReleaseFast, ReleaseSmall",
        ),
        "zig_root": attr.string(
            default = "zig",
            doc = "Directory containing build.zig (relative to workspace root)",
        ),
        "_zig": attr.label(
            default = "@zig_toolchain//:zig",
            allow_single_file = True,
            doc = "Zig compiler binary",
        ),
        "_zig_toolchain": attr.label(
            default = "@zig_toolchain//:zig_files",
            doc = "Zig compiler toolchain (lib, etc.)",
        ),
        "_kcp": attr.label(
            default = "//third_party/kcp:srcs",
            doc = "KCP library source files (from //third_party/kcp)",
        ),
    },
    doc = "Build a Zig binary and output to Bazel's output directory",
)
