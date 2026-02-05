"""Module extensions for zgrnet.

Provides:
- Zig toolchain (official release)
- KCP library (skywind3000/kcp)
"""

# =============================================================================
# KCP Library
# =============================================================================

_KCP_VERSION = "1.7"
_KCP_SHA256 = "b4d26994d95599ab0c44e1f93002f9fda275094a879d66c192d79d596529199e"

def _kcp_impl(ctx):
    """Download KCP source."""
    ctx.download_and_extract(
        url = "https://github.com/skywind3000/kcp/archive/refs/tags/{}.tar.gz".format(_KCP_VERSION),
        sha256 = _KCP_SHA256,
        stripPrefix = "kcp-{}".format(_KCP_VERSION),
    )
    ctx.file("BUILD.bazel", """
package(default_visibility = ["//visibility:public"])

filegroup(
    name = "srcs",
    srcs = glob(["**/*"]),
)

exports_files(["ikcp.c", "ikcp.h"])
""")

_kcp_repo = repository_rule(
    implementation = _kcp_impl,
)

def _kcp_ext_impl(ctx):
    """Module extension for KCP library."""
    _kcp_repo(name = "kcp")

kcp_lib = module_extension(
    implementation = _kcp_ext_impl,
)

# =============================================================================
# Zig Toolchain
# =============================================================================

_ZIG_VERSION = "0.15.2"

_ZIG_SHA256 = {
    "aarch64-macos": "3cc2bab367e185cdfb27501c4b30b1b0653c28d9f73df8dc91488e66ece5fa6b",
    "x86_64-macos": "375b6909fc1495d16fc2c7db9538f707456bfc3373b14ee83fdd3e22b3d43f7f",
    "x86_64-linux": "02aa270f183da276e5b5920b1dac44a63f1a49e55050ebde3aecc9eb82f93239",
    "aarch64-linux": "958ed7d1e00d0ea76590d27666efbf7a932281b3d7ba0c6b01b0ff26498f667f",
}

def _zig_toolchain_impl(ctx):
    """Download official Zig compiler."""
    os = ctx.os.name
    arch = ctx.os.arch

    # Map OS names
    if os == "mac os x" or os.startswith("darwin"):
        os_name = "macos"
    elif os.startswith("linux"):
        os_name = "linux"
    else:
        fail("Unsupported OS: " + os)

    # Map architecture
    if arch == "amd64" or arch == "x86_64":
        arch_name = "x86_64"
    elif arch == "aarch64" or arch == "arm64":
        arch_name = "aarch64"
    else:
        fail("Unsupported architecture: " + arch)

    platform = "{}-{}".format(arch_name, os_name)
    filename = "zig-{}-{}.tar.xz".format(platform, _ZIG_VERSION)

    url = "https://ziglang.org/download/{}/{}".format(_ZIG_VERSION, filename)

    ctx.download_and_extract(
        url = url,
        sha256 = _ZIG_SHA256.get(platform, ""),
        stripPrefix = "zig-{}-{}".format(platform, _ZIG_VERSION),
    )

    ctx.file("BUILD.bazel", """
package(default_visibility = ["//visibility:public"])

filegroup(
    name = "zig_files",
    srcs = glob(["**/*"]),
)

exports_files(["zig"])
""")

    ctx.file("VERSION", _ZIG_VERSION)

_zig_toolchain_repo = repository_rule(
    implementation = _zig_toolchain_impl,
)

def _zig_toolchain_ext_impl(ctx):
    """Module extension for Zig toolchain."""
    _zig_toolchain_repo(name = "zig_toolchain")

zig_toolchain = module_extension(
    implementation = _zig_toolchain_ext_impl,
)
