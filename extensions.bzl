"""Module extensions for zgrnet.

Provides:
- KCP library (skywind3000/kcp)

Note: Zig toolchain is now provided by embed_zig (bazel_dep in MODULE.bazel).
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
        strip_prefix = "kcp-{}".format(_KCP_VERSION),
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
