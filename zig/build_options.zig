//! Build options for Bazel-native builds.
//!
//! This file replaces the build.zig addOptions("build_options", ...) mechanism.
//! It auto-detects the optimal cipher backend based on the target architecture.
//!
//! For local dev with `zig build`, build.zig still uses addOptions() and this
//! file is not used.

const builtin = @import("builtin");

/// Cipher backend selection.
pub const Backend = enum {
    /// ARM64 assembly - fastest on ARM64 (~13 Gbps)
    aarch64_asm,
    /// x86_64 AVX2/SSE4.1 assembly - fastest on x86_64 (~12 Gbps)
    x86_64_asm,
    /// SIMD-optimized Zig (~10 Gbps, experimental)
    simd_zig,
    /// Pure Zig using std.crypto - portable (~6 Gbps)
    native_zig,
};

/// Auto-detected backend based on target architecture.
/// - ARM64: BoringSSL assembly
/// - Other: Pure Zig std.crypto
///
/// Note: x86_64 ASM backend exists but is not yet wired into Bazel's
/// select() for C/ASM sources. When added, change the x86_64 linux
/// case below from native_zig to x86_64_asm.
pub const backend: Backend = if (builtin.cpu.arch == .aarch64)
    .aarch64_asm
else
    .native_zig;

/// Minicoro coroutine support (disabled in Bazel builds).
pub const enable_minicoro = false;
