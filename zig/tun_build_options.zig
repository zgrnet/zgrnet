//! TUN build options for Bazel-native builds.
//!
//! This file replaces the build.zig addOptions("tun_build_options", ...) mechanism.
//! For Bazel builds, wintun.dll is not embedded — it must be provided at runtime.
//!
//! For local dev with `zig build -Dwintun_dll=path`, build.zig still uses
//! addOptions() and this file is not used.

/// Whether wintun.dll is embedded at compile time.
/// In Bazel builds this is always false — wintun.dll must be provided at runtime.
pub const has_wintun_dll = false;
