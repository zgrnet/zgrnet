//! Raw FFI bindings to the Zig dnsmgr library.
//!
//! This module provides raw C bindings. Users should prefer the safe
//! wrappers in the parent module.

use std::os::raw::{c_char, c_int};

/// Opaque DNS manager handle.
#[repr(C)]
pub struct DnsMgrHandle {
    _private: [u8; 0],
}

// Error codes (matching dnsmgr.h)
pub const DNSMGR_OK: c_int = 0;
pub const DNSMGR_ERR_SET_FAILED: c_int = -1;
pub const DNSMGR_ERR_CREATE_FAILED: c_int = -2;
pub const DNSMGR_ERR_REMOVE_FAILED: c_int = -3;
pub const DNSMGR_ERR_PERMISSION_DENIED: c_int = -4;
pub const DNSMGR_ERR_NOT_SUPPORTED: c_int = -5;
pub const DNSMGR_ERR_INVALID_ARGUMENT: c_int = -6;
pub const DNSMGR_ERR_FLUSH_FAILED: c_int = -7;
pub const DNSMGR_ERR_DETECT_FAILED: c_int = -8;
pub const DNSMGR_ERR_UPSTREAM_FAILED: c_int = -9;

extern "C" {
    pub fn dnsmgr_create(iface_name: *const c_char) -> *mut DnsMgrHandle;
    pub fn dnsmgr_close(mgr: *mut DnsMgrHandle);
    pub fn dnsmgr_set(
        mgr: *mut DnsMgrHandle,
        nameserver: *const c_char,
        domains: *const c_char,
    ) -> c_int;
    pub fn dnsmgr_supports_split_dns(mgr: *mut DnsMgrHandle) -> c_int;
    pub fn dnsmgr_flush_cache() -> c_int;
}
