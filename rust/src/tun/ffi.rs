//! Raw FFI bindings to the Zig TUN library.
//!
//! This module provides the raw C bindings. Users should prefer the safe
//! wrappers in the parent module.

use std::os::raw::{c_char, c_int, c_void};

/// Opaque TUN device handle.
#[repr(C)]
pub struct TunHandle {
    _private: [u8; 0],
}

// Error codes (matching tun.h)
pub const TUN_OK: c_int = 0;
pub const TUN_ERR_CREATE_FAILED: c_int = -1;
pub const TUN_ERR_OPEN_FAILED: c_int = -2;
pub const TUN_ERR_INVALID_NAME: c_int = -3;
pub const TUN_ERR_PERMISSION_DENIED: c_int = -4;
pub const TUN_ERR_DEVICE_NOT_FOUND: c_int = -5;
pub const TUN_ERR_NOT_SUPPORTED: c_int = -6;
pub const TUN_ERR_DEVICE_BUSY: c_int = -7;
pub const TUN_ERR_INVALID_ARGUMENT: c_int = -8;
pub const TUN_ERR_SYSTEM_RESOURCES: c_int = -9;
pub const TUN_ERR_WOULD_BLOCK: c_int = -10;
pub const TUN_ERR_IO_ERROR: c_int = -11;
pub const TUN_ERR_SET_MTU_FAILED: c_int = -12;
pub const TUN_ERR_SET_ADDRESS_FAILED: c_int = -13;
pub const TUN_ERR_SET_STATE_FAILED: c_int = -14;
pub const TUN_ERR_ALREADY_CLOSED: c_int = -15;
pub const TUN_ERR_WINTUN_NOT_FOUND: c_int = -16;
pub const TUN_ERR_WINTUN_INIT_FAILED: c_int = -17;

#[cfg(unix)]
pub type RawHandle = c_int;

#[cfg(windows)]
pub type RawHandle = *mut c_void;

extern "C" {
    // Initialization
    pub fn tun_init() -> c_int;
    pub fn tun_deinit();

    // Lifecycle
    pub fn tun_create(name: *const c_char) -> *mut TunHandle;
    pub fn tun_close(tun: *mut TunHandle);

    // Read/Write
    pub fn tun_read(tun: *mut TunHandle, buf: *mut c_void, len: usize) -> isize;
    pub fn tun_write(tun: *mut TunHandle, buf: *const c_void, len: usize) -> isize;

    // Properties
    pub fn tun_get_name(tun: *mut TunHandle) -> *const c_char;
    pub fn tun_get_handle(tun: *mut TunHandle) -> RawHandle;

    // MTU
    pub fn tun_get_mtu(tun: *mut TunHandle) -> c_int;
    pub fn tun_set_mtu(tun: *mut TunHandle, mtu: c_int) -> c_int;

    // Non-blocking
    pub fn tun_set_nonblocking(tun: *mut TunHandle, enabled: c_int) -> c_int;

    // Interface state
    pub fn tun_set_up(tun: *mut TunHandle) -> c_int;
    pub fn tun_set_down(tun: *mut TunHandle) -> c_int;

    // IP configuration
    pub fn tun_set_ipv4(
        tun: *mut TunHandle,
        addr: *const c_char,
        netmask: *const c_char,
    ) -> c_int;
    pub fn tun_set_ipv6(tun: *mut TunHandle, addr: *const c_char, prefix_len: c_int) -> c_int;
}
