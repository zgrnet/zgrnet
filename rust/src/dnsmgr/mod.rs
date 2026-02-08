//! OS DNS configuration manager.
//!
//! This module provides safe Rust wrappers around the Zig dnsmgr library,
//! offering a native Rust API for configuring the OS to route DNS queries
//! for specific domains to a custom nameserver.
//!
//! # Example
//!
//! ```no_run
//! use zgrnet::dnsmgr::Manager;
//!
//! let mut mgr = Manager::new(Some("utun3")).expect("failed to create DNS manager");
//! mgr.set_dns("100.64.0.1", &["zigor.net"]).expect("failed to set DNS");
//! // ... application runs ...
//! mgr.close(); // restores original DNS config
//! ```

pub mod ffi;

use std::ffi::CString;
use std::sync::RwLock;

/// Error type for DNS manager operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    SetFailed,
    CreateFailed,
    RemoveFailed,
    PermissionDenied,
    NotSupported,
    InvalidArgument,
    FlushFailed,
    DetectFailed,
    UpstreamFailed,
    NullPointer,
    Unknown(i32),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::SetFailed => write!(f, "dnsmgr: set DNS failed"),
            Error::CreateFailed => write!(f, "dnsmgr: create failed"),
            Error::RemoveFailed => write!(f, "dnsmgr: remove failed"),
            Error::PermissionDenied => write!(f, "dnsmgr: permission denied"),
            Error::NotSupported => write!(f, "dnsmgr: not supported"),
            Error::InvalidArgument => write!(f, "dnsmgr: invalid argument"),
            Error::FlushFailed => write!(f, "dnsmgr: flush cache failed"),
            Error::DetectFailed => write!(f, "dnsmgr: detect DNS mode failed"),
            Error::UpstreamFailed => write!(f, "dnsmgr: upstream operation failed"),
            Error::NullPointer => write!(f, "dnsmgr: null pointer"),
            Error::Unknown(code) => write!(f, "dnsmgr: unknown error code {}", code),
        }
    }
}

impl std::error::Error for Error {}

/// OS DNS configuration manager.
///
/// Thread-safe wrapper around the Zig dnsmgr library.
pub struct Manager {
    inner: RwLock<ManagerInner>,
}

struct ManagerInner {
    handle: *mut ffi::DnsMgrHandle,
    closed: bool,
}

// Safety: The raw `handle` pointer is not inherently thread-safe.
// Thread safety is provided by the `RwLock<ManagerInner>` in `Manager`,
// which ensures all access to the handle is properly synchronized.
unsafe impl Send for ManagerInner {}
unsafe impl Sync for ManagerInner {}

impl Manager {
    /// Create a new DNS manager.
    ///
    /// `iface_name` is the TUN interface name (e.g., "utun3").
    /// Pass `None` if not applicable.
    pub fn new(iface_name: Option<&str>) -> Result<Self, Error> {
        let c_name = match iface_name {
            Some(name) => {
                let s = CString::new(name).map_err(|_| Error::InvalidArgument)?;
                Some(s)
            }
            None => None,
        };

        let handle = unsafe {
            ffi::dnsmgr_create(
                c_name.as_ref().map(|s| s.as_ptr()).unwrap_or(std::ptr::null()),
            )
        };

        if handle.is_null() {
            return Err(Error::CreateFailed);
        }

        Ok(Manager {
            inner: RwLock::new(ManagerInner {
                handle,
                closed: false,
            }),
        })
    }

    /// Set DNS configuration.
    ///
    /// Routes queries for the given domains to the specified nameserver.
    pub fn set_dns(&self, nameserver: &str, domains: &[&str]) -> Result<(), Error> {
        let inner = self.inner.write().unwrap();
        if inner.closed {
            return Err(Error::SetFailed);
        }

        let c_ns = CString::new(nameserver).map_err(|_| Error::InvalidArgument)?;
        let csv = domains.join(",");
        let c_domains = CString::new(csv).map_err(|_| Error::InvalidArgument)?;

        let rc = unsafe { ffi::dnsmgr_set(inner.handle, c_ns.as_ptr(), c_domains.as_ptr()) };
        if rc != 0 {
            return Err(code_to_error(rc));
        }
        Ok(())
    }

    /// Check if platform supports split DNS natively.
    pub fn supports_split_dns(&self) -> bool {
        let inner = self.inner.read().unwrap();
        if inner.closed {
            return false;
        }
        unsafe { ffi::dnsmgr_supports_split_dns(inner.handle) != 0 }
    }

    /// Close the manager and restore original DNS configuration.
    pub fn close(&self) {
        let mut inner = self.inner.write().unwrap();
        if inner.closed {
            return;
        }
        unsafe { ffi::dnsmgr_close(inner.handle) };
        inner.handle = std::ptr::null_mut();
        inner.closed = true;
    }
}

impl Drop for Manager {
    fn drop(&mut self) {
        self.close();
    }
}

/// Flush the OS DNS cache.
pub fn flush_cache() -> Result<(), Error> {
    let rc = unsafe { ffi::dnsmgr_flush_cache() };
    if rc != 0 {
        return Err(code_to_error(rc));
    }
    Ok(())
}

fn code_to_error(code: i32) -> Error {
    match code {
        -1 => Error::SetFailed,
        -2 => Error::CreateFailed,
        -3 => Error::RemoveFailed,
        -4 => Error::PermissionDenied,
        -5 => Error::NotSupported,
        -6 => Error::InvalidArgument,
        -7 => Error::FlushFailed,
        -8 => Error::DetectFailed,
        -9 => Error::UpstreamFailed,
        _ => Error::Unknown(code),
    }
}
