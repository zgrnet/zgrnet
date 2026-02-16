//! Cross-platform TUN device interface.
//!
//! This module provides safe Rust wrappers around the Zig TUN library,
//! offering a native Rust API for creating and managing TUN devices.
//!
//! # Example
//!
//! ```no_run
//! use zgrnet::tun::{init, Device};
//! use std::net::Ipv4Addr;
//!
//! // Initialize TUN subsystem
//! init().expect("failed to initialize TUN");
//!
//! // Create TUN device
//! let mut device = Device::create(None).expect("failed to create TUN");
//! println!("Created TUN: {}", device.name());
//!
//! // Configure IP address
//! device.set_ipv4(
//!     Ipv4Addr::new(10, 0, 0, 1),
//!     Ipv4Addr::new(255, 255, 255, 0),
//! ).expect("failed to set IP");
//!
//! // Bring interface up
//! device.up().expect("failed to bring up");
//! ```

mod ffi;

use std::ffi::{CStr, CString};
use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, Ordering};

pub use ffi::RawHandle;

/// Error type for TUN operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    CreateFailed,
    OpenFailed,
    InvalidName,
    PermissionDenied,
    DeviceNotFound,
    NotSupported,
    DeviceBusy,
    InvalidArgument,
    SystemResources,
    WouldBlock,
    IoError,
    SetMtuFailed,
    SetAddressFailed,
    SetStateFailed,
    AlreadyClosed,
    WintunNotFound,
    WintunInitFailed,
    NullPointer,
    Unknown(i32),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::CreateFailed => write!(f, "failed to create TUN device"),
            Error::OpenFailed => write!(f, "failed to open TUN device"),
            Error::InvalidName => write!(f, "invalid device name"),
            Error::PermissionDenied => write!(f, "permission denied"),
            Error::DeviceNotFound => write!(f, "device not found"),
            Error::NotSupported => write!(f, "operation not supported"),
            Error::DeviceBusy => write!(f, "device is busy"),
            Error::InvalidArgument => write!(f, "invalid argument"),
            Error::SystemResources => write!(f, "system resources exhausted"),
            Error::WouldBlock => write!(f, "operation would block"),
            Error::IoError => write!(f, "I/O error"),
            Error::SetMtuFailed => write!(f, "failed to set MTU"),
            Error::SetAddressFailed => write!(f, "failed to set address"),
            Error::SetStateFailed => write!(f, "failed to set interface state"),
            Error::AlreadyClosed => write!(f, "device already closed"),
            Error::WintunNotFound => write!(f, "Wintun driver not found"),
            Error::WintunInitFailed => write!(f, "Wintun initialization failed"),
            Error::NullPointer => write!(f, "null pointer"),
            Error::Unknown(code) => write!(f, "unknown error code: {}", code),
        }
    }
}

impl std::error::Error for Error {}

impl From<Error> for io::Error {
    fn from(err: Error) -> io::Error {
        let kind = match err {
            Error::PermissionDenied => io::ErrorKind::PermissionDenied,
            Error::DeviceNotFound => io::ErrorKind::NotFound,
            Error::InvalidArgument => io::ErrorKind::InvalidInput,
            Error::WouldBlock => io::ErrorKind::WouldBlock,
            Error::AlreadyClosed => io::ErrorKind::NotConnected,
            Error::NotSupported => io::ErrorKind::Unsupported,
            _ => io::ErrorKind::Other,
        };
        io::Error::new(kind, err)
    }
}

fn code_to_error(code: i32) -> Error {
    match code {
        ffi::TUN_ERR_CREATE_FAILED => Error::CreateFailed,
        ffi::TUN_ERR_OPEN_FAILED => Error::OpenFailed,
        ffi::TUN_ERR_INVALID_NAME => Error::InvalidName,
        ffi::TUN_ERR_PERMISSION_DENIED => Error::PermissionDenied,
        ffi::TUN_ERR_DEVICE_NOT_FOUND => Error::DeviceNotFound,
        ffi::TUN_ERR_NOT_SUPPORTED => Error::NotSupported,
        ffi::TUN_ERR_DEVICE_BUSY => Error::DeviceBusy,
        ffi::TUN_ERR_INVALID_ARGUMENT => Error::InvalidArgument,
        ffi::TUN_ERR_SYSTEM_RESOURCES => Error::SystemResources,
        ffi::TUN_ERR_WOULD_BLOCK => Error::WouldBlock,
        ffi::TUN_ERR_IO_ERROR => Error::IoError,
        ffi::TUN_ERR_SET_MTU_FAILED => Error::SetMtuFailed,
        ffi::TUN_ERR_SET_ADDRESS_FAILED => Error::SetAddressFailed,
        ffi::TUN_ERR_SET_STATE_FAILED => Error::SetStateFailed,
        ffi::TUN_ERR_ALREADY_CLOSED => Error::AlreadyClosed,
        ffi::TUN_ERR_WINTUN_NOT_FOUND => Error::WintunNotFound,
        ffi::TUN_ERR_WINTUN_INIT_FAILED => Error::WintunInitFailed,
        _ => Error::Unknown(code),
    }
}

pub type Result<T> = std::result::Result<T, Error>;

/// Thread-safe storage for initialization result.
static INIT_RESULT: OnceLock<i32> = OnceLock::new();

/// Initialize the TUN subsystem.
///
/// On Windows, this loads the Wintun driver.
/// On Unix systems, this is a no-op but should be called for portability.
///
/// This function is safe to call multiple times; initialization happens once.
pub fn init() -> Result<()> {
    let result = *INIT_RESULT.get_or_init(|| unsafe { ffi::tun_init() });

    if result == ffi::TUN_OK {
        Ok(())
    } else {
        Err(code_to_error(result))
    }
}

/// Cleanup the TUN subsystem.
///
/// On Windows, this unloads the Wintun driver.
pub fn deinit() {
    unsafe {
        ffi::tun_deinit();
    }
}

/// A TUN device.
///
/// Thread-safe via `Arc<Device>`. Uses `AtomicBool` for the closed flag
/// instead of `RwLock` to avoid deadlocking `close()` on a blocked `read()`.
///
/// The deadlock: `read_packet()` holds a read lock across a blocking kernel
/// `read()` syscall. `close()`/`drop()` needs the write lock to null out the
/// handle. Write lock waits for all read locks — but read can't return until
/// the fd is closed. Classic deadlock.
///
/// Fix: no lock. Use atomic flag + raw pointer. `close()` sets the flag then
/// closes the fd (unblocking readers). Readers check the flag after returning
/// from the syscall.
pub struct Device {
    handle: *mut ffi::TunHandle,
    closed: AtomicBool,
    name: String,
}

// SAFETY: The handle is only mutated by close() which is idempotent via AtomicBool.
// After close, all FFI calls return errors (EBADF). The pointer itself is never
// freed — the Zig library manages the underlying memory via tun_close.
unsafe impl Send for Device {}
unsafe impl Sync for Device {}

impl Device {
    /// Create a new TUN device.
    ///
    /// If `name` is `None`, the system will auto-assign a name.
    pub fn create(name: Option<&str>) -> Result<Self> {
        init()?;

        // Handle CString creation gracefully - null bytes in name would cause panic
        let c_name = match name {
            Some(s) => Some(CString::new(s).map_err(|_| Error::InvalidName)?),
            None => None,
        };
        let name_ptr = c_name.as_ref().map_or(std::ptr::null(), |s| s.as_ptr());

        let handle = unsafe { ffi::tun_create(name_ptr) };
        if handle.is_null() {
            return Err(Error::CreateFailed);
        }

        // Get the assigned name
        let dev_name = unsafe {
            let name_ptr = ffi::tun_get_name(handle);
            if name_ptr.is_null() {
                String::new()
            } else {
                CStr::from_ptr(name_ptr).to_string_lossy().into_owned()
            }
        };

        Ok(Device {
            handle,
            closed: AtomicBool::new(false),
            name: dev_name,
        })
    }

    /// Get the device name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Close the TUN device (shutdown).
    ///
    /// Closes the fd, which unblocks any blocked read/write. The device
    /// memory remains valid — Drop calls tun_destroy() to free it after
    /// the Device is no longer referenced.
    ///
    /// Safe to call concurrently with read/write. Idempotent.
    pub fn close(&self) {
        if self.closed.swap(true, Ordering::SeqCst) {
            return; // already closed
        }
        unsafe { ffi::tun_close(self.handle) };
    }

    /// Destroy the TUN device (free memory).
    ///
    /// The caller MUST ensure no concurrent read/write calls are in progress.
    /// Normally you don't call this directly — Drop handles it.
    pub fn destroy(&self) {
        unsafe { ffi::tun_destroy(self.handle) };
    }

    /// Get the underlying file descriptor (Unix) or HANDLE (Windows).
    pub fn raw_handle(&self) -> RawHandle {
        unsafe { ffi::tun_get_handle(self.handle) }
    }

    /// Get the MTU (Maximum Transmission Unit).
    pub fn mtu(&self) -> Result<i32> {
        if self.closed.load(Ordering::SeqCst) { return Err(Error::AlreadyClosed); }
        let mtu = unsafe { ffi::tun_get_mtu(self.handle) };
        if mtu < 0 { Err(code_to_error(mtu)) } else { Ok(mtu) }
    }

    /// Set the MTU. Requires root/admin privileges.
    pub fn set_mtu(&self, mtu: i32) -> Result<()> {
        if self.closed.load(Ordering::SeqCst) { return Err(Error::AlreadyClosed); }
        let rc = unsafe { ffi::tun_set_mtu(self.handle, mtu) };
        if rc == ffi::TUN_OK { Ok(()) } else { Err(code_to_error(rc)) }
    }

    /// Set non-blocking mode.
    pub fn set_nonblocking(&self, enabled: bool) -> Result<()> {
        if self.closed.load(Ordering::SeqCst) { return Err(Error::AlreadyClosed); }
        let flag = if enabled { 1 } else { 0 };
        let rc = unsafe { ffi::tun_set_nonblocking(self.handle, flag) };
        if rc == ffi::TUN_OK { Ok(()) } else { Err(code_to_error(rc)) }
    }

    /// Bring the interface up. Requires root/admin privileges.
    pub fn up(&self) -> Result<()> {
        if self.closed.load(Ordering::SeqCst) { return Err(Error::AlreadyClosed); }
        let rc = unsafe { ffi::tun_set_up(self.handle) };
        if rc == ffi::TUN_OK { Ok(()) } else { Err(code_to_error(rc)) }
    }

    /// Bring the interface down. Requires root/admin privileges.
    pub fn down(&self) -> Result<()> {
        if self.closed.load(Ordering::SeqCst) { return Err(Error::AlreadyClosed); }
        let rc = unsafe { ffi::tun_set_down(self.handle) };
        if rc == ffi::TUN_OK { Ok(()) } else { Err(code_to_error(rc)) }
    }

    /// Set IPv4 address and netmask. Requires root/admin privileges.
    pub fn set_ipv4(&self, addr: Ipv4Addr, netmask: Ipv4Addr) -> Result<()> {
        if self.closed.load(Ordering::SeqCst) { return Err(Error::AlreadyClosed); }
        let addr_str = CString::new(addr.to_string()).map_err(|_| Error::InvalidArgument)?;
        let mask_str = CString::new(netmask.to_string()).map_err(|_| Error::InvalidArgument)?;
        let rc = unsafe { ffi::tun_set_ipv4(self.handle, addr_str.as_ptr(), mask_str.as_ptr()) };
        if rc == ffi::TUN_OK { Ok(()) } else { Err(code_to_error(rc)) }
    }

    /// Set IPv6 address with prefix length. Requires root/admin privileges.
    pub fn set_ipv6(&self, addr: Ipv6Addr, prefix_len: i32) -> Result<()> {
        if self.closed.load(Ordering::SeqCst) { return Err(Error::AlreadyClosed); }
        if !(0..=128).contains(&prefix_len) { return Err(Error::InvalidArgument); }
        let addr_str = CString::new(addr.to_string()).map_err(|_| Error::InvalidArgument)?;
        let rc = unsafe { ffi::tun_set_ipv6(self.handle, addr_str.as_ptr(), prefix_len) };
        if rc == ffi::TUN_OK { Ok(()) } else { Err(code_to_error(rc)) }
    }

    /// Read a packet from the TUN device.
    pub fn read_packet(&self, buf: &mut [u8]) -> Result<usize> {
        if self.closed.load(Ordering::SeqCst) { return Err(Error::AlreadyClosed); }
        if buf.is_empty() { return Ok(0); }

        let n = unsafe { ffi::tun_read(self.handle, buf.as_mut_ptr() as *mut _, buf.len()) };
        if n < 0 {
            if self.closed.load(Ordering::SeqCst) { return Err(Error::AlreadyClosed); }
            Err(code_to_error(n as i32))
        } else {
            Ok(n as usize)
        }
    }

    /// Write a packet to the TUN device.
    pub fn write_packet(&self, buf: &[u8]) -> Result<usize> {
        if self.closed.load(Ordering::SeqCst) { return Err(Error::AlreadyClosed); }
        if buf.is_empty() { return Ok(0); }

        let n = unsafe { ffi::tun_write(self.handle, buf.as_ptr() as *const _, buf.len()) };
        if n < 0 {
            if self.closed.load(Ordering::SeqCst) { return Err(Error::AlreadyClosed); }
            Err(code_to_error(n as i32))
        } else {
            Ok(n as usize)
        }
    }
}

impl Drop for Device {
    fn drop(&mut self) {
        // Close fd if not already closed, then free memory.
        // Drop has &mut self, so no concurrent readers exist.
        self.close();
        unsafe { ffi::tun_destroy(self.handle) };
    }
}

impl Read for Device {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.read_packet(buf).map_err(Into::into)
    }
}

impl Write for Device {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.write_packet(buf).map_err(Into::into)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Returns true if the current process is NOT running with root/admin privileges.
    /// Used to skip tests that require elevated permissions.
    fn is_unprivileged() -> bool {
        #[cfg(unix)]
        {
            // Check if running as root using id -u command
            std::process::Command::new("id")
                .arg("-u")
                .output()
                .map(|o| {
                    String::from_utf8_lossy(&o.stdout)
                        .trim()
                        .parse::<u32>()
                        .unwrap_or(1)
                        != 0
                })
                .unwrap_or(true)
        }
        #[cfg(windows)]
        {
            // Check if running as Administrator using "net session"
            // This command only succeeds when run with admin privileges
            std::process::Command::new("net")
                .arg("session")
                .output()
                .map(|o| !o.status.success())
                .unwrap_or(true)
        }
    }

    #[test]
    fn test_create_close() {
        if is_unprivileged() {
            eprintln!("Skipping test: requires root privileges");
            return;
        }

        let device = Device::create(None).expect("failed to create TUN");
        println!("Created TUN device: {}", device.name());
        assert!(!device.name().is_empty());
    }

    #[test]
    fn test_mtu() {
        if is_unprivileged() {
            eprintln!("Skipping test: requires root privileges");
            return;
        }

        let device = Device::create(None).expect("failed to create TUN");
        let mtu = device.mtu().expect("failed to get MTU");
        println!("Default MTU: {}", mtu);
        assert!(mtu >= 576 && mtu <= 65535);
    }

    #[test]
    fn test_set_ipv4() {
        if is_unprivileged() {
            eprintln!("Skipping test: requires root privileges");
            return;
        }

        let device = Device::create(None).expect("failed to create TUN");
        device
            .set_ipv4(
                Ipv4Addr::new(10, 0, 100, 1),
                Ipv4Addr::new(255, 255, 255, 0),
            )
            .expect("failed to set IPv4");
        println!("TUN {} configured with IP 10.0.100.1/24", device.name());
    }

    #[test]
    fn test_nonblocking() {
        if is_unprivileged() {
            eprintln!("Skipping test: requires root privileges");
            return;
        }

        let device = Device::create(None).expect("failed to create TUN");
        device.set_nonblocking(true).expect("failed to enable nonblocking");
        device.set_nonblocking(false).expect("failed to disable nonblocking");
    }

    #[test]
    fn test_up_down() {
        if is_unprivileged() {
            eprintln!("Skipping test: requires root privileges");
            return;
        }

        let device = Device::create(None).expect("failed to create TUN");
        // Set IP first (required on some systems)
        let _ = device.set_ipv4(
            Ipv4Addr::new(10, 0, 101, 1),
            Ipv4Addr::new(255, 255, 255, 0),
        );
        device.up().expect("failed to bring up");
        device.down().expect("failed to bring down");
    }

    #[test]
    fn test_read_write_two_devices() {
        if is_unprivileged() {
            eprintln!("Skipping test: requires root privileges");
            return;
        }

        let dev1 = Device::create(None).expect("failed to create TUN 1");
        let dev2 = Device::create(None).expect("failed to create TUN 2");

        println!("Created TUN devices: {} and {}", dev1.name(), dev2.name());

        // Configure
        dev1.set_ipv4(Ipv4Addr::new(10, 0, 50, 1), Ipv4Addr::new(255, 255, 255, 0))
            .expect("failed to set IPv4 on dev1");
        dev2.set_ipv4(Ipv4Addr::new(10, 0, 51, 1), Ipv4Addr::new(255, 255, 255, 0))
            .expect("failed to set IPv4 on dev2");

        dev1.set_nonblocking(true).expect("failed to set nonblocking");
        dev2.set_nonblocking(true).expect("failed to set nonblocking");

        // Create ICMP packet
        let packet = make_icmp_echo_request(
            Ipv4Addr::new(10, 0, 50, 1),
            Ipv4Addr::new(10, 0, 51, 1),
        );

        // Write to dev1
        match dev1.write_packet(&packet) {
            Ok(n) => println!("Wrote {} bytes to {}", n, dev1.name()),
            Err(e) => println!("Write failed (expected without routing): {:?}", e),
        }

        // Try to read
        let mut buf = [0u8; 1500];
        match dev1.read_packet(&mut buf) {
            Ok(n) => println!("Read {} bytes from {}", n, dev1.name()),
            Err(Error::WouldBlock) => println!("No packet received (routing may not be configured)"),
            Err(e) => println!("Read error: {:?}", e),
        }
    }

    #[test]
    fn test_set_ipv6() {
        if is_unprivileged() {
            eprintln!("Skipping test: requires root privileges");
            return;
        }

        let device = Device::create(None).expect("failed to create TUN");
        device
            .set_ipv6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1), 64)
            .expect("failed to set IPv6");
        println!("TUN {} configured with IPv6 fd00::1/64", device.name());
    }

    #[test]
    fn test_read_write_ipv6() {
        if is_unprivileged() {
            eprintln!("Skipping test: requires root privileges");
            return;
        }

        let dev1 = Device::create(None).expect("failed to create TUN 1");
        let dev2 = Device::create(None).expect("failed to create TUN 2");

        println!("Created TUN devices: {} and {}", dev1.name(), dev2.name());

        // Configure IPv6
        dev1.set_ipv6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1), 64)
            .expect("failed to set IPv6 on dev1");
        dev2.set_ipv6(Ipv6Addr::new(0xfd00, 0, 0, 1, 0, 0, 0, 1), 64)
            .expect("failed to set IPv6 on dev2");

        dev1.set_nonblocking(true).expect("failed to set nonblocking");
        dev2.set_nonblocking(true).expect("failed to set nonblocking");

        // Create ICMPv6 Echo Request packet
        let packet = make_icmpv6_echo_request(
            Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1),
            Ipv6Addr::new(0xfd00, 0, 0, 1, 0, 0, 0, 1),
        );

        // Write to dev1
        match dev1.write_packet(&packet) {
            Ok(n) => println!("Wrote {} bytes (IPv6) to {}", n, dev1.name()),
            Err(e) => println!("Write failed (expected without routing): {:?}", e),
        }

        // Try to read
        let mut buf = [0u8; 1500];
        match dev1.read_packet(&mut buf) {
            Ok(n) => println!("Read {} bytes from {}", n, dev1.name()),
            Err(Error::WouldBlock) => println!("No packet received (routing may not be configured)"),
            Err(e) => println!("Read error: {:?}", e),
        }
    }

    fn make_icmpv6_echo_request(src: Ipv6Addr, dst: Ipv6Addr) -> Vec<u8> {
        let mut packet = vec![0u8; 48]; // IPv6 header (40) + ICMPv6 header (8)

        // IPv6 header
        packet[0] = 0x60; // Version 6
        packet[1] = 0x00;
        packet[2] = 0x00;
        packet[3] = 0x00;
        packet[4] = 0x00; // Payload length high
        packet[5] = 8;    // Payload length low (ICMPv6 = 8 bytes)
        packet[6] = 58;   // Next header: ICMPv6
        packet[7] = 64;   // Hop limit

        // Source address
        packet[8..24].copy_from_slice(&src.octets());
        // Destination address
        packet[24..40].copy_from_slice(&dst.octets());

        // ICMPv6 Echo Request
        packet[40] = 128; // Type: Echo Request
        packet[41] = 0;   // Code
        // Checksum placeholder (bytes 42-43)
        packet[44] = 0;   // Identifier high
        packet[45] = 1;   // Identifier low
        packet[46] = 0;   // Sequence high
        packet[47] = 1;   // Sequence low

        // Calculate ICMPv6 checksum (includes pseudo-header)
        let checksum = calculate_icmpv6_checksum(&src.octets(), &dst.octets(), &packet[40..]);
        packet[42..44].copy_from_slice(&checksum.to_be_bytes());

        packet
    }

    fn calculate_icmpv6_checksum(src: &[u8; 16], dst: &[u8; 16], icmp_data: &[u8]) -> u16 {
        let mut sum: u32 = 0;

        // Pseudo-header: src address
        for i in (0..16).step_by(2) {
            sum += ((src[i] as u32) << 8) | (src[i + 1] as u32);
        }
        // Pseudo-header: dst address
        for i in (0..16).step_by(2) {
            sum += ((dst[i] as u32) << 8) | (dst[i + 1] as u32);
        }
        // Pseudo-header: ICMPv6 length
        sum += icmp_data.len() as u32;
        // Pseudo-header: Next header (ICMPv6 = 58)
        sum += 58;

        // ICMPv6 data
        let mut i = 0;
        while i < icmp_data.len() - 1 {
            sum += ((icmp_data[i] as u32) << 8) | (icmp_data[i + 1] as u32);
            i += 2;
        }
        if icmp_data.len() % 2 == 1 {
            sum += (icmp_data[icmp_data.len() - 1] as u32) << 8;
        }

        while sum > 0xFFFF {
            sum = (sum >> 16) + (sum & 0xFFFF);
        }
        !sum as u16
    }

    fn make_icmp_echo_request(src: Ipv4Addr, dst: Ipv4Addr) -> Vec<u8> {
        let mut packet = vec![0u8; 28];

        // IP header
        packet[0] = 0x45; // Version 4, IHL 5
        packet[1] = 0x00; // TOS
        packet[2] = 0x00; // Total length high
        packet[3] = 28;   // Total length low
        packet[4] = 0x00; // ID high
        packet[5] = 0x01; // ID low
        packet[6] = 0x00; // Flags
        packet[7] = 0x00; // Fragment offset
        packet[8] = 64;   // TTL
        packet[9] = 1;    // Protocol (ICMP)
        packet[12..16].copy_from_slice(&src.octets());
        packet[16..20].copy_from_slice(&dst.octets());

        // IP checksum - use to_be_bytes for idiomatic byte conversion
        let ip_checksum = calculate_checksum(&packet[..20]);
        packet[10..12].copy_from_slice(&ip_checksum.to_be_bytes());

        // ICMP header
        packet[20] = 8;  // Type: Echo request
        packet[21] = 0;  // Code
        packet[24] = 0;  // ID high
        packet[25] = 1;  // ID low
        packet[26] = 0;  // Sequence high
        packet[27] = 1;  // Sequence low

        // ICMP checksum - use to_be_bytes for idiomatic byte conversion
        let icmp_checksum = calculate_checksum(&packet[20..]);
        packet[22..24].copy_from_slice(&icmp_checksum.to_be_bytes());

        packet
    }

    fn calculate_checksum(data: &[u8]) -> u16 {
        let mut sum: u32 = 0;

        // Process complete 16-bit words using iterator
        let mut chunks = data.chunks_exact(2);
        for chunk in &mut chunks {
            sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
        }

        // Handle odd byte (if any)
        if let Some(&last_byte) = chunks.remainder().first() {
            sum += (last_byte as u32) << 8;
        }

        // Fold 32-bit sum to 16 bits
        while sum > 0xFFFF {
            sum = (sum >> 16) + (sum & 0xFFFF);
        }

        !sum as u16
    }
}
