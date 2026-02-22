//! UDP socket optimizations.
//!
//! Provides `SocketConfig` and `apply_socket_options()` to configure
//! SO_RCVBUF/SNDBUF, and on Linux: recvmmsg/sendmmsg, GRO/GSO, SO_BUSY_POLL.

use std::fmt;
use std::io;
use std::net::UdpSocket;

#[cfg(unix)]
use std::os::unix::io::AsRawFd;

pub const DEFAULT_RECV_BUF_SIZE: i32 = 4 * 1024 * 1024; // 4MB
pub const DEFAULT_SEND_BUF_SIZE: i32 = 4 * 1024 * 1024; // 4MB
pub const DEFAULT_BUSY_POLL_US: i32 = 50;
pub const DEFAULT_GSO_SEGMENT: i32 = 1400;
pub const DEFAULT_BATCH_SIZE: i32 = 64;

/// Configuration for UDP socket optimizations.
#[derive(Debug, Clone)]
pub struct SocketConfig {
    pub recv_buf_size: i32,
    pub send_buf_size: i32,
    pub busy_poll_us: i32,
    pub gro: bool,
}

impl Default for SocketConfig {
    fn default() -> Self {
        Self {
            recv_buf_size: DEFAULT_RECV_BUF_SIZE,
            send_buf_size: DEFAULT_SEND_BUF_SIZE,
            busy_poll_us: 0,
            gro: false,
        }
    }
}

impl SocketConfig {
    /// Returns a config with all optimizations enabled.
    pub fn full() -> Self {
        Self {
            recv_buf_size: DEFAULT_RECV_BUF_SIZE,
            send_buf_size: DEFAULT_SEND_BUF_SIZE,
            busy_poll_us: DEFAULT_BUSY_POLL_US,
            gro: true,
        }
    }
}

/// Result of a single optimization attempt.
pub struct OptimizationEntry {
    pub name: &'static str,
    pub applied: bool,
    pub detail: String,
    pub error: Option<io::Error>,
}

/// Collects results of all optimization attempts on a socket.
pub struct OptimizationReport {
    pub entries: Vec<OptimizationEntry>,
}

impl fmt::Display for OptimizationReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "[udp] socket optimizations:")?;
        for e in &self.entries {
            if e.applied {
                writeln!(f, "  {:<40} [ok]", e.detail)?;
            } else {
                let err_str = e
                    .error
                    .as_ref()
                    .map_or("unknown".to_string(), |e| e.to_string());
                writeln!(f, "  {:<40} [not available: {}]", e.name, err_str)?;
            }
        }
        Ok(())
    }
}

/// Apply all configured optimizations to a UDP socket.
/// Each optimization is tried independently; failures don't block others.
pub fn apply_socket_options(socket: &UdpSocket, cfg: &SocketConfig) -> OptimizationReport {
    let mut report = OptimizationReport {
        entries: Vec::new(),
    };

    #[cfg(unix)]
    {
        let fd = socket.as_raw_fd();

        let recv_buf = if cfg.recv_buf_size > 0 {
            cfg.recv_buf_size
        } else {
            DEFAULT_RECV_BUF_SIZE
        };
        match setsockopt_int(fd, libc::SOL_SOCKET, libc::SO_RCVBUF, recv_buf) {
            Ok(()) => {
                let actual = getsockopt_int(fd, libc::SOL_SOCKET, libc::SO_RCVBUF).unwrap_or(0);
                report.entries.push(OptimizationEntry {
                    name: "SO_RCVBUF",
                    applied: true,
                    detail: format!("SO_RCVBUF={} (actual={})", recv_buf, actual),
                    error: None,
                });
            }
            Err(e) => {
                report.entries.push(OptimizationEntry {
                    name: "SO_RCVBUF",
                    applied: false,
                    detail: String::new(),
                    error: Some(e),
                });
            }
        }

        let send_buf = if cfg.send_buf_size > 0 {
            cfg.send_buf_size
        } else {
            DEFAULT_SEND_BUF_SIZE
        };
        match setsockopt_int(fd, libc::SOL_SOCKET, libc::SO_SNDBUF, send_buf) {
            Ok(()) => {
                let actual = getsockopt_int(fd, libc::SOL_SOCKET, libc::SO_SNDBUF).unwrap_or(0);
                report.entries.push(OptimizationEntry {
                    name: "SO_SNDBUF",
                    applied: true,
                    detail: format!("SO_SNDBUF={} (actual={})", send_buf, actual),
                    error: None,
                });
            }
            Err(e) => {
                report.entries.push(OptimizationEntry {
                    name: "SO_SNDBUF",
                    applied: false,
                    detail: String::new(),
                    error: Some(e),
                });
            }
        }

        apply_platform_options(fd, cfg, &mut report);
    }

    #[cfg(not(unix))]
    {
        let _ = (socket, cfg);
    }

    report
}

#[cfg(unix)]
fn setsockopt_int(fd: i32, level: i32, optname: i32, value: i32) -> io::Result<()> {
    let ret = unsafe {
        libc::setsockopt(
            fd,
            level,
            optname,
            &value as *const i32 as *const libc::c_void,
            std::mem::size_of::<i32>() as libc::socklen_t,
        )
    };
    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(unix)]
fn getsockopt_int(fd: i32, level: i32, optname: i32) -> io::Result<i32> {
    let mut value: i32 = 0;
    let mut len = std::mem::size_of::<i32>() as libc::socklen_t;
    let ret = unsafe {
        libc::getsockopt(
            fd,
            level,
            optname,
            &mut value as *mut i32 as *mut libc::c_void,
            &mut len,
        )
    };
    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(value)
    }
}

#[cfg(target_os = "linux")]
const UDP_GRO: i32 = 104;
#[cfg(target_os = "linux")]
const UDP_SEGMENT: i32 = 103;

#[cfg(target_os = "linux")]
fn apply_platform_options(fd: i32, cfg: &SocketConfig, report: &mut OptimizationReport) {
    // SO_BUSY_POLL
    if cfg.busy_poll_us > 0 {
        match setsockopt_int(fd, libc::SOL_SOCKET, libc::SO_BUSY_POLL, cfg.busy_poll_us) {
            Ok(()) => {
                report.entries.push(OptimizationEntry {
                    name: "SO_BUSY_POLL",
                    applied: true,
                    detail: format!("SO_BUSY_POLL={}μs", cfg.busy_poll_us),
                    error: None,
                });
            }
            Err(e) => {
                report.entries.push(OptimizationEntry {
                    name: "SO_BUSY_POLL",
                    applied: false,
                    detail: String::new(),
                    error: Some(e),
                });
            }
        }
    }

    // UDP_GRO
    if cfg.gro {
        match setsockopt_int(fd, libc::IPPROTO_UDP, UDP_GRO, 1) {
            Ok(()) => {
                report.entries.push(OptimizationEntry {
                    name: "UDP_GRO",
                    applied: true,
                    detail: "UDP_GRO=1".to_string(),
                    error: None,
                });
            }
            Err(e) => {
                report.entries.push(OptimizationEntry {
                    name: "UDP_GRO",
                    applied: false,
                    detail: String::new(),
                    error: Some(e),
                });
            }
        }
    }
}

/// Check if UDP_SEGMENT (GSO) is available on a socket.
/// Probes by setting and immediately clearing the option to avoid side effects.
#[cfg(target_os = "linux")]
pub fn gso_supported(fd: i32) -> bool {
    if setsockopt_int(fd, libc::IPPROTO_UDP, UDP_SEGMENT, DEFAULT_GSO_SEGMENT).is_ok() {
        let _ = setsockopt_int(fd, libc::IPPROTO_UDP, UDP_SEGMENT, 0);
        true
    } else {
        false
    }
}

/// Batch reader using recvmmsg on Linux.
#[cfg(target_os = "linux")]
pub mod batch {
    use std::io;
    use std::mem;
    use std::net::{SocketAddr, SocketAddrV4, Ipv4Addr};

    pub const DEFAULT_BATCH_SIZE: usize = 64;

    pub struct RecvResult {
        pub n: usize,
        pub from: SocketAddr,
    }

    pub struct BatchReader {
        fd: i32,
        batch_size: usize,
        msgs: Vec<libc::mmsghdr>,
        iovecs: Vec<libc::iovec>,
        addrs: Vec<libc::sockaddr_in>,
    }

    impl BatchReader {
        pub fn new(fd: i32, batch_size: usize) -> Self {
            Self {
                fd,
                batch_size,
                msgs: vec![unsafe { mem::zeroed() }; batch_size],
                iovecs: vec![unsafe { mem::zeroed() }; batch_size],
                addrs: vec![unsafe { mem::zeroed() }; batch_size],
            }
        }

        /// Read up to batch_size packets using recvmmsg.
        /// Returns the number of packets received.
        pub fn read_batch(&mut self, buffers: &mut [&mut [u8]]) -> io::Result<Vec<RecvResult>> {
            let count = buffers.len().min(self.batch_size);

            for (i, buf) in buffers[..count].iter_mut().enumerate() {
                self.iovecs[i] = libc::iovec {
                    iov_base: buf.as_mut_ptr() as *mut libc::c_void,
                    iov_len: buf.len(),
                };
                self.addrs[i] = unsafe { mem::zeroed() };
                self.msgs[i].msg_hdr = libc::msghdr {
                    msg_name: &mut self.addrs[i] as *mut _ as *mut libc::c_void,
                    msg_namelen: mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
                    msg_iov: &mut self.iovecs[i],
                    msg_iovlen: 1,
                    msg_control: std::ptr::null_mut(),
                    msg_controllen: 0,
                    msg_flags: 0,
                };
                self.msgs[i].msg_len = 0;
            }

            let n = unsafe {
                libc::recvmmsg(
                    self.fd,
                    self.msgs.as_mut_ptr(),
                    count as libc::c_uint,
                    0,
                    std::ptr::null_mut(),
                )
            };
            if n < 0 {
                return Err(io::Error::last_os_error());
            }

            let mut results = Vec::with_capacity(n as usize);
            for i in 0..n as usize {
                let addr = &self.addrs[i];
                let ip = Ipv4Addr::from(u32::from_be(addr.sin_addr.s_addr));
                let port = u16::from_be(addr.sin_port);
                results.push(RecvResult {
                    n: self.msgs[i].msg_len as usize,
                    from: SocketAddr::V4(SocketAddrV4::new(ip, port)),
                });
            }
            Ok(results)
        }
    }

    pub struct BatchWriter {
        fd: i32,
        batch_size: usize,
        msgs: Vec<libc::mmsghdr>,
        iovecs: Vec<libc::iovec>,
        addrs: Vec<libc::sockaddr_in>,
    }

    impl BatchWriter {
        pub fn new(fd: i32, batch_size: usize) -> Self {
            Self {
                fd,
                batch_size,
                msgs: vec![unsafe { mem::zeroed() }; batch_size],
                iovecs: vec![unsafe { mem::zeroed() }; batch_size],
                addrs: vec![unsafe { mem::zeroed() }; batch_size],
            }
        }

        /// Write multiple packets using sendmmsg.
        /// Only IPv4 targets are supported; non-IPv4 entries are skipped.
        pub fn write_batch(
            &mut self,
            buffers: &[&[u8]],
            targets: &[SocketAddr],
        ) -> io::Result<usize> {
            let input_count = buffers.len().min(self.batch_size).min(targets.len());
            let mut valid = 0usize;

            for (buf, target) in buffers[..input_count].iter().zip(targets[..input_count].iter()) {
                let v4 = match *target {
                    SocketAddr::V4(v4) => v4,
                    _ => continue,
                };

                self.iovecs[valid] = libc::iovec {
                    iov_base: buf.as_ptr() as *mut libc::c_void,
                    iov_len: buf.len(),
                };
                self.addrs[valid].sin_family = libc::AF_INET as libc::sa_family_t;
                self.addrs[valid].sin_port = v4.port().to_be();
                self.addrs[valid].sin_addr = libc::in_addr {
                    s_addr: u32::from(*v4.ip()).to_be(),
                };
                self.msgs[valid].msg_hdr = libc::msghdr {
                    msg_name: &mut self.addrs[valid] as *mut _ as *mut libc::c_void,
                    msg_namelen: mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
                    msg_iov: &mut self.iovecs[valid],
                    msg_iovlen: 1,
                    msg_control: std::ptr::null_mut(),
                    msg_controllen: 0,
                    msg_flags: 0,
                };
                valid += 1;
            }

            if valid == 0 {
                return Ok(0);
            }

            let n = unsafe {
                libc::sendmmsg(
                    self.fd,
                    self.msgs.as_mut_ptr(),
                    valid as libc::c_uint,
                    0,
                )
            };
            if n < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(n as usize)
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::net::UdpSocket;
        use std::os::unix::io::AsRawFd;

        #[test]
        fn test_batch_reader_writer() {
            let receiver = UdpSocket::bind("127.0.0.1:0").unwrap();
            let recv_addr = receiver.local_addr().unwrap();

            let sender = UdpSocket::bind("127.0.0.1:0").unwrap();
            let sender_fd = sender.as_raw_fd();

            let mut writer = BatchWriter::new(sender_fd, DEFAULT_BATCH_SIZE);

            let msg1 = b"hello batch 1";
            let msg2 = b"hello batch 2";
            let msg3 = b"hello batch 3";
            let bufs: Vec<&[u8]> = vec![msg1, msg2, msg3];
            let addrs = vec![recv_addr; 3];

            let sent = writer.write_batch(&bufs, &addrs).unwrap();
            assert_eq!(sent, 3);

            let recv_fd = receiver.as_raw_fd();
            let mut reader = BatchReader::new(recv_fd, DEFAULT_BATCH_SIZE);

            let mut buf1 = [0u8; 256];
            let mut buf2 = [0u8; 256];
            let mut buf3 = [0u8; 256];
            let mut buffers: Vec<&mut [u8]> = vec![&mut buf1, &mut buf2, &mut buf3];

            std::thread::sleep(std::time::Duration::from_millis(50));
            let results = reader.read_batch(&mut buffers).unwrap();
            assert!(results.len() >= 1, "expected at least 1 packet, got 0");

            let mut total_bytes = 0;
            for r in &results {
                total_bytes += r.n;
            }
            assert!(total_bytes > 0);
        }
    }
}

#[cfg(all(unix, not(target_os = "linux")))]
fn apply_platform_options(_fd: i32, _cfg: &SocketConfig, _report: &mut OptimizationReport) {}

/// Create a UDP socket with SO_REUSEPORT set, bound to the given address.
/// Multiple sockets can bind to the same address for kernel load balancing.
#[cfg(unix)]
pub fn bind_reuseport(addr: &str) -> io::Result<UdpSocket> {
    use std::os::unix::io::FromRawFd;

    let bind_addr: std::net::SocketAddr = addr
        .parse()
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;

    let domain = if bind_addr.is_ipv4() {
        libc::AF_INET
    } else {
        libc::AF_INET6
    };

    #[cfg(target_os = "linux")]
    let sock_flags = libc::SOCK_DGRAM | libc::SOCK_CLOEXEC;
    #[cfg(not(target_os = "linux"))]
    let sock_flags = libc::SOCK_DGRAM;

    let fd = unsafe { libc::socket(domain, sock_flags, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }

    if let Err(e) = setsockopt_int(fd, libc::SOL_SOCKET, libc::SO_REUSEPORT, 1) {
        unsafe { libc::close(fd) };
        return Err(e);
    }

    let mut sa_storage: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    let sa_len: libc::socklen_t;

    match bind_addr {
        std::net::SocketAddr::V4(v4) => {
            sa_storage.sin_family = libc::AF_INET as libc::sa_family_t;
            sa_storage.sin_port = v4.port().to_be();
            sa_storage.sin_addr = libc::in_addr {
                s_addr: u32::from(*v4.ip()).to_be(),
            };
            sa_len = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
        }
        _ => {
            unsafe { libc::close(fd) };
            return Err(io::Error::new(io::ErrorKind::Unsupported, "IPv6 not implemented"));
        }
    }

    let ret = unsafe {
        libc::bind(
            fd,
            &sa_storage as *const libc::sockaddr_in as *const libc::sockaddr,
            sa_len,
        )
    };
    if ret < 0 {
        let e = io::Error::last_os_error();
        unsafe { libc::close(fd) };
        return Err(e);
    }

    Ok(unsafe { UdpSocket::from_raw_fd(fd) })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_socket_buffer_size_set_and_verify() {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let cfg = SocketConfig::default();
        let report = apply_socket_options(&socket, &cfg);

        for e in &report.entries {
            assert!(e.applied, "{} not applied: {:?}", e.name, e.error);
        }

        // Verify getsockopt returns a non-zero value. The actual value may be
        // less than requested due to kernel limits (net.core.rmem_max on Linux
        // defaults to ~208KB in CI containers).
        #[cfg(unix)]
        {
            let fd = socket.as_raw_fd();
            let actual_rcv = getsockopt_int(fd, libc::SOL_SOCKET, libc::SO_RCVBUF).unwrap();
            assert!(actual_rcv > 0, "SO_RCVBUF should be > 0, got {}", actual_rcv);

            let actual_snd = getsockopt_int(fd, libc::SOL_SOCKET, libc::SO_SNDBUF).unwrap();
            assert!(actual_snd > 0, "SO_SNDBUF should be > 0, got {}", actual_snd);
        }
    }

    #[test]
    fn test_socket_buffer_custom_values() {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let cfg = SocketConfig {
            recv_buf_size: 2 * 1024 * 1024,
            send_buf_size: 1 * 1024 * 1024,
            ..Default::default()
        };
        let report = apply_socket_options(&socket, &cfg);

        for e in &report.entries {
            assert!(e.applied, "{} not applied: {:?}", e.name, e.error);
        }
    }

    #[test]
    fn test_optimization_report_display() {
        let report = OptimizationReport {
            entries: vec![
                OptimizationEntry {
                    name: "SO_RCVBUF",
                    applied: true,
                    detail: "SO_RCVBUF=4194304 (actual=8388608)".to_string(),
                    error: None,
                },
                OptimizationEntry {
                    name: "SO_SNDBUF",
                    applied: true,
                    detail: "SO_SNDBUF=4194304 (actual=8388608)".to_string(),
                    error: None,
                },
            ],
        };
        let s = format!("{}", report);
        assert!(s.contains("[ok]"));
        assert!(s.contains("SO_RCVBUF"));
    }

    #[test]
    #[cfg(unix)]
    fn test_reuseport_multiple_bind() {
        let sock1 = super::bind_reuseport("127.0.0.1:0").unwrap();
        let addr = sock1.local_addr().unwrap();

        let sock2 = super::bind_reuseport(&addr.to_string()).unwrap();
        let sock3 = super::bind_reuseport(&addr.to_string()).unwrap();
        let sock4 = super::bind_reuseport(&addr.to_string()).unwrap();

        assert_eq!(sock2.local_addr().unwrap().port(), addr.port());
        assert_eq!(sock3.local_addr().unwrap().port(), addr.port());
        assert_eq!(sock4.local_addr().unwrap().port(), addr.port());
    }

    #[test]
    fn test_default_config() {
        let cfg = SocketConfig::default();
        assert_eq!(cfg.recv_buf_size, DEFAULT_RECV_BUF_SIZE);
        assert_eq!(cfg.send_buf_size, DEFAULT_SEND_BUF_SIZE);
        assert_eq!(cfg.busy_poll_us, 0);
        assert!(!cfg.gro);
    }

    #[test]
    fn test_full_config_apply_all() {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let cfg = SocketConfig::full();
        let report = apply_socket_options(&socket, &cfg);

        // SO_RCVBUF and SO_SNDBUF must always succeed
        for e in &report.entries {
            if (e.name == "SO_RCVBUF" || e.name == "SO_SNDBUF") && !e.applied {
                panic!("{} should be applied: {:?}", e.name, e.error);
            }
        }
        println!("{}", report);
    }

    #[test]
    fn test_graceful_degradation() {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let cfg = SocketConfig::full();
        let _ = apply_socket_options(&socket, &cfg);

        // Basic send/recv must work regardless of which optimizations applied
        let peer = UdpSocket::bind("127.0.0.1:0").unwrap();
        let peer_addr = peer.local_addr().unwrap();

        socket.send_to(b"graceful-test", peer_addr).unwrap();

        peer.set_read_timeout(Some(std::time::Duration::from_secs(1)))
            .unwrap();
        let mut buf = [0u8; 256];
        let (n, _) = peer.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"graceful-test");
    }
}
