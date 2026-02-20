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
    pub reuse_port: bool,
    pub busy_poll_us: i32,
    pub gro: bool,
    pub gso_segment: i32,
    pub batch_size: i32,
}

impl Default for SocketConfig {
    fn default() -> Self {
        Self {
            recv_buf_size: DEFAULT_RECV_BUF_SIZE,
            send_buf_size: DEFAULT_SEND_BUF_SIZE,
            reuse_port: false,
            busy_poll_us: 0,
            gro: false,
            gso_segment: 0,
            batch_size: 0,
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
fn apply_platform_options(_fd: i32, _cfg: &SocketConfig, _report: &mut OptimizationReport) {
    // Linux-specific optimizations added in later phases:
    // Phase 2: recvmmsg/sendmmsg (batch_size)
    // Phase 4: UDP_GRO / UDP_GSO (gro, gso_segment)
    // Phase 5: SO_BUSY_POLL (busy_poll_us)
}

#[cfg(all(unix, not(target_os = "linux")))]
fn apply_platform_options(_fd: i32, _cfg: &SocketConfig, _report: &mut OptimizationReport) {}

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

        #[cfg(unix)]
        {
            let fd = socket.as_raw_fd();
            let actual_rcv = getsockopt_int(fd, libc::SOL_SOCKET, libc::SO_RCVBUF).unwrap();
            assert!(
                actual_rcv >= DEFAULT_RECV_BUF_SIZE,
                "SO_RCVBUF: expected >= {}, got {}",
                DEFAULT_RECV_BUF_SIZE,
                actual_rcv
            );

            let actual_snd = getsockopt_int(fd, libc::SOL_SOCKET, libc::SO_SNDBUF).unwrap();
            assert!(
                actual_snd >= DEFAULT_SEND_BUF_SIZE,
                "SO_SNDBUF: expected >= {}, got {}",
                DEFAULT_SEND_BUF_SIZE,
                actual_snd
            );
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
    fn test_default_config() {
        let cfg = SocketConfig::default();
        assert_eq!(cfg.recv_buf_size, DEFAULT_RECV_BUF_SIZE);
        assert_eq!(cfg.send_buf_size, DEFAULT_SEND_BUF_SIZE);
        assert!(!cfg.reuse_port);
        assert_eq!(cfg.busy_poll_us, 0);
        assert!(!cfg.gro);
    }
}
