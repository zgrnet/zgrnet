//! Listener API — Handler Registry, Stream Header, and Listener SDK.
//!
//! The registry maps proto bytes to handler Unix sockets. When zgrnetd
//! receives a KCP stream, it looks up the proto and connects to the handler's
//! socket, forwarding the stream with a binary header (pubkey + proto + metadata).
//!
//! # Listener SDK
//!
//! External programs use [`Listener`] to register handlers with zgrnetd:
//!
//! ```rust,ignore
//! let listener = Listener::new("/run/zgrnet/control.sock")?;
//! let handler = listener.register(ListenerConfig { proto: 69, name: "proxy", mode: Mode::Stream })?;
//! loop {
//!     let (conn, meta) = handler.accept()?;
//!     // meta.remote_pubkey, meta.proto, meta.metadata
//! }
//! ```

use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::os::unix::net::UnixStream;
use std::sync::{atomic::{AtomicI64, Ordering}, Mutex};

/// Handler mode — stream (KCP) or dgram (raw UDP).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Stream,
    Dgram,
}

impl Mode {
    pub fn as_str(&self) -> &'static str {
        match self {
            Mode::Stream => "stream",
            Mode::Dgram => "dgram",
        }
    }
}

/// A registered protocol handler.
pub struct Handler {
    pub proto: u8,
    pub name: String,
    pub mode: Mode,
    pub target: String,
    pub sock: String,
    active: AtomicI64,
}

impl Handler {
    pub fn active(&self) -> i64 {
        self.active.load(Ordering::Relaxed)
    }

    pub fn add_active(&self, delta: i64) {
        self.active.fetch_add(delta, Ordering::Relaxed);
    }
}

/// JSON-friendly handler info.
pub struct HandlerInfo {
    pub proto: u8,
    pub name: String,
    pub mode: Mode,
    pub active: i64,
}

/// Handler Registry — maps proto bytes to handlers. Thread-safe.
///
/// Uses a single HashMap<u8, Handler> keyed by proto for O(1) lookup.
/// A secondary name→proto index enables unregister-by-name.
pub struct Registry {
    handlers: Mutex<HashMap<u8, Handler>>,
    names: Mutex<HashMap<String, u8>>,
    sock_dir: String,
}

impl Registry {
    pub fn new(sock_dir: &str) -> Self {
        Self {
            handlers: Mutex::new(HashMap::new()),
            names: Mutex::new(HashMap::new()),
            sock_dir: sock_dir.to_string(),
        }
    }

    pub fn register(&self, proto: u8, name: &str, mode: Mode, target: &str) -> Result<u8, String> {
        let mut handlers = self.handlers.lock().unwrap();
        let mut names = self.names.lock().unwrap();

        if handlers.contains_key(&proto) {
            return Err(format!("proto {} already registered", proto));
        }
        if names.contains_key(name) {
            return Err(format!("name {:?} already registered", name));
        }

        let sock = if target.is_empty() {
            format!("{}/{}.sock", self.sock_dir, name)
        } else {
            String::new()
        };

        handlers.insert(proto, Handler {
            proto,
            name: name.to_string(),
            mode,
            target: target.to_string(),
            sock,
            active: AtomicI64::new(0),
        });
        names.insert(name.to_string(), proto);

        Ok(proto)
    }

    pub fn unregister(&self, name: &str) -> Result<(), String> {
        let mut handlers = self.handlers.lock().unwrap();
        let mut names = self.names.lock().unwrap();

        let proto = names.remove(name)
            .ok_or_else(|| format!("handler {:?} not found", name))?;
        handlers.remove(&proto);

        Ok(())
    }

    pub fn lookup(&self, proto: u8) -> bool {
        let handlers = self.handlers.lock().unwrap();
        handlers.contains_key(&proto)
    }

    pub fn with_handler<F, R>(&self, proto: u8, f: F) -> Option<R>
    where
        F: FnOnce(&Handler) -> R,
    {
        let handlers = self.handlers.lock().unwrap();
        handlers.get(&proto).map(f)
    }

    pub fn list(&self) -> Vec<HandlerInfo> {
        let handlers = self.handlers.lock().unwrap();
        handlers.values().map(|h| HandlerInfo {
            proto: h.proto,
            name: h.name.clone(),
            mode: h.mode,
            active: h.active(),
        }).collect()
    }
}

// ════════════════════════════════════════════════════════════════════════
// Stream Header
// ════════════════════════════════════════════════════════════════════════

/// Minimum header size: 32 (pubkey) + 1 (proto) + 2 (metadata_len).
pub const STREAM_HEADER_SIZE: usize = 35;

/// Parsed stream header.
pub struct StreamMeta {
    pub remote_pubkey: [u8; 32],
    pub proto: u8,
    pub metadata: Vec<u8>,
}

/// Writes a stream header to the writer.
pub fn write_stream_header(w: &mut dyn Write, pubkey: &[u8; 32], proto: u8, metadata: &[u8]) -> io::Result<()> {
    let mut hdr = [0u8; STREAM_HEADER_SIZE];
    hdr[..32].copy_from_slice(pubkey);
    hdr[32] = proto;
    hdr[33] = (metadata.len() >> 8) as u8;
    hdr[34] = metadata.len() as u8;
    w.write_all(&hdr)?;
    if !metadata.is_empty() {
        w.write_all(metadata)?;
    }
    Ok(())
}

/// Reads a stream header from the reader.
pub fn read_stream_header(r: &mut dyn Read) -> io::Result<StreamMeta> {
    let mut hdr = [0u8; STREAM_HEADER_SIZE];
    r.read_exact(&mut hdr)?;

    let mut pubkey = [0u8; 32];
    pubkey.copy_from_slice(&hdr[..32]);
    let proto = hdr[32];
    let meta_len = ((hdr[33] as usize) << 8) | (hdr[34] as usize);

    let mut metadata = vec![0u8; meta_len];
    if meta_len > 0 {
        r.read_exact(&mut metadata)?;
    }

    Ok(StreamMeta {
        remote_pubkey: pubkey,
        proto,
        metadata,
    })
}

/// Connects to a handler's socket. Returns a boxed Read+Write trait object.
///
/// - Empty target → Unix socket at handler.sock (Mode A)
/// - `unix://` prefix → Unix socket at the given path
/// - `/` prefix → Unix socket (bare path)
/// - Otherwise → TCP connection (Mode B with TCP target)
pub fn connect_handler(handler: &Handler) -> io::Result<Box<dyn ReadWrite>> {
    let addr = if handler.target.is_empty() {
        &handler.sock
    } else {
        &handler.target
    };

    if addr.is_empty() {
        return Err(io::Error::other(format!("handler {:?} has no target or socket", handler.name)));
    }

    if addr.starts_with('/') {
        return Ok(Box::new(UnixStream::connect(addr)?));
    }

    if let Some(path) = addr.strip_prefix("unix://") {
        return Ok(Box::new(UnixStream::connect(path)?));
    }

    Ok(Box::new(TcpStream::connect(addr)?))
}

/// Trait alias for Read + Write + Send.
pub trait ReadWrite: Read + Write + Send {}
impl ReadWrite for UnixStream {}
impl ReadWrite for TcpStream {}

// ════════════════════════════════════════════════════════════════════════
// Listener SDK
// ════════════════════════════════════════════════════════════════════════

/// Configuration for registering a handler.
pub struct ListenerConfig {
    pub proto: u8,
    pub name: String,
    pub mode: Mode,
}

/// Listener SDK — connects to zgrnetd's control socket to register handlers.
pub struct Listener {
    control_addr: String,
}

impl Listener {
    pub fn new(control_addr: &str) -> Self {
        Self {
            control_addr: control_addr.to_string(),
        }
    }

    /// Register a handler with zgrnetd. Returns the socket path to listen on.
    pub fn register(&self, cfg: ListenerConfig) -> io::Result<String> {
        let mut conn = UnixStream::connect(&self.control_addr)?;

        let req = format!(
            r#"{{"proto":{},"name":"{}","mode":"{}"}}"#,
            cfg.proto, cfg.name, cfg.mode.as_str()
        );
        conn.write_all(req.as_bytes())?;
        conn.write_all(b"\n")?;

        let mut buf = vec![0u8; 4096];
        let n = conn.read(&mut buf)?;
        let resp = String::from_utf8_lossy(&buf[..n]);

        if resp.contains("\"error\"") && !resp.contains("\"error\":\"\"") {
            return Err(io::Error::other(resp.to_string()));
        }

        // Extract sock path from response (simple parse).
        if let Some(start) = resp.find("\"sock\":\"") {
            let rest = &resp[start + 8..];
            if let Some(end) = rest.find('"') {
                return Ok(rest[..end].to_string());
            }
        }

        Err(io::Error::other("no sock in response"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_registry_register_lookup() {
        let r = Registry::new("/tmp/test-handlers");
        let proto = r.register(69, "proxy", Mode::Stream, "").unwrap();
        assert_eq!(proto, 69);
        assert!(r.lookup(69));
        assert!(!r.lookup(70));
    }

    #[test]
    fn test_registry_duplicate() {
        let r = Registry::new("/tmp");
        r.register(69, "proxy", Mode::Stream, "").unwrap();
        assert!(r.register(69, "proxy2", Mode::Stream, "").is_err());
        assert!(r.register(70, "proxy", Mode::Stream, "").is_err());
    }

    #[test]
    fn test_registry_unregister() {
        let r = Registry::new("/tmp");
        r.register(69, "proxy", Mode::Stream, "").unwrap();
        r.unregister("proxy").unwrap();
        assert!(!r.lookup(69));
    }

    #[test]
    fn test_stream_header_roundtrip() {
        let pubkey = [0x42u8; 32];
        let metadata = b"hello world";

        let mut buf = Vec::new();
        write_stream_header(&mut buf, &pubkey, 69, metadata).unwrap();

        let meta = read_stream_header(&mut &buf[..]).unwrap();
        assert_eq!(meta.remote_pubkey, pubkey);
        assert_eq!(meta.proto, 69);
        assert_eq!(meta.metadata, metadata);
    }

    #[test]
    fn test_stream_header_empty_metadata() {
        let pubkey = [0x01u8; 32];

        let mut buf = Vec::new();
        write_stream_header(&mut buf, &pubkey, 128, &[]).unwrap();
        assert_eq!(buf.len(), STREAM_HEADER_SIZE);

        let meta = read_stream_header(&mut &buf[..]).unwrap();
        assert_eq!(meta.proto, 128);
        assert!(meta.metadata.is_empty());
    }
}
