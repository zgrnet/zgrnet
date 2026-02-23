//! Unified UDP networking layer for zgrnet.
//!
//! Provides a single `UDP` type that manages multiple peers, handles
//! Noise Protocol handshakes, and supports roaming.

use crate::noise::{
    Key, KeyPair, KEY_SIZE,
    Config as HandshakeConfig, HandshakeState, Pattern,
    build_handshake_init, build_handshake_resp, build_transport_message,
    parse_handshake_init, parse_handshake_resp, parse_transport_message,
    MAX_PACKET_SIZE, generate_index, Session, SessionConfig,
    message, encode_payload, decode_payload,
};
use crate::kcp::{Mux, MuxConfig, Stream as KcpStream};
use crate::relay;

use crossbeam_channel::{bounded, Receiver, Sender};
use std::collections::HashMap;
use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};
use std::thread;
use tokio::time as tokio_time;

/// Peer connection state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerState {
    /// Newly registered peer.
    New,
    /// Performing handshake.
    Connecting,
    /// Session established.
    Established,
    /// Connection failed.
    Failed,
}

impl std::fmt::Display for PeerState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PeerState::New => write!(f, "new"),
            PeerState::Connecting => write!(f, "connecting"),
            PeerState::Established => write!(f, "established"),
            PeerState::Failed => write!(f, "failed"),
        }
    }
}

/// Information about the local host.
#[derive(Debug, Clone)]
pub struct HostInfo {
    pub public_key: Key,
    pub addr: SocketAddr,
    pub peer_count: usize,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub last_seen: Option<Instant>,
}

/// Information about a peer.
#[derive(Debug, Clone)]
pub struct PeerInfo {
    pub public_key: Key,
    pub endpoint: Option<SocketAddr>,
    pub state: PeerState,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub last_seen: Option<Instant>,
}

/// A peer with its info.
#[derive(Debug)]
pub struct Peer {
    pub info: PeerInfo,
}

/// Errors from UDP operations.
#[derive(Debug)]
pub enum UdpError {
    /// UDP socket is closed.
    Closed,
    /// Peer not found.
    PeerNotFound,
    /// Peer has no endpoint.
    NoEndpoint,
    /// Peer has no established session.
    NoSession,
    /// Handshake failed.
    HandshakeFailed,
    /// Handshake timeout.
    HandshakeTimeout,
    /// IO error.
    Io(io::Error),
    /// Session error.
    Session(String),
}

impl std::fmt::Display for UdpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UdpError::Closed => write!(f, "udp closed"),
            UdpError::PeerNotFound => write!(f, "peer not found"),
            UdpError::NoEndpoint => write!(f, "peer has no endpoint"),
            UdpError::NoSession => write!(f, "peer has no established session"),
            UdpError::HandshakeFailed => write!(f, "handshake failed"),
            UdpError::HandshakeTimeout => write!(f, "handshake timeout"),
            UdpError::Io(e) => write!(f, "io error: {}", e),
            UdpError::Session(e) => write!(f, "session error: {}", e),
        }
    }
}

impl std::error::Error for UdpError {}

impl From<io::Error> for UdpError {
    fn from(e: io::Error) -> Self {
        UdpError::Io(e)
    }
}

pub type Result<T> = std::result::Result<T, UdpError>;

/// Internal peer state.
struct PeerStateInternal {
    pk: Key,
    endpoint: Option<SocketAddr>,
    session: Option<Session>,
    state: PeerState,
    rx_bytes: u64,
    tx_bytes: u64,
    last_seen: Option<Instant>,

    // KCP stream multiplexing (initialized when session is established)
    mux: Option<Arc<Mux>>,
    accept_tx: Option<Sender<Arc<KcpStream>>>,
    accept_rx: Option<Receiver<Arc<KcpStream>>>,
}

/// Pending handshake tracking.
struct PendingHandshake {
    peer_pk: Key,
    hs_state: HandshakeState,
    local_idx: u32,
    done: std::sync::mpsc::Sender<Result<()>>,
    #[allow(dead_code)] // TODO: implement timeout logic
    created_at: Instant,
}

/// Options for creating a UDP instance.
#[derive(Default)]
pub struct UdpOptions {
    /// Address to bind to. Default is "0.0.0.0:0".
    pub bind_addr: Option<String>,
    /// Allow connections from unknown peers.
    pub allow_unknown: bool,
    /// Socket configuration (buffer sizes, GSO, GRO, busy-poll).
    /// If None, uses default configuration.
    pub socket_config: Option<super::sockopt::SocketConfig>,
}

impl UdpOptions {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn bind_addr(mut self, addr: &str) -> Self {
        self.bind_addr = Some(addr.to_string());
        self
    }

    pub fn allow_unknown(mut self, allow: bool) -> Self {
        self.allow_unknown = allow;
        self
    }
}

/// UDP-based network using the Noise Protocol.
///
/// Manages multiple peers, handles handshakes, and supports roaming.
pub struct UDP {
    socket: UdpSocket,
    local_key: KeyPair,
    allow_unknown: bool,
    socket_config: super::sockopt::SocketConfig,

    // Relay routing and forwarding
    route_table: RwLock<Option<Arc<relay::RouteTable>>>,
    local_metrics: Mutex<relay::NodeMetrics>,

    // Peer management
    peers: RwLock<HashMap<Key, Arc<Mutex<PeerStateInternal>>>>,
    by_index: RwLock<HashMap<u32, Key>>,

    // Pending handshakes (as initiator)
    pending: Mutex<HashMap<u32, PendingHandshake>>,

    // Statistics
    total_rx: AtomicU64,
    total_tx: AtomicU64,
    last_seen: Mutex<Option<Instant>>,

    // State
    closed: AtomicBool,
}

impl UDP {
    /// Creates a new UDP network.
    pub fn new(key: KeyPair, opts: UdpOptions) -> Result<Self> {
        let bind_addr = opts.bind_addr.as_deref().unwrap_or("0.0.0.0:0");
        let socket = UdpSocket::bind(bind_addr)?;

        // Apply socket configuration (user-provided or default)
        let socket_config = opts.socket_config.unwrap_or_default();
        super::sockopt::apply_socket_options(&socket, &socket_config);

        // Set read timeout for non-blocking behavior in receive loop
        socket.set_read_timeout(Some(Duration::from_millis(500)))?;

        Ok(Self {
            socket,
            local_key: key,
            allow_unknown: opts.allow_unknown,
            socket_config,
            route_table: RwLock::new(None),
            local_metrics: Mutex::new(relay::NodeMetrics::default()),
            peers: RwLock::new(HashMap::new()),
            by_index: RwLock::new(HashMap::new()),
            pending: Mutex::new(HashMap::new()),
            total_rx: AtomicU64::new(0),
            total_tx: AtomicU64::new(0),
            last_seen: Mutex::new(None),
            closed: AtomicBool::new(false),
        })
    }

    /// Sets the relay router for forwarding relay packets.
    /// Deprecated: Use set_route_table instead.
    pub fn set_router(&self, _router: Box<dyn relay::Router + Send + Sync>) {
        // No-op — use set_route_table
    }

    /// Sets the route table for relay forwarding and outbound wrapping.
    pub fn set_route_table(&self, rt: Arc<relay::RouteTable>) {
        *self.route_table.write().unwrap() = Some(rt);
    }

    /// Returns the current route table.
    pub fn route_table(&self) -> Option<Arc<relay::RouteTable>> {
        self.route_table.read().unwrap().clone()
    }

    /// Updates the local node metrics for PONG responses.
    pub fn set_local_metrics(&self, metrics: relay::NodeMetrics) {
        *self.local_metrics.lock().unwrap() = metrics;
    }

    /// Sets or updates a peer's endpoint address.
    pub fn set_peer_endpoint(&self, pk: Key, endpoint: SocketAddr) {
        if self.closed.load(Ordering::SeqCst) {
            return;
        }

        let mut peers = self.peers.write().unwrap();
        if let Some(peer) = peers.get(&pk) {
            let mut p = peer.lock().unwrap();
            p.endpoint = Some(endpoint);
        } else {
            peers.insert(
                pk,
                Arc::new(Mutex::new(PeerStateInternal {
                    pk,
                    endpoint: Some(endpoint),
                    session: None,
                    state: PeerState::New,
                    rx_bytes: 0,
                    tx_bytes: 0,
                    last_seen: None,
                    mux: None,
                    accept_tx: None,
                    accept_rx: None,
                })),
            );
        }
    }

    /// Removes a peer.
    pub fn remove_peer(&self, pk: &Key) {
        let mut peers = self.peers.write().unwrap();
        if let Some(peer) = peers.remove(pk) {
            let p = peer.lock().unwrap();
            if let Some(ref session) = p.session {
                let mut by_index = self.by_index.write().unwrap();
                by_index.remove(&session.local_index());
            }
        }
    }

    /// Returns information about the local host.
    pub fn host_info(&self) -> HostInfo {
        let peers = self.peers.read().unwrap();
        let last_seen = self.last_seen.lock().unwrap();

        HostInfo {
            public_key: self.local_key.public,
            addr: self.socket.local_addr().unwrap_or_else(|_| "0.0.0.0:0".parse().unwrap()),
            peer_count: peers.len(),
            rx_bytes: self.total_rx.load(Ordering::SeqCst),
            tx_bytes: self.total_tx.load(Ordering::SeqCst),
            last_seen: *last_seen,
        }
    }

    /// Returns information about a specific peer.
    pub fn peer_info(&self, pk: &Key) -> Option<PeerInfo> {
        let peers = self.peers.read().unwrap();
        peers.get(pk).map(|peer| {
            let p = peer.lock().unwrap();
            PeerInfo {
                public_key: p.pk,
                endpoint: p.endpoint,
                state: p.state,
                rx_bytes: p.rx_bytes,
                tx_bytes: p.tx_bytes,
                last_seen: p.last_seen,
            }
        })
    }

    /// Returns an iterator over all peers.
    pub fn peers(&self) -> Vec<Peer> {
        let peers = self.peers.read().unwrap();
        peers
            .values()
            .map(|peer| {
                let p = peer.lock().unwrap();
                Peer {
                    info: PeerInfo {
                        public_key: p.pk,
                        endpoint: p.endpoint,
                        state: p.state,
                        rx_bytes: p.rx_bytes,
                        tx_bytes: p.tx_bytes,
                        last_seen: p.last_seen,
                    },
                }
            })
            .collect()
    }

    /// Sends encrypted data to a peer using the default CHAT protocol byte.
    pub fn write_to(&self, pk: &Key, data: &[u8]) -> Result<()> {
        self.write_to_protocol(pk, message::protocol::CHAT, data)
    }

    /// Sends encrypted data to a peer with a specific protocol byte.
    ///
    /// The protocol byte is prepended to the data before encryption,
    /// matching the wire format: `protocol(1) + payload`.
    pub fn write_to_protocol(&self, pk: &Key, protocol: u8, data: &[u8]) -> Result<()> {
        if self.closed.load(Ordering::SeqCst) {
            return Err(UdpError::Closed);
        }

        let peers = self.peers.read().unwrap();
        let peer = peers.get(pk).ok_or(UdpError::PeerNotFound)?;
        let mut p = peer.lock().unwrap();

        let endpoint = p.endpoint.ok_or(UdpError::NoEndpoint)?;
        let session = p.session.as_mut().ok_or(UdpError::NoSession)?;

        // Encode payload with protocol byte
        let payload = encode_payload(protocol, data);

        // Encrypt the data
        let (ciphertext, nonce) = session
            .encrypt(&payload)
            .map_err(|e| UdpError::Session(e.to_string()))?;

        // Build transport message
        let msg = build_transport_message(session.remote_index(), nonce, &ciphertext);

        // Use GSO for large messages if enabled (Linux only)
        let n = if self.socket_config.gso && msg.len() > super::sockopt::DEFAULT_GSO_SEGMENT as usize {
            self.send_to_gso(&msg, endpoint)?
        } else {
            self.socket.send_to(&msg, endpoint)?
        };

        // Update stats
        self.total_tx.fetch_add(n as u64, Ordering::SeqCst);
        p.tx_bytes += n as u64;

        Ok(())
    }

    /// Sends a message using GSO (Generic Segmentation Offload).
    /// Uses sendmsg with UDP_SEGMENT cmsg to enable per-send segmentation.
    /// Only works on Linux 4.18+ with supported NICs.
    #[cfg(target_os = "linux")]
    fn send_to_gso(&self, data: &[u8], addr: SocketAddr) -> io::Result<usize> {
        use std::os::unix::io::AsRawFd;
        use std::ptr;
        use std::mem;

        let fd = self.socket.as_raw_fd();
        let segment_size: u16 = super::sockopt::DEFAULT_GSO_SEGMENT as u16;

        // Prepare iovec
        let iov = libc::iovec {
            iov_base: data.as_ptr() as *mut libc::c_void,
            iov_len: data.len(),
        };

        // Prepare cmsg buffer: cmsghdr + u16 segment size
        let cmsg_space = unsafe { libc::CMSG_SPACE(mem::size_of::<u16>() as u32) } as usize;
        let mut cmsg_buf = vec![0u8; cmsg_space];

        // Fill cmsg header directly (cmsg_buf starts with cmsghdr)
        // This avoids the incorrect CMSG_FIRSTHDR usage on Vec<u8>
        let cmsg_hdr = cmsg_buf.as_mut_ptr() as *mut libc::cmsghdr;
        unsafe {
            (*cmsg_hdr).cmsg_level = libc::IPPROTO_UDP;
            (*cmsg_hdr).cmsg_type = super::sockopt::UDP_SEGMENT;
            (*cmsg_hdr).cmsg_len = libc::CMSG_LEN(mem::size_of::<u16>() as u32) as usize;

            // Write segment size into cmsg data area
            let data_ptr = libc::CMSG_DATA(cmsg_hdr) as *mut u16;
            ptr::write_unaligned(data_ptr, segment_size);
        }

        // Prepare sockaddr
        let (sockaddr, sockaddr_len): (mem::MaybeUninit<libc::sockaddr_storage>, libc::socklen_t) = match addr {
            SocketAddr::V4(v4) => {
                let sa = libc::sockaddr_in {
                    sin_family: libc::AF_INET as libc::sa_family_t,
                    sin_port: v4.port().to_be(),
                    sin_addr: unsafe { mem::transmute::<[u8; 4], libc::in_addr>(v4.ip().octets()) },
                    sin_zero: [0; 8],
                };
                let sa_bytes = unsafe {
                    std::slice::from_raw_parts(
                        &sa as *const _ as *const u8,
                        mem::size_of::<libc::sockaddr_in>(),
                    )
                };
                let mut storage = mem::MaybeUninit::<libc::sockaddr_storage>::uninit();
                unsafe {
                    ptr::copy_nonoverlapping(
                        sa_bytes.as_ptr(),
                        storage.as_mut_ptr() as *mut u8,
                        sa_bytes.len(),
                    );
                }
                (storage, mem::size_of::<libc::sockaddr_in>() as libc::socklen_t)
            }
            SocketAddr::V6(v6) => {
                let sa = libc::sockaddr_in6 {
                    sin6_family: libc::AF_INET6 as libc::sa_family_t,
                    sin6_port: v6.port().to_be(),
                    sin6_flowinfo: v6.flowinfo(),
                    sin6_addr: unsafe { mem::transmute::<[u8; 16], libc::in6_addr>(v6.ip().octets()) },
                    sin6_scope_id: v6.scope_id(),
                };
                let sa_bytes = unsafe {
                    std::slice::from_raw_parts(
                        &sa as *const _ as *const u8,
                        mem::size_of::<libc::sockaddr_in6>(),
                    )
                };
                let mut storage = mem::MaybeUninit::<libc::sockaddr_storage>::uninit();
                unsafe {
                    ptr::copy_nonoverlapping(
                        sa_bytes.as_ptr(),
                        storage.as_mut_ptr() as *mut u8,
                        sa_bytes.len(),
                    );
                }
                (storage, mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t)
            }
        };

        // Prepare msghdr
        let msg = libc::msghdr {
            msg_name: sockaddr.as_ptr() as *mut libc::c_void,
            msg_namelen: sockaddr_len,
            msg_iov: &iov as *const _ as *mut libc::iovec,
            msg_iovlen: 1,
            msg_control: cmsg_buf.as_ptr() as *mut libc::c_void,
            msg_controllen: cmsg_space,
            msg_flags: 0,
        };

        // Send
        let n = unsafe { libc::sendmsg(fd, &msg, 0) };
        if n < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(n as usize)
        }
    }

    /// Non-Linux fallback: GSO not supported
    #[cfg(not(target_os = "linux"))]
    fn send_to_gso(&self, _data: &[u8], _addr: SocketAddr) -> io::Result<usize> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "GSO is only supported on Linux",
        ))
    }

    /// Opens a new KCP stream to the specified peer.
    /// The peer must be in established state with mux initialized.
    /// proto specifies the stream protocol type (e.g., protocol::TCP_PROXY).
    /// metadata contains additional data sent with the SYN frame (e.g., encoded Address).
    /// Use proto=0 and metadata=&[] for untyped streams.
    pub fn open_stream(&self, pk: &Key, proto: u8, metadata: &[u8]) -> Result<Arc<KcpStream>> {
        if self.closed.load(Ordering::SeqCst) {
            return Err(UdpError::Closed);
        }

        // Get the mux without holding the peer lock during open_stream()
        // This avoids deadlock since mux output callback also locks the peer
        let mux = {
            let peers = self.peers.read().unwrap();
            let peer = peers.get(pk).ok_or(UdpError::PeerNotFound)?;
            let p = peer.lock().unwrap();

            if p.state != PeerState::Established {
                return Err(UdpError::NoSession);
            }

            p.mux.as_ref().ok_or(UdpError::NoSession)?.clone()
        };

        mux.open_stream(proto, metadata).map_err(|_| UdpError::NoSession)
    }

    /// Accepts an incoming KCP stream from the specified peer.
    /// This blocks until a stream is available or the UDP is closed.
    /// The peer must be in established state with mux initialized.
    pub fn accept_stream(&self, pk: &Key) -> Result<Arc<KcpStream>> {
        if self.closed.load(Ordering::SeqCst) {
            return Err(UdpError::Closed);
        }

        // Get the accept receiver
        let accept_rx = {
            let peers = self.peers.read().unwrap();
            let peer = peers.get(pk).ok_or(UdpError::PeerNotFound)?;
            let p = peer.lock().unwrap();

            if p.state != PeerState::Established {
                return Err(UdpError::NoSession);
            }

            p.accept_rx.as_ref().ok_or(UdpError::NoSession)?.clone()
        };

        // Block until a stream is available
        // Use recv_timeout to allow checking for close
        loop {
            if self.closed.load(Ordering::SeqCst) {
                return Err(UdpError::Closed);
            }

            match accept_rx.recv_timeout(Duration::from_millis(100)) {
                Ok(stream) => return Ok(stream),
                Err(crossbeam_channel::RecvTimeoutError::Timeout) => continue,
                Err(crossbeam_channel::RecvTimeoutError::Disconnected) => {
                    return Err(UdpError::Closed);
                }
            }
        }
    }

    /// Reads the next decrypted message from any peer.
    /// Handles handshakes internally and only returns transport data.
    /// Returns (sender_pk, bytes_read).
    pub fn read_from(&self, buf: &mut [u8]) -> Result<(Key, usize)> {
        let (pk, _proto, n) = self.read_packet(buf)?;
        Ok((pk, n))
    }

    /// Reads the next decrypted message from any peer, including the protocol byte.
    /// Unlike read_from, this also returns the protocol byte from the encrypted payload.
    /// Returns (sender_pk, protocol_byte, bytes_read).
    pub fn read_packet(&self, buf: &mut [u8]) -> Result<(Key, u8, usize)> {
        if self.closed.load(Ordering::SeqCst) {
            return Err(UdpError::Closed);
        }

        let mut recv_buf = vec![0u8; MAX_PACKET_SIZE];

        loop {
            if self.closed.load(Ordering::SeqCst) {
                return Err(UdpError::Closed);
            }

            // Read from socket
            let (nr, from) = match self.socket.recv_from(&mut recv_buf) {
                Ok(r) => r,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
                Err(e) if e.kind() == io::ErrorKind::TimedOut => continue,
                Err(e) => {
                    if self.closed.load(Ordering::SeqCst) {
                        return Err(UdpError::Closed);
                    }
                    return Err(UdpError::Io(e));
                }
            };

            if nr < 1 {
                continue;
            }

            // Update stats
            self.total_rx.fetch_add(nr as u64, Ordering::SeqCst);
            *self.last_seen.lock().unwrap() = Some(Instant::now());

            // Parse message type
            let msg_type = recv_buf[0];

            match msg_type {
                message::message_type::HANDSHAKE_INIT => {
                    self.handle_handshake_init(&recv_buf[..nr], from);
                    continue;
                }
                message::message_type::HANDSHAKE_RESP => {
                    self.handle_handshake_resp(&recv_buf[..nr], from);
                    continue;
                }
                message::message_type::TRANSPORT => {
                    match self.handle_transport(&recv_buf[..nr], from, buf) {
                        Ok((pk, proto, n)) => return Ok((pk, proto, n)),
                        Err(_) => continue,
                    }
                }
                _ => continue,
            }
        }
    }

    /// Initiates a handshake with a peer.
    pub fn connect(&self, pk: &Key) -> Result<()> {
        self.connect_timeout(pk, Duration::from_secs(5))
    }

    /// Initiates a handshake with a peer with timeout.
    pub fn connect_timeout(&self, pk: &Key, timeout: Duration) -> Result<()> {
        if self.closed.load(Ordering::SeqCst) {
            return Err(UdpError::Closed);
        }

        let peers = self.peers.read().unwrap();
        let peer = peers.get(pk).ok_or(UdpError::PeerNotFound)?;
        let mut p = peer.lock().unwrap();

        let endpoint = p.endpoint.ok_or(UdpError::NoEndpoint)?;
        p.state = PeerState::Connecting;
        let peer_pk = p.pk;
        drop(p);
        drop(peers);

        // Generate local index
        let local_idx = generate_index();

        // Create handshake state
        let mut hs = HandshakeState::new(HandshakeConfig {
            pattern: Some(Pattern::IK),
            initiator: true,
            local_static: Some(self.local_key.clone()),
            remote_static: Some(peer_pk),
            ..Default::default()
        })
        .map_err(|_| UdpError::HandshakeFailed)?;

        // Write handshake initiation
        let msg1 = hs
            .write_message(&[])
            .map_err(|_| UdpError::HandshakeFailed)?;

        // Build wire message
        let ephemeral = hs.local_ephemeral().ok_or(UdpError::HandshakeFailed)?;
        let wire_msg = build_handshake_init(local_idx, &ephemeral, &msg1[KEY_SIZE..]);

        // Create channel for completion notification
        let (tx, rx) = std::sync::mpsc::channel();

        // Register pending handshake
        {
            let mut pending = self.pending.lock().unwrap();
            pending.insert(
                local_idx,
                PendingHandshake {
                    peer_pk,
                    hs_state: hs,
                    local_idx,
                    done: tx,
                    created_at: Instant::now(),
                },
            );
        }

        // Send handshake initiation
        if let Err(e) = self.socket.send_to(&wire_msg, endpoint) {
            let mut pending = self.pending.lock().unwrap();
            pending.remove(&local_idx);
            return Err(UdpError::Io(e));
        }

        // Wait for response with timeout
        match rx.recv_timeout(timeout) {
            Ok(result) => result,
            Err(_) => {
                let mut pending = self.pending.lock().unwrap();
                pending.remove(&local_idx);

                let peers = self.peers.read().unwrap();
                if let Some(peer) = peers.get(pk) {
                    let mut p = peer.lock().unwrap();
                    p.state = PeerState::Failed;
                }
                Err(UdpError::HandshakeTimeout)
            }
        }
    }

    /// Closes the UDP network.
    pub fn close(&self) -> Result<()> {
        self.closed.store(true, Ordering::SeqCst);
        Ok(())
    }

    /// Returns true if the UDP network is closed.
    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::SeqCst)
    }

    /// Determines if we are the KCP client for a peer.
    /// Uses deterministic rule: smaller public key is client (uses odd stream IDs).
    fn is_kcp_client(&self, remote_pk: &Key) -> bool {
        self.local_key.public.as_bytes() < remote_pk.as_bytes()
    }

    /// Initializes the KCP Mux for a peer.
    /// Called when session is established (handshake complete).
    fn init_mux(&self, remote_pk: Key) {
        let is_client = self.is_kcp_client(&remote_pk);

        // Create channels for stream acceptance (capacity 16 like Go)
        let (accept_tx, accept_rx) = bounded::<Arc<KcpStream>>(16);

        // Get peer reference
        let peer_arc = {
            let peers = self.peers.read().unwrap();
            match peers.get(&remote_pk) {
                Some(p) => Arc::clone(p),
                None => return,
            }
        };

        // We need to clone self references for the closures
        // Use weak-like pattern to avoid circular references
        let socket = self.socket.try_clone().expect("Failed to clone socket");
        let peers_for_output = Arc::clone(&peer_arc);
        let accept_tx_for_mux = accept_tx.clone();

        // Create Mux
        let mux = Arc::new(Mux::new(
            MuxConfig::default(),
            is_client,
            // Output function: send KCP frames through the encrypted session
            Box::new(move |data| {
                let mut p = peers_for_output.lock().unwrap();
                let endpoint = match p.endpoint {
                    Some(e) => e,
                    None => return Err("no endpoint".into()),
                };
                let session = match p.session.as_mut() {
                    Some(s) => s,
                    None => return Err("no session".into()),
                };

                // Encode payload with KCP protocol byte
                let payload = encode_payload(message::protocol::KCP, data);

                // Encrypt
                let (ciphertext, nonce) = session
                    .encrypt(&payload)
                    .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)?;

                // Build transport message
                let msg = build_transport_message(session.remote_index(), nonce, &ciphertext);

                // Send
                socket.send_to(&msg, endpoint)?;

                Ok(())
            }),
            // OnStreamData: called when a stream has data available
            Box::new(|_stream_id| {
                // Data availability is handled internally by Stream.read_data
            }),
            // OnNewStream: called when remote opens a new stream
            Box::new(move |stream| {
                if accept_tx_for_mux.try_send(stream).is_err() {
                    eprintln!("[warn] accept queue full, stream dropped");
                }
            }),
        ));

        // Store mux in peer state
        {
            let mut p = peer_arc.lock().unwrap();
            // Close existing mux if any
            if let Some(ref old_mux) = p.mux {
                old_mux.close();
            }
            p.mux = Some(Arc::clone(&mux));
            p.accept_tx = Some(accept_tx);
            p.accept_rx = Some(accept_rx);
        }

        // Start mux update loop in background
        // Use tokio coroutine if runtime available, otherwise fallback to thread
        let mux_for_loop = Arc::clone(&mux);
        if tokio::runtime::Handle::try_current().is_ok() {
            // Running in tokio context - use async task
            tokio::spawn(async move {
                Self::mux_update_loop_async(mux_for_loop).await;
            });
        } else {
            // No tokio runtime - fallback to thread (for sync tests)
            thread::spawn(move || {
                Self::mux_update_loop_sync(mux_for_loop);
            });
        }
    }

    /// Background loop that updates KCP state (async version using tokio).
    async fn mux_update_loop_async(mux: Arc<Mux>) {
        let mut interval = tokio_time::interval(Duration::from_millis(1)); // 1ms update interval
        let start = Instant::now();
        while !mux.is_closed() {
            interval.tick().await;
            let current = start.elapsed().as_millis() as u32;
            mux.update(current);
        }
    }

    /// Background loop that updates KCP state (sync version using thread).
    fn mux_update_loop_sync(mux: Arc<Mux>) {
        let interval = Duration::from_millis(1); // 1ms update interval
        let start = Instant::now();
        while !mux.is_closed() {
            let current = start.elapsed().as_millis() as u32;
            mux.update(current);
            thread::sleep(interval);
        }
    }

    // Internal: handle incoming handshake initiation
    fn handle_handshake_init(&self, data: &[u8], from: SocketAddr) {
        let msg = match parse_handshake_init(data) {
            Ok(m) => m,
            Err(_) => return,
        };

        // Create handshake state to process the init
        let mut hs = match HandshakeState::new(HandshakeConfig {
            pattern: Some(Pattern::IK),
            initiator: false,
            local_static: Some(self.local_key.clone()),
            ..Default::default()
        }) {
            Ok(h) => h,
            Err(_) => return,
        };

        // Build Noise message from wire format
        let mut noise_msg = [0u8; KEY_SIZE + 48];
        noise_msg[..KEY_SIZE].copy_from_slice(&msg.ephemeral.0);
        noise_msg[KEY_SIZE..].copy_from_slice(&msg.static_encrypted);

        // Read the handshake message
        if hs.read_message(&noise_msg).is_err() {
            return;
        }

        // Get the remote's public key
        let remote_pk = *hs.remote_static();

        // Check if peer is known or if we allow unknown peers
        {
            let mut peers = self.peers.write().unwrap();
            if let std::collections::hash_map::Entry::Vacant(e) = peers.entry(remote_pk) {
                if !self.allow_unknown {
                    return;
                }
                e.insert(Arc::new(Mutex::new(PeerStateInternal {
                    pk: remote_pk,
                    endpoint: Some(from),
                    session: None,
                    state: PeerState::New,
                    rx_bytes: 0,
                    tx_bytes: 0,
                    last_seen: None,
                    mux: None,
                    accept_tx: None,
                    accept_rx: None,
                })));
            }
        }

        // Generate local index for response
        let local_idx = generate_index();

        // Write response message
        let resp_payload = match hs.write_message(&[]) {
            Ok(p) => p,
            Err(_) => return,
        };

        // Build wire message
        let ephemeral = match hs.local_ephemeral() {
            Some(e) => e,
            None => return,
        };
        let wire_msg = build_handshake_resp(
            local_idx,
            msg.sender_index,
            &ephemeral,
            &resp_payload[KEY_SIZE..],
        );

        // Send response
        if self.socket.send_to(&wire_msg, from).is_err() {
            return;
        }

        // Complete handshake and create session
        let (send_cs, recv_cs) = match hs.split() {
            Ok((s, r)) => (s, r),
            Err(_) => return,
        };

        let session = Session::new(SessionConfig {
            local_index: local_idx,
            remote_index: msg.sender_index,
            send_key: *send_cs.key(),
            recv_key: *recv_cs.key(),
            remote_pk,
        });

        // Update peer state
        {
            let peers = self.peers.read().unwrap();
            if let Some(peer) = peers.get(&remote_pk) {
                let mut p = peer.lock().unwrap();
                p.endpoint = Some(from);
                p.session = Some(session);
                p.state = PeerState::Established;
                p.last_seen = Some(Instant::now());
            }
        }

        // Register in index map
        {
            let mut by_index = self.by_index.write().unwrap();
            by_index.insert(local_idx, remote_pk);
        }

        // Initialize KCP Mux for this peer
        self.init_mux(remote_pk);
    }

    // Internal: handle incoming handshake response
    fn handle_handshake_resp(&self, data: &[u8], from: SocketAddr) {
        let msg = match parse_handshake_resp(data) {
            Ok(m) => m,
            Err(_) => return,
        };

        // Find the pending handshake
        let pending = {
            let mut pending_map = self.pending.lock().unwrap();
            match pending_map.remove(&msg.receiver_index) {
                Some(p) => p,
                None => return,
            }
        };

        // Build Noise message from wire format
        let mut noise_msg = [0u8; KEY_SIZE + 16];
        noise_msg[..KEY_SIZE].copy_from_slice(&msg.ephemeral.0);
        noise_msg[KEY_SIZE..].copy_from_slice(&msg.empty_encrypted);

        // Read the handshake response
        let mut hs = pending.hs_state;
        if hs.read_message(&noise_msg).is_err() {
            let peers = self.peers.read().unwrap();
            if let Some(peer) = peers.get(&pending.peer_pk) {
                let mut p = peer.lock().unwrap();
                p.state = PeerState::Failed;
            }
            let _ = pending.done.send(Err(UdpError::HandshakeFailed));
            return;
        }

        // Complete handshake and create session
        let (send_cs, recv_cs) = match hs.split() {
            Ok((s, r)) => (s, r),
            Err(_) => {
                let _ = pending.done.send(Err(UdpError::HandshakeFailed));
                return;
            }
        };

        let peer_pk = pending.peer_pk;
        let session = Session::new(SessionConfig {
            local_index: pending.local_idx,
            remote_index: msg.sender_index,
            send_key: *send_cs.key(),
            recv_key: *recv_cs.key(),
            remote_pk: peer_pk,
        });

        // Update peer state
        {
            let peers = self.peers.read().unwrap();
            if let Some(peer) = peers.get(&peer_pk) {
                let mut p = peer.lock().unwrap();
                p.endpoint = Some(from);
                p.session = Some(session);
                p.state = PeerState::Established;
                p.last_seen = Some(Instant::now());
            }
        }

        // Register in index map
        {
            let mut by_index = self.by_index.write().unwrap();
            by_index.insert(pending.local_idx, peer_pk);
        }

        // Initialize KCP Mux for this peer
        self.init_mux(peer_pk);

        // Signal completion
        let _ = pending.done.send(Ok(()));
    }

    // Internal: handle incoming transport message
    // Returns (sender_pk, protocol_byte, bytes_copied_to_out_buf)
    fn handle_transport(
        &self,
        data: &[u8],
        from: SocketAddr,
        out_buf: &mut [u8],
    ) -> Result<(Key, u8, usize)> {
        let msg = parse_transport_message(data).map_err(|_| UdpError::NoSession)?;

        // Find peer by receiver index
        let peer_pk = {
            let by_index = self.by_index.read().unwrap();
            *by_index.get(&msg.receiver_index).ok_or(UdpError::PeerNotFound)?
        };

        // Decrypt and process with peer lock, then release before mux operations
        let (plaintext, mux) = {
            let peers = self.peers.read().unwrap();
            let peer = peers.get(&peer_pk).ok_or(UdpError::PeerNotFound)?;
            let mut p = peer.lock().unwrap();

            let session = p.session.as_mut().ok_or(UdpError::NoSession)?;

            // Decrypt
            let plaintext = session
                .decrypt(msg.ciphertext, msg.counter)
                .map_err(|e| UdpError::Session(e.to_string()))?;

            // Update peer state (roaming + stats)
            if p.endpoint.map(|e| e != from).unwrap_or(true) {
                p.endpoint = Some(from);
            }
            p.rx_bytes += data.len() as u64;
            p.last_seen = Some(Instant::now());

            // Get mux clone if available
            let mux = p.mux.clone();

            (plaintext, mux)
        };

        // Decode protocol and payload
        if plaintext.is_empty() {
            // Keepalive message
            return Ok((peer_pk, 0, 0));
        }

        let (protocol, payload) = decode_payload(&plaintext)
            .map_err(|_| UdpError::Session("invalid payload".to_string()))?;

        // Route based on protocol (without holding peer lock)
        match protocol {
            message::protocol::KCP => {
                // Route to KCP Mux
                if let Some(ref mux) = mux {
                    if let Err(e) = mux.input(payload) {
                        eprintln!("[warn] KCP input error from peer {}: {}", peer_pk, e);
                    }
                }
                // Return 0 bytes - KCP data is handled internally
                Ok((peer_pk, protocol, 0))
            }

            message::protocol::RELAY_0 => {
                let rt_guard = self.route_table.read().unwrap();
                if let Some(ref rt) = *rt_guard {
                    if let Ok(action) = relay::handle_relay0(rt.as_ref(), &peer_pk.0, payload) {
                        drop(rt_guard);
                        self.execute_relay_action(&action);
                    }
                }
                Ok((peer_pk, protocol, 0))
            }

            message::protocol::RELAY_1 => {
                let rt_guard = self.route_table.read().unwrap();
                if let Some(ref rt) = *rt_guard {
                    if let Ok(action) = relay::handle_relay1(rt.as_ref(), payload) {
                        drop(rt_guard);
                        self.execute_relay_action(&action);
                    }
                }
                Ok((peer_pk, protocol, 0))
            }

            message::protocol::RELAY_2 => {
                // Last hop: extract src and inner payload, then decrypt
                if let Ok((src, inner_payload)) = relay::handle_relay2(payload) {
                    if let Ok((inner_pk, inner_proto, n)) = self.process_relayed_packet(&src, &inner_payload, out_buf) {
                        return Ok((inner_pk, inner_proto, n));
                    }
                }
                Ok((peer_pk, protocol, 0))
            }

            message::protocol::PING => {
                let rt_guard = self.route_table.read().unwrap();
                if rt_guard.is_some() {
                    drop(rt_guard);
                    let metrics = *self.local_metrics.lock().unwrap();
                    if let Ok(action) = relay::handle_ping(&peer_pk.0, payload, &metrics) {
                        self.execute_relay_action(&action);
                    }
                }
                Ok((peer_pk, protocol, 0))
            }

            message::protocol::PONG => {
                // PONG delivered to caller for upper-layer processing
                let n = payload.len().min(out_buf.len());
                out_buf[..n].copy_from_slice(&payload[..n]);
                Ok((peer_pk, protocol, n))
            }

            _ => {
                // Non-KCP protocol, copy to output buffer
                let n = payload.len().min(out_buf.len());
                out_buf[..n].copy_from_slice(&payload[..n]);
                Ok((peer_pk, protocol, n))
            }
        }
    }

    /// Execute a relay forwarding action by sending to the target peer.
    fn execute_relay_action(&self, action: &relay::Action) {
        let pk = Key(action.dst);

        let peers = self.peers.read().unwrap();
        let peer = match peers.get(&pk) {
            Some(p) => p.clone(),
            None => return,
        };
        drop(peers);

        let p = peer.lock().unwrap();
        if let (Some(ref session), Some(endpoint)) = (&p.session, p.endpoint) {
            let payload_buf = encode_payload(action.protocol, &action.data);
            if let Ok((ct, nonce)) = session.encrypt(&payload_buf) {
                let msg = build_transport_message(session.remote_index(), nonce, &ct);
                let _ = self.socket.send_to(&msg, endpoint);
            }
        }
    }

    /// Process an inner payload from a RELAY_2 message.
    fn process_relayed_packet(
        &self,
        src: &[u8; 32],
        inner_payload: &[u8],
        out_buf: &mut [u8],
    ) -> Result<(Key, u8, usize)> {
        let msg = parse_transport_message(inner_payload).map_err(|_| UdpError::NoSession)?;

        let inner_pk = {
            let by_index = self.by_index.read().unwrap();
            *by_index.get(&msg.receiver_index).ok_or(UdpError::PeerNotFound)?
        };

        let (plaintext, mux) = {
            let peers = self.peers.read().unwrap();
            let peer = peers.get(&inner_pk).ok_or(UdpError::PeerNotFound)?;
            let mut p = peer.lock().unwrap();
            let session = p.session.as_mut().ok_or(UdpError::NoSession)?;
            let plaintext = session.decrypt(msg.ciphertext, msg.counter)
                .map_err(|e| UdpError::Session(e.to_string()))?;
            let mux = p.mux.clone();
            (plaintext, mux)
        };

        if plaintext.is_empty() {
            return Ok((Key(*src), 0, 0));
        }

        let (inner_proto, inner_data) = decode_payload(&plaintext)
            .map_err(|_| UdpError::Session("invalid payload".to_string()))?;

        match inner_proto {
            message::protocol::KCP => {
                if let Some(ref mux) = mux {
                    let _ = mux.input(inner_data);
                }
                Ok((Key(*src), inner_proto, 0))
            }
            _ => {
                let n = inner_data.len().min(out_buf.len());
                out_buf[..n].copy_from_slice(&inner_data[..n]);
                Ok((Key(*src), inner_proto, n))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_udp() {
        let key = KeyPair::generate();
        let udp = UDP::new(key, UdpOptions::new()).unwrap();
        assert!(!udp.is_closed());
        udp.close().unwrap();
        assert!(udp.is_closed());
    }

    #[test]
    fn test_set_peer_endpoint() {
        let key = KeyPair::generate();
        let udp = UDP::new(key, UdpOptions::new()).unwrap();

        let peer_key = KeyPair::generate();
        let endpoint: SocketAddr = "127.0.0.1:12345".parse().unwrap();

        udp.set_peer_endpoint(peer_key.public, endpoint);

        let info = udp.peer_info(&peer_key.public).unwrap();
        assert_eq!(info.endpoint, Some(endpoint));
        assert_eq!(info.state, PeerState::New);
    }

    #[test]
    fn test_remove_peer() {
        let key = KeyPair::generate();
        let udp = UDP::new(key, UdpOptions::new()).unwrap();

        let peer_key = KeyPair::generate();
        let endpoint: SocketAddr = "127.0.0.1:12345".parse().unwrap();

        udp.set_peer_endpoint(peer_key.public, endpoint);
        assert!(udp.peer_info(&peer_key.public).is_some());

        udp.remove_peer(&peer_key.public);
        assert!(udp.peer_info(&peer_key.public).is_none());
    }

    #[test]
    fn test_host_info() {
        let key = KeyPair::generate();
        let udp = UDP::new(key.clone(), UdpOptions::new()).unwrap();

        let info = udp.host_info();
        assert_eq!(info.public_key, key.public);
        assert_eq!(info.peer_count, 0);
    }

    // ==================== KCP Stream E2E Tests ====================

    /// Helper: read from stream with polling since read_data() is non-blocking
    fn read_with_poll(stream: &Arc<KcpStream>, buf: &mut [u8], timeout: Duration) -> usize {
        let deadline = Instant::now() + timeout;
        let mut total = 0;
        while Instant::now() < deadline {
            match stream.read_data(&mut buf[total..]) {
                Ok(n) if n > 0 => {
                    total += n;
                    return total;
                }
                Ok(_) => thread::sleep(Duration::from_millis(1)),
                Err(_) => break,
            }
        }
        total
    }

    /// Helper: read all expected bytes from stream
    fn read_all_with_poll(stream: &Arc<KcpStream>, expected: usize, timeout: Duration) -> Vec<u8> {
        let deadline = Instant::now() + timeout;
        let mut buf = vec![0u8; expected * 2];
        let mut received = Vec::with_capacity(expected);
        while received.len() < expected && Instant::now() < deadline {
            match stream.read_data(&mut buf) {
                Ok(n) if n > 0 => received.extend_from_slice(&buf[..n]),
                Ok(_) => thread::sleep(Duration::from_millis(1)),
                Err(_) => break,
            }
        }
        received
    }

    /// Create a connected pair of UDP instances for testing
    fn create_connected_pair() -> (Arc<UDP>, Arc<UDP>, KeyPair, KeyPair) {
        let server_key = KeyPair::generate();
        let client_key = KeyPair::generate();

        let server = Arc::new(
            UDP::new(server_key.clone(), UdpOptions::new().bind_addr("127.0.0.1:0").allow_unknown(true))
                .expect("Failed to create server")
        );
        let client = Arc::new(
            UDP::new(client_key.clone(), UdpOptions::new().bind_addr("127.0.0.1:0").allow_unknown(true))
                .expect("Failed to create client")
        );

        let server_addr = server.host_info().addr;
        let client_addr = client.host_info().addr;

        server.set_peer_endpoint(client_key.public, client_addr);
        client.set_peer_endpoint(server_key.public, server_addr);

        // Start receive loops
        let server_clone = Arc::clone(&server);
        thread::spawn(move || {
            let mut buf = vec![0u8; 65535];
            while !server_clone.is_closed() {
                let _ = server_clone.read_from(&mut buf);
            }
        });

        let client_clone = Arc::clone(&client);
        thread::spawn(move || {
            let mut buf = vec![0u8; 65535];
            while !client_clone.is_closed() {
                let _ = client_clone.read_from(&mut buf);
            }
        });

        // Connect
        client.connect(&server_key.public).expect("Failed to connect");
        thread::sleep(Duration::from_millis(100));

        (server, client, server_key, client_key)
    }

    #[test]
    fn test_kcp_stream_open_accept() {
        let (server, client, server_key, client_key) = create_connected_pair();

        // Server accepts in background
        let server_clone = Arc::clone(&server);
        let client_pub = client_key.public;
        let (tx, rx) = std::sync::mpsc::channel();
        thread::spawn(move || {
            let stream = server_clone.accept_stream(&client_pub);
            let _ = tx.send(stream);
        });

        // Client opens stream
        let client_stream = client.open_stream(&server_key.public, 0, &[]).expect("Failed to open stream");
        // Stream ID is assigned based on public key comparison (smaller key uses odd IDs)
        // The first stream ID depends on which peer opens first and their key order

        // Wait for server to accept
        let server_stream = rx.recv_timeout(Duration::from_secs(2))
            .expect("Timeout waiting for accept")
            .expect("Server failed to accept");
        assert_eq!(server_stream.id(), client_stream.id());

        // Cleanup
        client_stream.shutdown();
        server_stream.shutdown();
        server.close().unwrap();
        client.close().unwrap();
    }

    #[test]
    fn test_kcp_stream_bidirectional() {
        let (server, client, server_key, client_key) = create_connected_pair();

        // Server accepts in background
        let server_clone = Arc::clone(&server);
        let client_pub = client_key.public;
        let (tx, rx) = std::sync::mpsc::channel();
        thread::spawn(move || {
            let stream = server_clone.accept_stream(&client_pub);
            let _ = tx.send(stream);
        });

        // Client opens stream
        let client_stream = client.open_stream(&server_key.public, 0, &[]).unwrap();
        let server_stream = rx.recv_timeout(Duration::from_secs(2)).unwrap().unwrap();

        // Client sends
        let client_msg = b"Hello from client!";
        client_stream.write_data(client_msg).unwrap();

        // Server receives
        let received = read_all_with_poll(&server_stream, client_msg.len(), Duration::from_secs(2));
        assert_eq!(received, client_msg);

        // Server sends
        let server_msg = b"Hello from server!";
        server_stream.write_data(server_msg).unwrap();

        // Client receives
        let received = read_all_with_poll(&client_stream, server_msg.len(), Duration::from_secs(2));
        assert_eq!(received, server_msg);

        // Cleanup
        client_stream.shutdown();
        server_stream.shutdown();
        server.close().unwrap();
        client.close().unwrap();
    }

    #[test]
    fn test_kcp_stream_large_data() {
        let (server, client, server_key, client_key) = create_connected_pair();

        // Server accepts in background
        let server_clone = Arc::clone(&server);
        let client_pub = client_key.public;
        let (tx, rx) = std::sync::mpsc::channel();
        thread::spawn(move || {
            let stream = server_clone.accept_stream(&client_pub);
            let _ = tx.send(stream);
        });

        let client_stream = client.open_stream(&server_key.public, 0, &[]).unwrap();
        let server_stream = rx.recv_timeout(Duration::from_secs(2)).unwrap().unwrap();

        // Send 100KB of data
        let test_data: Vec<u8> = (0..100 * 1024).map(|i| (i % 256) as u8).collect();

        // Writer in background
        let client_stream_clone = Arc::clone(&client_stream);
        let test_data_clone = test_data.clone();
        thread::spawn(move || {
            let chunk_size = 8192;
            let mut written = 0;
            while written < test_data_clone.len() {
                let end = (written + chunk_size).min(test_data_clone.len());
                client_stream_clone.write_data(&test_data_clone[written..end]).unwrap();
                written = end;
            }
        });

        // Reader
        let mut received = Vec::with_capacity(test_data.len());
        let mut buf = vec![0u8; 4096];
        let deadline = Instant::now() + Duration::from_secs(10);

        while received.len() < test_data.len() && Instant::now() < deadline {
            match server_stream.read_data(&mut buf) {
                Ok(n) if n > 0 => received.extend_from_slice(&buf[..n]),
                Ok(_) => thread::sleep(Duration::from_millis(1)),
                Err(_) => break,
            }
        }

        assert_eq!(received.len(), test_data.len(), "Received {} bytes, expected {}", received.len(), test_data.len());
        assert_eq!(received, test_data);

        // Cleanup
        client_stream.shutdown();
        server_stream.shutdown();
        server.close().unwrap();
        client.close().unwrap();
    }

    #[test]
    fn test_kcp_stream_multiple_streams() {
        let (server, client, server_key, client_key) = create_connected_pair();

        let num_streams = 5;
        let (accept_tx, accept_rx) = std::sync::mpsc::channel();

        // Server accepts streams
        let server_clone = Arc::clone(&server);
        let client_pub = client_key.public;
        thread::spawn(move || {
            for _ in 0..num_streams {
                if let Ok(stream) = server_clone.accept_stream(&client_pub) {
                    let _ = accept_tx.send(stream);
                }
            }
        });

        // Open multiple streams and send/receive
        for i in 0..num_streams {
            let client_stream = client.open_stream(&server_key.public, 0, &[]).unwrap();
            let server_stream = accept_rx.recv_timeout(Duration::from_secs(2)).unwrap();

            // Exchange data
            let msg = format!("Stream {} test", i);
            client_stream.write_data(msg.as_bytes()).unwrap();

            let received = read_all_with_poll(&server_stream, msg.len(), Duration::from_secs(2));
            assert_eq!(String::from_utf8_lossy(&received), msg);

            client_stream.shutdown();
            server_stream.shutdown();
        }

        // Cleanup
        server.close().unwrap();
        client.close().unwrap();
    }
}
