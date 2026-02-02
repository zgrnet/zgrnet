//! Async UDP with Go-style pipeline architecture.
//!
//! Architecture:
//!   io_task: socket -> clone packet -> decrypt_chan + output_chan
//!   decrypt_workers (x N): decrypt_chan -> decrypt -> send ready
//!   read_from: output_chan -> wait ready -> return

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

use tokio::net::UdpSocket as TokioUdpSocket;
use tokio::sync::{mpsc, oneshot, Mutex, RwLock};

use crate::noise::{
    build_handshake_init, build_handshake_resp, build_transport_message, generate_index, message,
    parse_handshake_init, parse_handshake_resp, parse_transport_message, Config as HandshakeConfig,
    HandshakeState, Key, KeyPair, Pattern, Session, SessionConfig, MAX_PACKET_SIZE, KEY_SIZE,
};

/// Pipeline packet with ready signal (Go-style).
struct PipelinePacket {
    // Raw data
    data: Vec<u8>,
    from: SocketAddr,
    
    // Decrypted result (filled by decrypt worker)
    pk: Option<Key>,
    payload: Option<Vec<u8>>,
    is_handshake: bool,
    
    // Ready signal
    ready_tx: Option<oneshot::Sender<()>>,
    ready_rx: Option<oneshot::Receiver<()>>,
}

impl PipelinePacket {
    fn new(data: Vec<u8>, from: SocketAddr) -> Self {
        let (tx, rx) = oneshot::channel();
        Self {
            data,
            from,
            pk: None,
            payload: None,
            is_handshake: false,
            ready_tx: Some(tx),
            ready_rx: Some(rx),
        }
    }
}

/// Decrypted packet ready for consumption.
#[derive(Debug)]
pub struct DecryptedPacket {
    pub pk: Key,
    pub payload: Vec<u8>,
}

/// Raw packet (for external use).
#[derive(Debug)]
pub struct RawPacket {
    pub data: Vec<u8>,
    pub from: SocketAddr,
}

/// Peer connection state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerState {
    New,
    Connecting,
    Established,
    Failed,
}

/// Internal peer state.
struct PeerInternal {
    pk: Key,
    endpoint: Option<SocketAddr>,
    session: Option<Session>,
    state: PeerState,
    rx_bytes: u64,
    tx_bytes: u64,
    last_seen: Option<Instant>,
}

/// Pending handshake tracking.
struct PendingHandshake {
    peer_pk: Key,
    hs_state: HandshakeState,
    local_idx: u32,
    done: oneshot::Sender<Result<(), String>>,
}

/// Configuration for async UDP.
#[derive(Clone)]
pub struct AsyncUdpConfig {
    pub raw_chan_size: usize,
    pub output_chan_size: usize,
    pub decrypt_workers: usize,
    pub allow_unknown: bool,
}

impl Default for AsyncUdpConfig {
    fn default() -> Self {
        Self {
            raw_chan_size: 4096,
            output_chan_size: 4096,
            decrypt_workers: 0, // 0 = use CPU count
            allow_unknown: true,
        }
    }
}

impl AsyncUdpConfig {
    pub fn effective_workers(&self) -> usize {
        if self.decrypt_workers == 0 {
            std::thread::available_parallelism()
                .map(|n| n.get())
                .unwrap_or(4)
        } else {
            self.decrypt_workers
        }
    }
}

/// Async UDP with Go-style pipeline architecture.
pub struct AsyncUDP {
    socket: Arc<TokioUdpSocket>,
    local_key: KeyPair,

    // Peer management
    peers: Arc<RwLock<HashMap<Key, Arc<Mutex<PeerInternal>>>>>,
    by_index: Arc<RwLock<HashMap<u32, Key>>>,

    // Pending handshakes
    pending: Arc<Mutex<HashMap<u32, PendingHandshake>>>,

    // Output channel (Go-style: packets with ready signal)
    output_rx: Mutex<mpsc::Receiver<Arc<Mutex<PipelinePacket>>>>,

    // Stats
    total_rx: AtomicU64,
    total_tx: AtomicU64,

    // State
    closed: AtomicBool,
}

impl AsyncUDP {
    /// Creates a new async UDP instance with Go-style pipeline.
    pub async fn new(key: KeyPair, bind_addr: &str, config: AsyncUdpConfig) -> std::io::Result<Arc<Self>> {
        let socket = Arc::new(TokioUdpSocket::bind(bind_addr).await?);
        
        // Channels: decrypt_chan for workers, output_chan for read_from
        let (decrypt_tx, decrypt_rx) = mpsc::channel::<Arc<Mutex<PipelinePacket>>>(config.raw_chan_size);
        let (output_tx, output_rx) = mpsc::channel::<Arc<Mutex<PipelinePacket>>>(config.output_chan_size);

        let peers = Arc::new(RwLock::new(HashMap::new()));
        let by_index = Arc::new(RwLock::new(HashMap::new()));
        let pending = Arc::new(Mutex::new(HashMap::new()));

        let udp = Arc::new(Self {
            socket: socket.clone(),
            local_key: key,
            peers: peers.clone(),
            by_index: by_index.clone(),
            pending: pending.clone(),
            output_rx: Mutex::new(output_rx),
            total_rx: AtomicU64::new(0),
            total_tx: AtomicU64::new(0),
            closed: AtomicBool::new(false),
        });

        // Start I/O task: reads from socket, sends to both channels (Go-style)
        let io_socket = socket.clone();
        let io_decrypt_tx = decrypt_tx;
        let io_output_tx = output_tx.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; MAX_PACKET_SIZE];
            loop {
                match io_socket.recv_from(&mut buf).await {
                    Ok((n, from)) => {
                        let pkt = Arc::new(Mutex::new(PipelinePacket::new(
                            buf[..n].to_vec(),
                            from,
                        )));
                        
                        // Send to both channels (Go-style: same packet in both)
                        // If decrypt_chan is full, drop
                        if io_decrypt_tx.try_send(pkt.clone()).is_err() {
                            continue;
                        }
                        
                        // Send to output_chan
                        let _ = io_output_tx.try_send(pkt);
                    }
                    Err(_) => break,
                }
            }
        });

        // Start decrypt workers
        let workers = config.effective_workers();
        let decrypt_rx = Arc::new(Mutex::new(decrypt_rx));

        for _ in 0..workers {
            let worker_rx = decrypt_rx.clone();
            let worker_peers = peers.clone();
            let worker_by_index = by_index.clone();
            let worker_pending = pending.clone();
            let worker_socket = socket.clone();
            let worker_local_key = udp.local_key.clone();
            let worker_allow_unknown = config.allow_unknown;

            tokio::spawn(async move {
                loop {
                    let pkt = {
                        let mut rx = worker_rx.lock().await;
                        rx.recv().await
                    };

                    let pkt = match pkt {
                        Some(p) => p,
                        None => break,
                    };

                    // Process packet
                    let mut pkt_guard = pkt.lock().await;
                    
                    if pkt_guard.data.is_empty() {
                        // Signal ready and continue
                        if let Some(tx) = pkt_guard.ready_tx.take() {
                            let _ = tx.send(());
                        }
                        continue;
                    }

                    let msg_type = pkt_guard.data[0];

                    match msg_type {
                        t if t == message::message_type::HANDSHAKE_INIT => {
                            Self::handle_handshake_init_static(
                                &pkt_guard.data,
                                pkt_guard.from,
                                &worker_local_key,
                                worker_allow_unknown,
                                &worker_peers,
                                &worker_by_index,
                                &worker_socket,
                            )
                            .await;
                            pkt_guard.is_handshake = true;
                        }
                        t if t == message::message_type::HANDSHAKE_RESP => {
                            Self::handle_handshake_resp_static(
                                &pkt_guard.data,
                                pkt_guard.from,
                                &worker_peers,
                                &worker_by_index,
                                &worker_pending,
                            )
                            .await;
                            pkt_guard.is_handshake = true;
                        }
                        t if t == message::message_type::TRANSPORT => {
                            if let Some((pk, payload)) = Self::handle_transport_static(
                                &pkt_guard.data,
                                pkt_guard.from,
                                &worker_peers,
                                &worker_by_index,
                            )
                            .await
                            {
                                pkt_guard.pk = Some(pk);
                                pkt_guard.payload = Some(payload);
                            }
                        }
                        _ => {}
                    }

                    // Signal ready
                    if let Some(tx) = pkt_guard.ready_tx.take() {
                        let _ = tx.send(());
                    }
                }
            });
        }

        Ok(udp)
    }

    /// Sets a peer's endpoint.
    pub async fn set_peer_endpoint(&self, pk: Key, endpoint: SocketAddr) {
        let mut peers = self.peers.write().await;
        if let Some(peer) = peers.get(&pk) {
            let mut p = peer.lock().await;
            p.endpoint = Some(endpoint);
        } else {
            peers.insert(
                pk,
                Arc::new(Mutex::new(PeerInternal {
                    pk,
                    endpoint: Some(endpoint),
                    session: None,
                    state: PeerState::New,
                    rx_bytes: 0,
                    tx_bytes: 0,
                    last_seen: None,
                })),
            );
        }
    }

    /// Initiates a handshake with a peer.
    pub async fn connect(&self, pk: &Key) -> Result<(), String> {
        let (endpoint, peer_pk) = {
            let peers = self.peers.read().await;
            let peer = peers.get(pk).ok_or("peer not found")?;
            let p = peer.lock().await;
            let endpoint = p.endpoint.ok_or("no endpoint")?;
            (endpoint, p.pk)
        };

        {
            let peers = self.peers.read().await;
            if let Some(peer) = peers.get(pk) {
                let mut p = peer.lock().await;
                p.state = PeerState::Connecting;
            }
        }

        let local_idx = generate_index();

        let mut hs = HandshakeState::new(HandshakeConfig {
            pattern: Some(Pattern::IK),
            initiator: true,
            local_static: Some(self.local_key.clone()),
            remote_static: Some(peer_pk),
            ..Default::default()
        })
        .map_err(|e| format!("handshake init failed: {:?}", e))?;

        let msg1 = hs
            .write_message(&[])
            .map_err(|e| format!("write message failed: {:?}", e))?;

        let ephemeral = hs.local_ephemeral().ok_or("no ephemeral")?;
        let wire_msg = build_handshake_init(local_idx, &ephemeral, &msg1[KEY_SIZE..]);

        let (tx, rx) = oneshot::channel();

        {
            let mut pending = self.pending.lock().await;
            pending.insert(
                local_idx,
                PendingHandshake {
                    peer_pk,
                    hs_state: hs,
                    local_idx,
                    done: tx,
                },
            );
        }

        self.socket
            .send_to(&wire_msg, endpoint)
            .await
            .map_err(|e| format!("send failed: {:?}", e))?;

        match tokio::time::timeout(std::time::Duration::from_secs(5), rx).await {
            Ok(Ok(result)) => result,
            Ok(Err(_)) => Err("channel closed".to_string()),
            Err(_) => {
                let mut pending = self.pending.lock().await;
                pending.remove(&local_idx);
                Err("timeout".to_string())
            }
        }
    }

    /// Sends encrypted data to a peer.
    pub async fn write_to(&self, pk: &Key, data: &[u8]) -> Result<usize, String> {
        let peers = self.peers.read().await;
        let peer = peers.get(pk).ok_or("peer not found")?;
        let mut p = peer.lock().await;

        let endpoint = p.endpoint.ok_or("no endpoint")?;
        let session = p.session.as_mut().ok_or("no session")?;

        let (ciphertext, nonce) = session
            .encrypt(data)
            .map_err(|e| format!("encrypt failed: {:?}", e))?;

        let msg = build_transport_message(session.remote_index(), nonce, &ciphertext);

        let n = self
            .socket
            .send_to(&msg, endpoint)
            .await
            .map_err(|e| format!("send failed: {:?}", e))?;

        self.total_tx.fetch_add(n as u64, Ordering::SeqCst);
        p.tx_bytes += n as u64;

        Ok(n)
    }

    /// Reads the next decrypted packet (Go-style: waits for ready signal).
    pub async fn read_from(&self) -> Option<DecryptedPacket> {
        loop {
            let pkt = {
                let mut rx = self.output_rx.lock().await;
                rx.recv().await?
            };

            // Wait for ready signal
            let ready_rx = {
                let mut pkt_guard = pkt.lock().await;
                pkt_guard.ready_rx.take()
            };

            if let Some(rx) = ready_rx {
                let _ = rx.await;
            }

            // Check result
            let pkt_guard = pkt.lock().await;
            
            // Skip handshakes
            if pkt_guard.is_handshake {
                continue;
            }

            // Return if we have payload
            if let (Some(pk), Some(payload)) = (pkt_guard.pk, pkt_guard.payload.clone()) {
                return Some(DecryptedPacket { pk, payload });
            }
        }
    }

    /// Returns the local address.
    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    /// Returns the local public key.
    pub fn public_key(&self) -> Key {
        self.local_key.public
    }

    /// Returns peer state.
    pub async fn peer_state(&self, pk: &Key) -> Option<PeerState> {
        let peers = self.peers.read().await;
        let peer = peers.get(pk)?;
        let p = peer.lock().await;
        Some(p.state)
    }

    /// Closes the UDP.
    pub fn close(&self) {
        self.closed.store(true, Ordering::SeqCst);
    }

    // Static handlers (same as before)
    async fn handle_handshake_init_static(
        data: &[u8],
        from: SocketAddr,
        local_key: &KeyPair,
        allow_unknown: bool,
        peers: &Arc<RwLock<HashMap<Key, Arc<Mutex<PeerInternal>>>>>,
        by_index: &Arc<RwLock<HashMap<u32, Key>>>,
        socket: &Arc<TokioUdpSocket>,
    ) {
        let msg = match parse_handshake_init(data) {
            Ok(m) => m,
            Err(_) => return,
        };

        let mut hs = match HandshakeState::new(HandshakeConfig {
            pattern: Some(Pattern::IK),
            initiator: false,
            local_static: Some(local_key.clone()),
            ..Default::default()
        }) {
            Ok(h) => h,
            Err(_) => return,
        };

        let mut noise_msg = [0u8; KEY_SIZE + 48];
        noise_msg[..KEY_SIZE].copy_from_slice(&msg.ephemeral.0);
        noise_msg[KEY_SIZE..].copy_from_slice(&msg.static_encrypted);

        if hs.read_message(&noise_msg).is_err() {
            return;
        }

        let remote_pk = *hs.remote_static();

        {
            let mut peers_w = peers.write().await;
            if let std::collections::hash_map::Entry::Vacant(e) = peers_w.entry(remote_pk) {
                if !allow_unknown {
                    return;
                }
                e.insert(Arc::new(Mutex::new(PeerInternal {
                    pk: remote_pk,
                    endpoint: Some(from),
                    session: None,
                    state: PeerState::New,
                    rx_bytes: 0,
                    tx_bytes: 0,
                    last_seen: None,
                })));
            }
        }

        let local_idx = generate_index();

        let resp_payload = match hs.write_message(&[]) {
            Ok(p) => p,
            Err(_) => return,
        };

        let ephemeral = match hs.local_ephemeral() {
            Some(e) => e,
            None => return,
        };
        let wire_msg = build_handshake_resp(local_idx, msg.sender_index, &ephemeral, &resp_payload[KEY_SIZE..]);

        if socket.send_to(&wire_msg, from).await.is_err() {
            return;
        }

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

        let peers_r = peers.read().await;
        if let Some(peer) = peers_r.get(&remote_pk) {
            let mut p = peer.lock().await;
            p.endpoint = Some(from);
            p.session = Some(session);
            p.state = PeerState::Established;
            p.last_seen = Some(Instant::now());
        }

        let mut by_idx = by_index.write().await;
        by_idx.insert(local_idx, remote_pk);
    }

    async fn handle_handshake_resp_static(
        data: &[u8],
        from: SocketAddr,
        peers: &Arc<RwLock<HashMap<Key, Arc<Mutex<PeerInternal>>>>>,
        by_index: &Arc<RwLock<HashMap<u32, Key>>>,
        pending: &Arc<Mutex<HashMap<u32, PendingHandshake>>>,
    ) {
        let msg = match parse_handshake_resp(data) {
            Ok(m) => m,
            Err(_) => return,
        };

        let pend = {
            let mut pending_map = pending.lock().await;
            match pending_map.remove(&msg.receiver_index) {
                Some(p) => p,
                None => return,
            }
        };

        let mut noise_msg = [0u8; KEY_SIZE + 16];
        noise_msg[..KEY_SIZE].copy_from_slice(&msg.ephemeral.0);
        noise_msg[KEY_SIZE..].copy_from_slice(&msg.empty_encrypted);

        let mut hs = pend.hs_state;
        if hs.read_message(&noise_msg).is_err() {
            let peers_r = peers.read().await;
            if let Some(peer) = peers_r.get(&pend.peer_pk) {
                let mut p = peer.lock().await;
                p.state = PeerState::Failed;
            }
            let _ = pend.done.send(Err("handshake failed".to_string()));
            return;
        }

        let (send_cs, recv_cs) = match hs.split() {
            Ok((s, r)) => (s, r),
            Err(_) => {
                let _ = pend.done.send(Err("split failed".to_string()));
                return;
            }
        };

        let session = Session::new(SessionConfig {
            local_index: pend.local_idx,
            remote_index: msg.sender_index,
            send_key: *send_cs.key(),
            recv_key: *recv_cs.key(),
            remote_pk: pend.peer_pk,
        });

        let peers_r = peers.read().await;
        if let Some(peer) = peers_r.get(&pend.peer_pk) {
            let mut p = peer.lock().await;
            p.endpoint = Some(from);
            p.session = Some(session);
            p.state = PeerState::Established;
            p.last_seen = Some(Instant::now());
        }

        let mut by_idx = by_index.write().await;
        by_idx.insert(pend.local_idx, pend.peer_pk);

        let _ = pend.done.send(Ok(()));
    }

    async fn handle_transport_static(
        data: &[u8],
        from: SocketAddr,
        peers: &Arc<RwLock<HashMap<Key, Arc<Mutex<PeerInternal>>>>>,
        by_index: &Arc<RwLock<HashMap<u32, Key>>>,
    ) -> Option<(Key, Vec<u8>)> {
        let msg = parse_transport_message(data).ok()?;

        let peer_pk = {
            let by_idx = by_index.read().await;
            *by_idx.get(&msg.receiver_index)?
        };

        let peers_r = peers.read().await;
        let peer = peers_r.get(&peer_pk)?;
        let mut p = peer.lock().await;

        let session = p.session.as_mut()?;

        let plaintext = session.decrypt(msg.ciphertext, msg.counter).ok()?;

        if p.endpoint.map(|e| e != from).unwrap_or(true) {
            p.endpoint = Some(from);
        }
        p.rx_bytes += data.len() as u64;
        p.last_seen = Some(Instant::now());

        Some((peer_pk, plaintext))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_async_udp_create() {
        let key = KeyPair::generate();
        let udp = AsyncUDP::new(key, "127.0.0.1:0", AsyncUdpConfig::default())
            .await
            .unwrap();
        assert!(udp.local_addr().is_ok());
    }

    #[test]
    fn test_config_default_uses_cpu_count() {
        let config = AsyncUdpConfig::default();
        assert_eq!(config.decrypt_workers, 0);
        let effective = config.effective_workers();
        assert!(effective > 0);
        assert!(effective <= 128);
    }

    #[tokio::test]
    async fn test_async_udp_handshake_and_transfer() {
        let server_key = KeyPair::generate();
        let client_key = KeyPair::generate();

        let server = AsyncUDP::new(server_key.clone(), "127.0.0.1:0", AsyncUdpConfig::default())
            .await
            .unwrap();
        let client = AsyncUDP::new(client_key.clone(), "127.0.0.1:0", AsyncUdpConfig::default())
            .await
            .unwrap();

        let server_addr = server.local_addr().unwrap();
        let client_addr = client.local_addr().unwrap();

        server.set_peer_endpoint(client_key.public, client_addr).await;
        client.set_peer_endpoint(server_key.public, server_addr).await;

        client.connect(&server_key.public).await.unwrap();

        let data = b"hello go-style pipeline!";
        client.write_to(&server_key.public, data).await.unwrap();

        let timeout = tokio::time::timeout(std::time::Duration::from_secs(2), server.read_from()).await;
        assert!(timeout.is_ok());
        let pkt = timeout.unwrap();
        assert!(pkt.is_some());
        let pkt = pkt.unwrap();
        assert_eq!(pkt.payload, data);
        assert_eq!(pkt.pk, client_key.public);
    }
}
