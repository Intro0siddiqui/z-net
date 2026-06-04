//! Lean Network Engine - Zero-Copy Rust Protocol Daemon
//! 
//! A single-threaded async I/O engine using mio and rustls.
//! Exposes C ABI for Zig integration.

use std::ffi::{c_char, c_void, c_uchar};
use std::ptr::null_mut;
use std::slice::{from_raw_parts, from_raw_parts_mut};
use std::collections::HashMap;
use std::io::{Read, Write, ErrorKind, IoSliceMut};
use std::net::ToSocketAddrs;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicBool, Ordering};

use mio::net::TcpStream;
use mio::{Events, Interest, Poll, Token};
use rustls::{ClientConfig, ClientConnection, RootCertStore};

pub mod protocols {
    pub mod http;
    pub mod http3;
    pub mod fetch;
    pub mod early_hints;
    pub mod compression;
    pub mod proxy;
    pub mod webtransport;
    pub mod auth;
}

pub mod security {
    pub mod dns;
    pub mod ocsp;
}

pub mod monitoring;

use crate::monitoring::NetworkMetrics;

// ============================================================
// Type Definitions
// ============================================================

/// Opaque handle to network engine
pub type NetEngineHandle = *mut c_void;

/// Opaque handle to connection
pub type ConnectionHandle = *mut c_void;

/// Opaque handle for Fetch
pub type FetchHandle = *mut c_void;

/// Opaque handle for Connection (Plan alias)
pub type ConnHandle = *mut c_void;

#[repr(C)]
pub struct FetchOptions {
    pub method: *const c_char,
    pub timeout: u32,
}

/// nsresult constants (match WPE/XPCOM)
const NS_OK: i32 = 0;
const NS_ERROR_FAILURE: i32 = -2147467259i32;

/// Error codes
#[repr(i32)]
#[derive(Debug, Clone, Copy)]
pub enum NetError {
    None = 0,
    InvalidHandle = -1,
    NotConnected = -2,
    IoError = -3,
    TlsError = -4,
    WouldBlock = -5,
    OutOfMemory = -6,
    AlreadyRunning = -7,
}

/// Connection state
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ConnState {
    Closed = 0,
    Connecting = 1,
    Handshaking = 2,
    Connected = 3,
    Closing = 4,
}

/// Maximum buffer size (16KB stack buffer)
pub const MAX_BUFFER_SIZE: usize = 16384;

#[repr(C)]
pub struct BodyRingDescriptor {
    pub buffer_ptr: *mut u8,
    pub capacity: usize,
    pub _pad1: [u8; 64],
    pub head: AtomicU64,
    pub _pad2: [u8; 64],
    pub tail: AtomicU64,
    pub _pad3: [u8; 64],
    pub is_closed: AtomicBool,
}

// ============================================================
// State Machines
// ============================================================

/// Connection context
struct Connection {
    stream: TcpStream,
    #[allow(dead_code)]
    state: ConnState,
    is_paused: bool,
    read_buf: [u8; MAX_BUFFER_SIZE],
    #[allow(dead_code)]
    write_buf: [u8; MAX_BUFFER_SIZE],
    host: String,
    #[allow(dead_code)]
    port: u16,
    tlsconn: Option<ClientConnection>,
}

impl Connection {
    fn new(stream: TcpStream, host: String, port: u16) -> Self {
        Self {
            stream,
            state: ConnState::Connecting,
            is_paused: false,
            read_buf: [0u8; MAX_BUFFER_SIZE],
            write_buf: [0u8; MAX_BUFFER_SIZE],
            host,
            port,
            tlsconn: None,
        }
    }
}

/// Opaque handle to a standalone TLS connection (used by the Zig `z_tls`
/// module for DNS-over-TLS and other direct TLS consumers).
pub type TlsHandle = *mut c_void;

/// Standalone TLS connection state. Owns a blocking `std::net::TcpStream`
/// and a rustls `ClientConnection`. The TcpStream is intentionally
/// blocking because DNS-over-TLS and other direct TLS users are
/// low-throughput, latency-tolerant, and benefit from a simpler API.
pub struct TlsState {
    stream: std::net::TcpStream,
    tls: ClientConnection,
    #[allow(dead_code)]
    host: String,
    #[allow(dead_code)]
    port: u16,
    is_closed: bool,
}

impl TlsState {
    fn new(host: String, port: u16) -> Result<Self, NetError> {
        let addrs = match format!("{}:{}", host, port).to_socket_addrs() {
            Ok(a) => a,
            Err(_) => return Err(NetError::IoError),
        };

        let mut stream = None;
        for addr in addrs {
            if let Ok(s) = std::net::TcpStream::connect(addr) {
                stream = Some(s);
                break;
            }
        }
        let stream = match stream {
            Some(s) => s,
            None => return Err(NetError::IoError),
        };
        let _ = stream.set_nodelay(true);

        // Build a per-connection ClientConfig with a process-wide default
        // root cert store. We clone the engine's config in the public FFI
        // path; here we just build a default one for standalone usage.
        let root_store = RootCertStore::empty();
        let config = ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();

        let server_name = match rustls::pki_types::ServerName::try_from(host.as_str()) {
            Ok(name) => name.to_owned(),
            Err(_) => return Err(NetError::TlsError),
        };

        let tls = match ClientConnection::new(Arc::new(config), server_name) {
            Ok(c) => c,
            Err(_) => return Err(NetError::TlsError),
        };

        Ok(Self {
            stream,
            tls,
            host,
            port,
            is_closed: false,
        })
    }
}

/// Network engine state
pub struct NetEngine {
    poll: Poll,
    events: Events,
    connections: HashMap<usize, Connection>,
    next_tls_id: usize,
    tls_states: HashMap<usize, Box<TlsState>>,
    next_conn_id: usize,
    tls_config: Arc<ClientConfig>,
    body_rings: HashMap<u64, *mut BodyRingDescriptor>,
    conn_body_rings: HashMap<usize, u64>,
    /// QUIC endpoints keyed by the engine-level `conn_id` returned from
    /// `net_http3_connect`. Each entry owns a `quinn_proto::Endpoint`
    /// plus a UDP socket (so the endpoint can be driven by the
    /// existing mio loop).
    quic_endpoints: HashMap<usize, QuicEndpointEntry>,
    /// Per-connection QUIC state. The keys are the same `conn_id` as
    /// `quic_endpoints`; a single endpoint can hold multiple
    /// connections in principle, but the current FFI surface only
    /// exposes one.
    quic_conns: HashMap<usize, QuicConnectionEntry>,
    next_quic_id: usize,
}

/// Owned state for a single QUIC endpoint. We keep the `mio::net::UdpSocket`
/// here so the existing `net_poll` loop can read incoming datagrams and
/// feed them to the `Endpoint`. The `Endpoint` itself is `!Sync`; we
/// serialize access through the engine.
#[allow(dead_code)]
struct QuicEndpointEntry {
    socket: mio::net::UdpSocket,
    endpoint: std::sync::Mutex<quinn_proto::Endpoint>,
    server_addr: std::net::SocketAddr,
    local_addr: std::net::SocketAddr,
}

/// Per-connection QUIC state. Quinn-proto identifies connections via
/// `ConnectionHandle` (an index into the `Endpoint`'s slab). We cache
/// the `Connection` so we can poll the streams and emit transmits.
#[allow(dead_code)]
struct QuicConnectionEntry {
    handle: quinn_proto::ConnectionHandle,
    connection: quinn_proto::Connection,
    remote: std::net::SocketAddr,
}

impl NetEngine {
    fn new() -> Result<Self, NetError> {
        let poll = Poll::new().map_err(|_| NetError::IoError)?;
        let events = Events::with_capacity(1024);
        
        // Install default crypto provider for rustls 0.23
        #[cfg(feature = "ring")]
        let _ = rustls::crypto::ring::default_provider().install_default();
        
        // Setup default TLS config
        let root_store = RootCertStore::empty();
        // Note: In production, you'd load system root certs here.
        
        let config = ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();
            
        Ok(Self {
            poll,
            events,
            connections: HashMap::new(),
            next_tls_id: 1,
            tls_states: HashMap::new(),
            next_conn_id: 1,
            tls_config: Arc::new(config),
            body_rings: HashMap::new(),
            conn_body_rings: HashMap::new(),
            quic_endpoints: HashMap::new(),
            quic_conns: HashMap::new(),
            next_quic_id: 1,
        })
    }
    
    fn poll(&mut self, timeout_ms: i32) -> i32 {
        // 1. Check for paused connections that can be resumed (Low Watermark: 50%)
        for (conn_id, &ring_id) in self.conn_body_rings.iter() {
            if let Some(conn) = self.connections.get_mut(conn_id) {
                if conn.is_paused {
                    if let Some(&ring_ptr) = self.body_rings.get(&ring_id) {
                        let ring = unsafe { &*ring_ptr };
                        let available_read = ring.head.load(Ordering::Acquire).wrapping_sub(ring.tail.load(Ordering::Acquire)) as usize;
                        if available_read < (ring.capacity * 50 / 100) {
                            // Resume polling
                            let _ = self.poll.registry().register(
                                &mut conn.stream,
                                Token(*conn_id),
                                Interest::READABLE | Interest::WRITABLE
                            );
                            conn.is_paused = false;
                        }
                    }
                }
            }
        }

        let timeout = if timeout_ms >= 0 {
            Some(std::time::Duration::from_millis(timeout_ms as u64))
        } else {
            None
        };
        
        match self.poll.poll(&mut self.events, timeout) {
            Ok(_) => {
                let mut count = 0;
                for _ in self.events.iter() {
                    count += 1;
                }
                count
            }
            Err(_) => -1,
        }
    }
}

// ============================================================
// C ABI Exports
// ============================================================

/// Create a new network engine
#[no_mangle]
pub extern "C" fn net_engine_create() -> NetEngineHandle {
    match NetEngine::new() {
        Ok(engine) => Box::into_raw(Box::new(engine)) as NetEngineHandle,
        Err(_) => null_mut(),
    }
}

/// Destroy a network engine
#[no_mangle]
pub extern "C" fn net_engine_destroy(handle: NetEngineHandle) {
    if !handle.is_null() {
        unsafe {
            let _ = Box::from_raw(handle as *mut NetEngine);
        }
    }
}

/// Connect to a host
#[no_mangle]
pub extern "C" fn net_connect(
    engine_handle: NetEngineHandle,
    host: *const c_char,
    port: u16,
) -> ConnectionHandle {
    if engine_handle.is_null() {
        return null_mut();
    }
    
    let engine = unsafe { &mut *(engine_handle as *mut NetEngine) };
    
    let host_str = unsafe {
        std::ffi::CStr::from_ptr(host)
            .to_string_lossy()
            .into_owned()
    };
    
    let addr_str = format!("{}:{}", host_str, port);
    let addrs = match addr_str.to_socket_addrs() {
        Ok(a) => a,
        Err(_) => return null_mut(),
    };
    
    let mut stream = None;
    for addr in addrs {
        if let Ok(s) = TcpStream::connect(addr) {
            stream = Some(s);
            break;
        }
    }
    
    let mut stream = match stream {
        Some(s) => s,
        None => return null_mut(),
    };
    
    // Enable TCP_NODELAY to avoid 40ms stall
    let _ = stream.set_nodelay(true);
    
    let conn_id = engine.next_conn_id;
    engine.next_conn_id += 1;
    
    if engine.poll.registry().register(
        &mut stream,
        Token(conn_id),
        Interest::READABLE | Interest::WRITABLE
    ).is_err() {
        return null_mut();
    }
    
    let mut conn = Connection::new(stream, host_str, port);
    
    // Initialize TLS only if port is 443
    if port == 443 {
        if let Ok(server_name) = rustls::pki_types::ServerName::try_from(conn.host.as_str()) {
            if let Ok(tls) = ClientConnection::new(engine.tls_config.clone(), server_name.to_owned()) {
                conn.tlsconn = Some(tls);
            }
        }
    }
    
    engine.connections.insert(conn_id, conn);
    conn_id as ConnectionHandle
}

/// Close a connection
#[no_mangle]
pub extern "C" fn net_close(engine_handle: NetEngineHandle, conn_handle: ConnectionHandle) -> i32 {
    if engine_handle.is_null() || conn_handle.is_null() {
        return NS_ERROR_FAILURE;
    }
    
    let engine = unsafe { &mut *(engine_handle as *mut NetEngine) };
    let conn_id = conn_handle as usize;
    
    if engine.connections.remove(&conn_id).is_some() {
        NS_OK
    } else {
        NS_ERROR_FAILURE
    }
}

/// Read data from connection
#[no_mangle]
pub extern "C" fn net_read(
    engine_handle: NetEngineHandle,
    conn_handle: ConnectionHandle,
    buffer: *mut c_uchar,
    buffer_len: usize,
    bytes_read: *mut usize,
) -> i32 {
    if engine_handle.is_null() || conn_handle.is_null() || buffer.is_null() {
        return NS_ERROR_FAILURE;
    }
    
    let engine = unsafe { &mut *(engine_handle as *mut NetEngine) };
    let conn_id = conn_handle as usize;

    // 1. Check if we have a bound BodyRing for zero-copy Pull
    if let Some(&ring_id) = engine.conn_body_rings.get(&conn_id) {
        if let Some(&ring_ptr) = engine.body_rings.get(&ring_id) {
            let ring = unsafe { &*ring_ptr };
            let connection = match engine.connections.get_mut(&conn_id) {
                Some(c) => c,
                None => return NS_ERROR_FAILURE,
            };

            let head = ring.head.load(Ordering::Acquire);
            let tail = ring.tail.load(Ordering::Acquire);
            if head.wrapping_sub(tail) >= ring.capacity as u64 {
                return NS_ERROR_FAILURE;
            }
            let head_idx = (head % ring.capacity as u64) as usize;
            let tail_idx = (tail % ring.capacity as u64) as usize;

            let mut bufs = [IoSliceMut::new(&mut []), IoSliceMut::new(&mut [])];
            let n_bufs = if head_idx >= tail_idx {
                bufs[0] = IoSliceMut::new(unsafe { std::slice::from_raw_parts_mut(ring.buffer_ptr.add(head_idx), ring.capacity - head_idx) });
                bufs[1] = IoSliceMut::new(unsafe { std::slice::from_raw_parts_mut(ring.buffer_ptr, tail_idx) });
                2
            } else {
                bufs[0] = IoSliceMut::new(unsafe { std::slice::from_raw_parts_mut(ring.buffer_ptr.add(head_idx), tail_idx - head_idx) });
                1
            };

            match connection.stream.read_vectored(&mut bufs[..n_bufs]) {
                Ok(0) => return NS_ERROR_FAILURE,
                Ok(n) => {
                    ring.head.fetch_add(n as u64, Ordering::Release);
                    unsafe {
                        if !bytes_read.is_null() {
                            *bytes_read = n;
                        }
                    }

                    // Backpressure: 95% High Watermark
                    let available_read = ring.head.load(Ordering::Acquire).wrapping_sub(ring.tail.load(Ordering::Acquire)) as usize;
                    if available_read > (ring.capacity * 95 / 100) {
                        let _ = engine.poll.registry().deregister(&mut connection.stream);
                        connection.is_paused = true;
                    }
                    return NS_OK;
                }
                Err(ref e) if e.kind() == ErrorKind::WouldBlock => return NS_ERROR_FAILURE,
                Err(_) => return NS_ERROR_FAILURE,
            }
        }
    }
    
    let connection = match engine.connections.get_mut(&conn_id) {
        Some(c) => c,
        None => return NS_ERROR_FAILURE,
    };
    
    let dst = unsafe { from_raw_parts_mut(buffer, buffer_len) };
    
    if let Some(ref mut tlsconn) = connection.tlsconn {
        // 1. Try to read from socket and feed to TLS
        match connection.stream.read(&mut connection.read_buf) {
            Ok(0) => return NS_ERROR_FAILURE,
            Ok(n) => {
                let mut cursor = std::io::Cursor::new(&connection.read_buf[..n]);
                if tlsconn.read_tls(&mut cursor).is_err() {
                    return NS_ERROR_FAILURE;
                }
                if tlsconn.process_new_packets().is_err() {
                    return NS_ERROR_FAILURE;
                }
            }
            Err(ref e) if e.kind() == ErrorKind::WouldBlock => {
                // No new data, check if we have pending plaintext
            }
            Err(_) => return NS_ERROR_FAILURE,
        }
        
        // 2. Read plaintext from TLS
        match tlsconn.reader().read(dst) {
            Ok(n) => {
                unsafe {
                    if !bytes_read.is_null() {
                        *bytes_read = n;
                    }
                }
                return NS_OK;
            }
            Err(ref e) if e.kind() == ErrorKind::WouldBlock => {
                return NS_ERROR_FAILURE;
            }
            Err(_) => return NS_ERROR_FAILURE,
        }
    }
    
    // Non-TLS path
    match connection.stream.read(dst) {
        Ok(n) => {
            unsafe {
                if !bytes_read.is_null() {
                    *bytes_read = n;
                }
            }
            NS_OK
        }
        Err(ref e) if e.kind() == ErrorKind::WouldBlock => NS_ERROR_FAILURE,
        Err(_) => NS_ERROR_FAILURE,
    }
}

/// Write data to connection
#[no_mangle]
pub extern "C" fn net_write(
    engine_handle: NetEngineHandle,
    conn_handle: ConnectionHandle,
    data: *const c_uchar,
    data_len: usize,
    bytes_written: *mut usize,
) -> i32 {
    if engine_handle.is_null() || conn_handle.is_null() || data.is_null() {
        return NS_ERROR_FAILURE;
    }
    
    let engine = unsafe { &mut *(engine_handle as *mut NetEngine) };
    let conn_id = conn_handle as usize;
    
    let connection = match engine.connections.get_mut(&conn_id) {
        Some(c) => c,
        None => return NS_ERROR_FAILURE,
    };
    
    let src = unsafe { from_raw_parts(data, data_len) };
    
    if let Some(ref mut tlsconn) = connection.tlsconn {
        // 1. Write plaintext to TLS
        let n = match tlsconn.writer().write(src) {
            Ok(n) => n,
            Err(_) => return NS_ERROR_FAILURE,
        };
        
        // 2. Flush ciphertext to socket
        while tlsconn.wants_write() {
            match tlsconn.write_tls(&mut connection.stream) {
                Ok(_) => {},
                Err(ref e) if e.kind() == ErrorKind::WouldBlock => break,
                Err(_) => return NS_ERROR_FAILURE,
            }
        }
        
        unsafe {
            if !bytes_written.is_null() {
                *bytes_written = n;
            }
        }
        return NS_OK;
    }
    
    // Non-TLS path
    match connection.stream.write(src) {
        Ok(n) => {
            unsafe {
                if !bytes_written.is_null() {
                    *bytes_written = n;
                }
            }
            NS_OK
        }
        Err(ref e) if e.kind() == ErrorKind::WouldBlock => NS_ERROR_FAILURE,
        Err(_) => NS_ERROR_FAILURE,
    }
}

/// Poll for readiness
#[no_mangle]
pub extern "C" fn net_poll(
    engine_handle: NetEngineHandle,
    timeout_ms: i32,
) -> i32 {
    if engine_handle.is_null() {
        return NS_ERROR_FAILURE;
    }
    
    let engine = unsafe { &mut *(engine_handle as *mut NetEngine) };
    engine.poll(timeout_ms)
}

/// Get connection state
#[no_mangle]
pub extern "C" fn net_conn_state(
    _engine_handle: NetEngineHandle,
    conn_handle: ConnectionHandle,
) -> i32 {
    if conn_handle.is_null() {
        return ConnState::Closed as i32;
    }
    // Simplification for the C ABI
    ConnState::Connected as i32
}

// ============================================================
// Plan Extensions
// ============================================================

#[no_mangle]
pub extern "C" fn net_fetch_create(_url: *const c_char, _options: *const FetchOptions) -> FetchHandle {
    // Scaffolding implementation
    null_mut()
}

#[no_mangle]
pub extern "C" fn net_http3_connect(
    engine_handle: NetEngineHandle,
    host: *const c_char,
    port: u16,
) -> ConnHandle {
    if engine_handle.is_null() {
        return null_mut();
    }

    let engine = unsafe { &mut *(engine_handle as *mut NetEngine) };

    let host_str = unsafe {
        let cstr = std::ffi::CStr::from_ptr(host);
        cstr.to_string_lossy().into_owned()
    };

    let addr_str = format!("{}:{}", host_str, port);
    let addrs = match addr_str.to_socket_addrs() {
        Ok(a) => a,
        Err(_) => return null_mut(),
    };

    let server_addr = match addrs.into_iter().next() {
        Some(a) => a,
        None => return null_mut(),
    };

    // HTTP/3 (QUIC) requires a UDP socket. Mio support for UDP is standard.
    let socket = match std::net::UdpSocket::bind("0.0.0.0:0") {
        Ok(s) => s,
        Err(_) => return null_mut(),
    };

    if socket.set_nonblocking(true).is_err() {
        return null_mut();
    }

    let local_addr = match socket.local_addr() {
        Ok(a) => a,
        Err(_) => return null_mut(),
    };

    let mut udp_stream = match mio::net::UdpSocket::from_std(socket) {
        s => s,
    };

    let conn_id = engine.next_quic_id;
    engine.next_quic_id += 1;

    if engine
        .poll
        .registry()
        .register(
            &mut udp_stream,
            Token(conn_id),
            Interest::READABLE | Interest::WRITABLE,
        )
        .is_err()
    {
        return null_mut();
    }

    // Build the quinn-proto endpoint. We use the default `EndpointConfig`
    // and a fresh `ClientConfig` backed by rustls 0.20 (the version
    // pinned by quinn-proto 0.11). The engine's own `tls_config` is
    // rustls 0.23, so we cannot share it.
    let endpoint_config = Arc::new(quinn_proto::EndpointConfig::default());
    let mut endpoint = quinn_proto::Endpoint::new(endpoint_config, None, false, None);

    // quinn-proto re-exports rustls 0.20, so we build a self-signed
    // client config with the default crypto provider and the
    // `webpki` roots. In production we would load a platform root
    // store; for the engine scaffolding we use the empty store and
    // rely on QUIC's built-in certificate verification (which can be
    // enabled per-connection via `ClientConfig`).
    let provider = Arc::new(quinn_proto::rustls::crypto::ring::default_provider());
    let roots = quinn_proto::rustls::RootCertStore::empty();
    let rustls_client_config =
        quinn_proto::rustls::ClientConfig::builder_with_provider(provider.clone())
            .with_protocol_versions(&[&quinn_proto::rustls::version::TLS13])
            .expect("TLS 1.3 supported")
            .with_root_certificates(roots)
            .with_no_client_auth();
    let quic_crypto = match quinn_proto::crypto::rustls::QuicClientConfig::try_from(Arc::new(rustls_client_config)) {
        Ok(c) => Arc::new(c),
        Err(_) => return null_mut(),
    };

    let mut transport = quinn_proto::TransportConfig::default();
    transport.max_idle_timeout(quinn_proto::IdleTimeout::try_from(
        std::time::Duration::from_secs(30),
    ).ok());
    let client_config = quinn_proto::ClientConfig::new(quic_crypto);
    let mut client_config = client_config;
    client_config.transport_config(Arc::new(transport));

    // Initiate the connection. The returned `Connection` is in the
    // `Handshaking` state and will be driven forward by
    // `net_http3_drive` on subsequent calls.
    let now = std::time::Instant::now();
    let (ch, connection) = match endpoint.connect(now, client_config, server_addr, &host_str) {
        Ok(c) => c,
        Err(_) => return null_mut(),
    };

    engine.quic_endpoints.insert(
        conn_id,
        QuicEndpointEntry {
            socket: udp_stream,
            endpoint: std::sync::Mutex::new(endpoint),
            server_addr,
            local_addr,
        },
    );
    engine.quic_conns.insert(
        conn_id,
        QuicConnectionEntry {
            handle: ch,
            connection,
            remote: server_addr,
        },
    );

    conn_id as ConnHandle
}

#[no_mangle]
pub extern "C" fn net_body_ring_register(
    engine_handle: NetEngineHandle,
    id: u64,
    ptr: *mut BodyRingDescriptor,
) -> i32 {
    if engine_handle.is_null() {
        return NS_ERROR_FAILURE;
    }
    let engine = unsafe { &mut *(engine_handle as *mut NetEngine) };
    engine.body_rings.insert(id, ptr);
    0
}

#[no_mangle]
pub extern "C" fn net_body_ring_unregister(engine_handle: NetEngineHandle, id: u64) -> i32 {
    if engine_handle.is_null() {
        return NS_ERROR_FAILURE;
    }
    let engine = unsafe { &mut *(engine_handle as *mut NetEngine) };
    engine.body_rings.remove(&id);
    0
}

#[no_mangle]
pub extern "C" fn net_conn_bind_body_ring(
    engine_handle: NetEngineHandle,
    conn_handle: ConnectionHandle,
    id: u64,
) -> i32 {
    if engine_handle.is_null() || conn_handle.is_null() {
        return NS_ERROR_FAILURE;
    }
    let engine = unsafe { &mut *(engine_handle as *mut NetEngine) };
    let conn_id = conn_handle as usize;
    engine.conn_body_rings.insert(conn_id, id);
    0
}

#[no_mangle]
pub extern "C" fn net_get_metrics(engine_handle: NetEngineHandle) -> *const NetworkMetrics {
    if engine_handle.is_null() {
        return std::ptr::null();
    }
    
    // In a real implementation, this would return a pointer to metrics stored in the engine.
    // We use Box::into_raw to provide a stable pointer for this scaffolding.
    let metrics = Box::new(NetworkMetrics {
        total_packets_sent: 0,
        total_packets_received: 0,
        packet_loss_rate: 0.0,
        average_latency_ms: 0.0,
        jitter_ms: 0.0,
        throughput_mbps: 0.0,
        connection_quality_score: 100.0,
    });
    Box::into_raw(metrics)
}

// ============================================================
// Standalone TLS FFI (consumed by Zig `z_tls`)
// ============================================================
//
// The standalone TLS surface lets the Zig `z_tls` module obtain a
// rustls-backed TLS connection without owning a TcpStream directly.
// Each `TlsHandle` is registered in the engine's `tls_states` map and
// cleaned up by `net_tls_close`.
//
// All call sites are synchronous and blocking; the underlying
// `std::net::TcpStream` is created in `TlsState::new` and is fully
// owned by the TlsState. This is appropriate for DNS-over-TLS and
// other direct TLS consumers that are latency-tolerant and
// low-throughput.

/// Create a new standalone TLS connection and drive the rustls
/// handshake to completion. Returns a heap-allocated opaque handle
/// that the caller must release with `net_tls_close`.
#[no_mangle]
pub extern "C" fn net_tls_create(
    engine_handle: NetEngineHandle,
    host: *const c_char,
    port: u16,
) -> TlsHandle {
    if engine_handle.is_null() || host.is_null() {
        return null_mut();
    }
    let engine = unsafe { &mut *(engine_handle as *mut NetEngine) };

    let host_str = unsafe {
        match std::ffi::CStr::from_ptr(host).to_str() {
            Ok(s) => s.to_owned(),
            Err(_) => return null_mut(),
        }
    };

    let mut state = match TlsState::new(host_str, port) {
        Ok(s) => s,
        Err(_) => return null_mut(),
    };

    // Drive the rustls handshake. We loop until we either complete the
    // handshake or hit a non-WouldBlock I/O error.
    use std::io::Read as IoRead;
    while state.tls.is_handshaking() {
        // Pump bytes from TLS into the socket.
        if state.tls.wants_write() {
            match state.tls.write_tls(&mut state.stream) {
                Ok(_) => {}
                Err(ref e) if e.kind() == ErrorKind::WouldBlock => {}
                Err(_) => return null_mut(),
            }
        }
        // Pump bytes from the socket into TLS.
        if state.tls.wants_read() {
            let mut buf = [0u8; 16 * 1024];
            match state.stream.read(&mut buf) {
                Ok(0) => return null_mut(),
                Ok(n) => {
                    let mut cursor = std::io::Cursor::new(&buf[..n]);
                    if state.tls.read_tls(&mut cursor).is_err() {
                        return null_mut();
                    }
                    if state.tls.process_new_packets().is_err() {
                        return null_mut();
                    }
                }
                Err(ref e) if e.kind() == ErrorKind::WouldBlock => {
                    // Spurious wakeup; loop again to check progress.
                    break;
                }
                Err(_) => return null_mut(),
            }
        }
        if !state.tls.is_handshaking() {
            break;
        }
        if !state.tls.wants_read() && !state.tls.wants_write() {
            // No forward progress possible; bail out to avoid spin.
            break;
        }
    }

    let tls_id = engine.next_tls_id;
    engine.next_tls_id += 1;
    engine.tls_states.insert(tls_id, Box::new(state));

    tls_id as TlsHandle
}

/// Read plaintext from a TLS connection. On success returns 0 and
/// writes the number of bytes into `*bytes_read`. Returns the
/// engine error code on failure.
#[no_mangle]
pub extern "C" fn net_tls_read(
    engine_handle: NetEngineHandle,
    tls_handle: TlsHandle,
    buffer: *mut c_uchar,
    buffer_len: usize,
    bytes_read: *mut usize,
) -> i32 {
    if engine_handle.is_null() || tls_handle.is_null() || buffer.is_null() {
        return NS_ERROR_FAILURE;
    }
    let engine = unsafe { &mut *(engine_handle as *mut NetEngine) };
    let tls_id = tls_handle as usize;
    let state = match engine.tls_states.get_mut(&tls_id) {
        Some(s) => s,
        None => return NS_ERROR_FAILURE,
    };
    if state.is_closed {
        return NS_ERROR_FAILURE;
    }

    use std::io::Read as IoRead;
    let dst = unsafe { from_raw_parts_mut(buffer, buffer_len) };

    // Drive TLS forward progress: read from socket into TLS, then
    // expose plaintext to the caller.
    let mut tmp = [0u8; 16 * 1024];
    loop {
        match state.stream.read(&mut tmp) {
            Ok(0) => return NS_ERROR_FAILURE,
            Ok(n) => {
                let mut cursor = std::io::Cursor::new(&tmp[..n]);
                if state.tls.read_tls(&mut cursor).is_err() {
                    return NS_ERROR_FAILURE;
                }
                if state.tls.process_new_packets().is_err() {
                    return NS_ERROR_FAILURE;
                }
            }
            Err(ref e) if e.kind() == ErrorKind::WouldBlock => break,
            Err(_) => return NS_ERROR_FAILURE,
        }
    }

    match state.tls.reader().read(dst) {
        Ok(0) => NS_ERROR_FAILURE,
        Ok(n) => {
            unsafe {
                if !bytes_read.is_null() {
                    *bytes_read = n;
                }
            }
            NS_OK
        }
        Err(ref e) if e.kind() == ErrorKind::WouldBlock => NS_ERROR_FAILURE,
        Err(_) => NS_ERROR_FAILURE,
    }
}

/// Write plaintext to a TLS connection. Returns 0 on success and
/// writes the number of plaintext bytes accepted into `*bytes_written`.
#[no_mangle]
pub extern "C" fn net_tls_write(
    engine_handle: NetEngineHandle,
    tls_handle: TlsHandle,
    data: *const c_uchar,
    data_len: usize,
    bytes_written: *mut usize,
) -> i32 {
    if engine_handle.is_null() || tls_handle.is_null() || data.is_null() {
        return NS_ERROR_FAILURE;
    }
    let engine = unsafe { &mut *(engine_handle as *mut NetEngine) };
    let tls_id = tls_handle as usize;
    let state = match engine.tls_states.get_mut(&tls_id) {
        Some(s) => s,
        None => return NS_ERROR_FAILURE,
    };
    if state.is_closed {
        return NS_ERROR_FAILURE;
    }

    use std::io::Write as IoWrite;
    let src = unsafe { from_raw_parts(data, data_len) };

    let n = match state.tls.writer().write(src) {
        Ok(n) => n,
        Err(_) => return NS_ERROR_FAILURE,
    };

    while state.tls.wants_write() {
        match state.tls.write_tls(&mut state.stream) {
            Ok(_) => {}
            Err(ref e) if e.kind() == ErrorKind::WouldBlock => break,
            Err(_) => return NS_ERROR_FAILURE,
        }
    }

    unsafe {
        if !bytes_written.is_null() {
            *bytes_written = n;
        }
    }
    NS_OK
}

/// Return the negotiated TLS protocol version as a 4-character
/// identifier: `0x0303` for TLS 1.2, `0x0304` for TLS 1.3. Returns
/// 0 on failure.
#[no_mangle]
pub extern "C" fn net_tls_protocol_version(
    engine_handle: NetEngineHandle,
    tls_handle: TlsHandle,
) -> u16 {
    if engine_handle.is_null() || tls_handle.is_null() {
        return 0;
    }
    let engine = unsafe { &mut *(engine_handle as *mut NetEngine) };
    let tls_id = tls_handle as usize;
    let state = match engine.tls_states.get(&tls_id) {
        Some(s) => s,
        None => return 0,
    };
    match state.tls.protocol_version() {
        Some(rustls::ProtocolVersion::TLSv1_2) => 0x0303,
        Some(rustls::ProtocolVersion::TLSv1_3) => 0x0304,
        _ => 0,
    }
}

/// Close a TLS connection and release the handle.
#[no_mangle]
pub extern "C" fn net_tls_close(engine_handle: NetEngineHandle, tls_handle: TlsHandle) -> i32 {
    if engine_handle.is_null() || tls_handle.is_null() {
        return NS_ERROR_FAILURE;
    }
    let engine = unsafe { &mut *(engine_handle as *mut NetEngine) };
    let tls_id = tls_handle as usize;
    match engine.tls_states.remove(&tls_id) {
        Some(mut state) => {
            state.is_closed = true;
            let _ = state.stream.shutdown(std::net::Shutdown::Both);
            NS_OK
        }
        None => NS_ERROR_FAILURE,
    }
}

/// Rustls verification result.
#[repr(C)]
pub enum TlsVerifyResult {
    Accepted = 0,
    Rejected = -1,
    NotEstablished = -2,
}

/// Returns rustls's WebPKI verification result after the handshake.
#[no_mangle]
pub extern "C" fn net_tls_verify_result(
    engine_handle: NetEngineHandle,
    tls_handle: TlsHandle,
) -> TlsVerifyResult {
    if engine_handle.is_null() || tls_handle.is_null() {
        return TlsVerifyResult::Rejected;
    }
    let engine = unsafe { &*(engine_handle as *mut NetEngine) };
    let tls_id = tls_handle as usize;
    match engine.tls_states.get(&tls_id) {
        Some(state) => {
            if state.is_closed {
                return TlsVerifyResult::Rejected;
            }
            if state.tls.is_handshaking() {
                return TlsVerifyResult::NotEstablished;
            }
            match state.tls.peer_certificates() {
                Some(_) => TlsVerifyResult::Accepted,
                None => TlsVerifyResult::Rejected,
            }
        }
        None => TlsVerifyResult::Rejected,
    }
}

/// Copies the peer certificate (first cert, DER-encoded) into the
/// caller-provided buffer. Returns bytes written, or -1 on error.
#[no_mangle]
pub extern "C" fn net_tls_peer_certificate(
    engine_handle: NetEngineHandle,
    tls_handle: TlsHandle,
    out: *mut u8,
    out_len: usize,
) -> i32 {
    if engine_handle.is_null() || tls_handle.is_null() || out.is_null() {
        return -1;
    }
    let engine = unsafe { &*(engine_handle as *mut NetEngine) };
    let tls_id = tls_handle as usize;
    match engine.tls_states.get(&tls_id) {
        Some(state) => {
            match state.tls.peer_certificates() {
                Some(certs) if !certs.is_empty() => {
                    let first_cert = &certs[0];
                    let der = first_cert.as_ref();
                    let len = der.len().min(out_len);
                    unsafe {
                        std::ptr::copy_nonoverlapping(der.as_ptr(), out, len);
                    }
                    len as i32
                }
                _ => -1,
            }
        }
        None => -1,
    }
}

// ============================================================
// QUIC / HTTP/3 FFI (consumed by Zig `z_http3`)
// ============================================================
//
// The QUIC surface drives the underlying quinn-proto state machine.
// `net_http3_drive` reads any pending datagrams from the registered
// UDP socket, feeds them into the `Endpoint`, then drains outgoing
// transmits from each `Connection` and writes them to the socket.
// HTTP/3 framing (HEADERS, DATA, QPACK) is the responsibility of
// `z_http3`; this layer only carries the QUIC transport.

/// Pump the QUIC state forward: process incoming datagrams on the
/// UDP socket, advance the connection handshake, and emit any
/// outgoing datagrams the connection wants to send. Returns the
/// number of datagrams processed, or `-1` on error.
#[no_mangle]
pub extern "C" fn net_http3_drive(engine_handle: NetEngineHandle, conn_handle: ConnHandle) -> i32 {
    if engine_handle.is_null() || conn_handle.is_null() {
        return -1;
    }
    let engine = unsafe { &mut *(engine_handle as *mut NetEngine) };
    let conn_id = conn_handle as usize;

    let endpoint_entry = match engine.quic_endpoints.get_mut(&conn_id) {
        Some(e) => e,
        None => return -1,
    };

    let now = std::time::Instant::now();
    let mut processed: i32 = 0;
    let mut rx_buf = [0u8; 2048];
    let mut tx_buf: Vec<u8> = Vec::new();

    // Read incoming datagrams off the UDP socket and feed them to
    // the endpoint. We do non-blocking reads so a stalled socket
    // does not block the engine.
    loop {
        match endpoint_entry.socket.recv_from(&mut rx_buf) {
            Ok((n, remote)) => {
                let data = bytes::BytesMut::from(&rx_buf[..n]);
                let event = {
                    let mut endpoint = endpoint_entry.endpoint.lock().unwrap();
                    endpoint.handle(now, remote, None, None, data, &mut tx_buf)
                };
                if let Some(quinn_proto::DatagramEvent::ConnectionEvent(ch, conn_event)) = event {
                    if let Some(conn_entry) = engine.quic_conns.get_mut(&conn_id) {
                        if conn_entry.handle == ch {
                            let _ = conn_entry.connection.handle_event(conn_event);
                        }
                    }
                }
                // `NewConnection` and `Response` are not produced for
                // an outbound client flow; the endpoint simply
                // discards them and the next transmit poll will pick
                // up any state changes.
                processed += 1;
            }
            Err(ref e) if e.kind() == ErrorKind::WouldBlock => break,
            Err(_) => break,
        }
    }

    // Poll the connection for outgoing transmits. Quinn-proto packs
    // the datagram into `tx_buf`; we send it on the registered UDP
    // socket.
    if let Some(conn_entry) = engine.quic_conns.get_mut(&conn_id) {
        // Connection-level timeouts / handshakes first.
        while let Some(timeout) = conn_entry.connection.poll_timeout() {
            if timeout > now {
                break;
            }
            conn_entry.connection.handle_timeout(now);
        }
        let max_datagrams = 1usize;
        while let Some(transmit) = conn_entry.connection.poll_transmit(now, max_datagrams, &mut tx_buf) {
            if (transmit.size) > tx_buf.len() {
                break;
            }
            let bytes = &tx_buf[..transmit.size];
            let _ = endpoint_entry.socket.send_to(bytes, transmit.destination);
            tx_buf.clear();
        }
    }

    processed
}

/// Close a QUIC connection and release all associated state.
#[no_mangle]
pub extern "C" fn net_http3_close(engine_handle: NetEngineHandle, conn_handle: ConnHandle) -> i32 {
    if engine_handle.is_null() || conn_handle.is_null() {
        return NS_ERROR_FAILURE;
    }
    let engine = unsafe { &mut *(engine_handle as *mut NetEngine) };
    let conn_id = conn_handle as usize;

    // Drain the connection cleanly so the peer sees a CONNECTION_CLOSE.
    if let Some(mut conn_entry) = engine.quic_conns.remove(&conn_id) {
        let now = std::time::Instant::now();
        conn_entry
            .connection
            .close(now, 0u32.into(), bytes::Bytes::from_static(b"client closed"));
    }
    if let Some(mut endpoint_entry) = engine.quic_endpoints.remove(&conn_id) {
        let _ = engine.poll.registry().deregister(&mut endpoint_entry.socket);
    }
    NS_OK
}
