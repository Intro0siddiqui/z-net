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
use std::sync::atomic::{AtomicU64, AtomicBool, AtomicI32, AtomicU32, Ordering};

use std::net::{TcpStream, UdpSocket};
use compio_driver::{AsRawFd, Proactor};
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
    pub mod dns;
    pub mod websocket;
    pub mod quic;
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
    pub _pad3: [u8; 48],
    pub pause_fd: AtomicI32,
    pub futex_word: AtomicU32,
    pub is_closed: AtomicBool,
}

impl BodyRingDescriptor {
    pub fn available_write(&self) -> usize {
        let head = self.head.load(Ordering::Acquire);
        let tail = self.tail.load(Ordering::Acquire);
        let used = head.wrapping_sub(tail) as usize;
        if used >= self.capacity { 0 } else { self.capacity - used }
    }

    pub fn available_read(&self) -> usize {
        let head = self.head.load(Ordering::Acquire);
        let tail = self.tail.load(Ordering::Acquire);
        head.wrapping_sub(tail) as usize
    }

    pub fn should_stop_reading(&self) -> bool {
        self.available_read() > (self.capacity * 95 / 100)
    }

    pub fn should_resume_reading(&self) -> bool {
        self.available_read() < (self.capacity * 50 / 100)
    }

    pub fn signal_resume(&self) {
        let pfd = self.pause_fd.load(Ordering::Acquire);
        if pfd >= 0 {
            let val: u64 = 1;
            unsafe {
                libc::write(pfd, &val as *const u64 as *const libc::c_void, 8);
            }
        }
        self.futex_word.fetch_add(1, Ordering::Release);
        unsafe {
            libc::syscall(
                libc::SYS_futex,
                &self.futex_word as *const AtomicU32,
                libc::FUTEX_WAKE,
                1,
                std::ptr::null::<libc::timespec>(),
            );
        }
    }

    pub fn wait_drain(&self, timeout_ms: i32) {
        let pfd = self.pause_fd.load(Ordering::Acquire);
        if pfd >= 0 {
            let mut pfd_poll = libc::pollfd {
                fd: pfd,
                events: libc::POLLIN,
                revents: 0,
            };
            unsafe {
                libc::poll(&mut pfd_poll, 1, timeout_ms);
                let mut val: u64 = 0;
                libc::read(pfd, &mut val as *mut u64 as *mut libc::c_void, 8);
            }
        } else {
            let cur = self.futex_word.load(Ordering::Acquire);
            let ts = libc::timespec {
                tv_sec: 0,
                tv_nsec: (timeout_ms as i64 * 1_000_000).min(10_000_000),
            };
            unsafe {
                libc::syscall(
                    libc::SYS_futex,
                    &self.futex_word as *const AtomicU32,
                    libc::FUTEX_WAIT,
                    cur,
                    &ts,
                );
            }
        }
    }

    pub fn write_slice(&self, data: &[u8]) -> usize {
        let avail = self.available_write();
        let to_write = data.len().min(avail);
        if to_write == 0 {
            return 0;
        }
        let head = self.head.load(Ordering::Acquire);
        let head_idx = (head % self.capacity as u64) as usize;
        let first_chunk = to_write.min(self.capacity - head_idx);
        let second_chunk = to_write - first_chunk;

        unsafe {
            std::ptr::copy_nonoverlapping(data.as_ptr(), self.buffer_ptr.add(head_idx), first_chunk);
            if second_chunk > 0 {
                std::ptr::copy_nonoverlapping(data.as_ptr().add(first_chunk), self.buffer_ptr, second_chunk);
            }
        }
        self.head.fetch_add(to_write as u64, Ordering::Release);
        to_write
    }
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
    fn new(host: String, port: u16, config: Arc<ClientConfig>) -> Result<Self, NetError> {
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

        // Reuse the engine's client config so the trust anchors and the
        // resumption session store are shared across connections.
        let server_name = match rustls::pki_types::ServerName::try_from(host.as_str()) {
            Ok(name) => name.to_owned(),
            Err(_) => return Err(NetError::TlsError),
        };

        let tls = match ClientConnection::new(config, server_name) {
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
    pub proactor: Proactor,
    connections: HashMap<usize, Connection>,
    next_tls_id: usize,
    tls_states: HashMap<usize, Box<TlsState>>,
    next_conn_id: usize,
    tls_config: Arc<ClientConfig>,
    pub http_engine: protocols::http::client::HttpClientEngine,
    body_rings: HashMap<u64, *mut BodyRingDescriptor>,
    conn_body_rings: HashMap<usize, u64>,
    quic_endpoints: HashMap<usize, QuicEndpointEntry>,
    quic_conns: HashMap<usize, QuicConnectionEntry>,
    next_quic_id: usize,
    pub last_error: std::sync::Mutex<Option<String>>,
}

/// Owned state for a single QUIC endpoint.
#[allow(dead_code)]
struct QuicEndpointEntry {
    socket: UdpSocket,
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

/// Helper to parse PEM certificates from a file on disk (e.g. system CA bundle).
fn load_pem_certs(path: &str) -> Vec<rustls::pki_types::CertificateDer<'static>> {
    let mut certs = Vec::new();
    if let Ok(content) = std::fs::read_to_string(path) {
        let mut in_cert = false;
        let mut b64 = String::new();
        for line in content.lines() {
            let line = line.trim();
            if line == "-----BEGIN CERTIFICATE-----" {
                in_cert = true;
                b64.clear();
            } else if line == "-----END CERTIFICATE-----" {
                if in_cert {
                    use base64::Engine;
                    if let Ok(der) = base64::engine::general_purpose::STANDARD.decode(&b64) {
                        certs.push(rustls::pki_types::CertificateDer::from(der));
                    }
                    in_cert = false;
                }
            } else if in_cert {
                b64.push_str(line);
            }
        }
    }
    certs
}

/// Build the client trust store from Mozilla's compiled-in root bundle
/// supplemented by the host system's root certificates (/etc/ssl/certs/ca-certificates.crt).
fn root_store() -> RootCertStore {
    let mut store = RootCertStore::empty();
    store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    for cert in load_pem_certs("/etc/ssl/certs/ca-certificates.crt") {
        let _ = store.add(cert);
    }
    store
}

impl NetEngine {
    fn new() -> Result<Self, NetError> {
        let proactor = Proactor::new().map_err(|e| {
            eprintln!("[z-net] Proactor::new failed: {:?}", e);
            NetError::IoError
        })?;
        
        // Install default crypto provider for rustls 0.23
        #[cfg(feature = "ring")]
        let _ = rustls::crypto::ring::default_provider().install_default();
        
        // Setup default TLS config with ALPN for HTTP/1.1 streaming and full session resumption
        // Note: HTTP/1.1 is pinned until full HTTP/2 multiplexed streaming is wired into execute_streaming
        let mut config = ClientConfig::builder()
            .with_root_certificates(root_store())
            .with_no_client_auth();
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        config.resumption = rustls::client::Resumption::in_memory_sessions(1024);
        config.enable_early_data = true;
            
        let tls_cfg = Arc::new(config);
        let http_engine = protocols::http::client::HttpClientEngine::new(tls_cfg.clone());
            
        Ok(Self {
            proactor,
            connections: HashMap::new(),
            next_tls_id: 1,
            tls_states: HashMap::new(),
            next_conn_id: 1,
            tls_config: tls_cfg,
            http_engine,
            body_rings: HashMap::new(),
            conn_body_rings: HashMap::new(),
            quic_endpoints: HashMap::new(),
            quic_conns: HashMap::new(),
            next_quic_id: 1,
            last_error: std::sync::Mutex::new(None),
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
                            let _ = self.proactor.attach(conn.stream.as_raw_fd());
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
        
        match self.proactor.poll(timeout) {
            Ok(_) => 0,
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

/// Connect to a host with explicit TLS option (allowing TLS on custom ports like 8443)
#[no_mangle]
pub extern "C" fn net_connect_tls(
    engine_handle: NetEngineHandle,
    host: *const c_char,
    port: u16,
    use_tls: bool,
) -> ConnectionHandle {
    if engine_handle.is_null() || host.is_null() {
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
    
    let stream = match stream {
        Some(s) => s,
        None => return null_mut(),
    };
    
    // Enable TCP_NODELAY to avoid 40ms stall
    let _ = stream.set_nodelay(true);
    
    let conn_id = engine.next_conn_id;
    engine.next_conn_id += 1;
    
    if engine.proactor.attach(stream.as_raw_fd()).is_err() {
        return null_mut();
    }
    
    let mut conn = Connection::new(stream, host_str, port);
    
    // Initialize TLS if explicitly requested
    if use_tls {
        if let Ok(server_name) = rustls::pki_types::ServerName::try_from(conn.host.as_str()) {
            if let Ok(tls) = ClientConnection::new(engine.tls_config.clone(), server_name.to_owned()) {
                conn.tlsconn = Some(tls);
            }
        }
    }
    
    engine.connections.insert(conn_id, conn);
    conn_id as ConnectionHandle
}

/// Connect to a host (defaults to TLS if port == 443)
#[no_mangle]
pub extern "C" fn net_connect(
    engine_handle: NetEngineHandle,
    host: *const c_char,
    port: u16,
) -> ConnectionHandle {
    net_connect_tls(engine_handle, host, port, port == 443)
}

/// Query the ALPN protocol negotiated on a connection (e.g. "h2", "http/1.1", or empty if none)
#[no_mangle]
pub extern "C" fn net_conn_alpn_protocol(
    engine_handle: NetEngineHandle,
    conn_handle: ConnectionHandle,
    out_buf: *mut u8,
    out_buf_len: usize,
    out_actual_len: *mut usize,
) -> i32 {
    if engine_handle.is_null() || conn_handle.is_null() || out_buf.is_null() || out_actual_len.is_null() {
        return NS_ERROR_FAILURE;
    }
    let engine = unsafe { &*(engine_handle as *const NetEngine) };
    let conn_id = conn_handle as usize;
    if let Some(conn) = engine.connections.get(&conn_id) {
        if let Some(ref tls) = conn.tlsconn {
            if let Some(alpn) = tls.alpn_protocol() {
                let to_copy = alpn.len().min(out_buf_len);
                unsafe {
                    std::ptr::copy_nonoverlapping(alpn.as_ptr(), out_buf, to_copy);
                    *out_actual_len = to_copy;
                }
                return NS_OK;
            }
        }
    }
    unsafe { *out_actual_len = 0; }
    NS_OK
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

// ============================================================
// HTTP Client C ABI Interface (High-level Engine API)
// ============================================================

#[repr(C)]
pub struct ZNetHttpRawResponse {
    pub status: u16,
    pub reason: *mut c_char,
    pub header_names: *mut *mut c_char,
    pub header_values: *mut *mut c_char,
    pub header_count: usize,
    pub body_data: *mut u8,
    pub body_len: usize,
}

#[no_mangle]
pub extern "C" fn net_http_execute(
    engine_handle: NetEngineHandle,
    session_id: u64,
    method: *const c_char,
    url: *const c_char,
    header_names: *const *const c_char,
    header_values: *const *const c_char,
    header_count: usize,
    body: *const u8,
    body_len: usize,
    transparent_decompression: bool,
    out_response: *mut *mut ZNetHttpRawResponse,
) -> i32 {
    if engine_handle.is_null() || method.is_null() || url.is_null() || out_response.is_null() {
        return NS_ERROR_FAILURE;
    }
    let engine = unsafe { &mut *(engine_handle as *mut NetEngine) };

    let method_str = unsafe { std::ffi::CStr::from_ptr(method).to_string_lossy().into_owned() };
    let url_str = unsafe { std::ffi::CStr::from_ptr(url).to_string_lossy().into_owned() };

    let mut opts = protocols::http::client::HttpRequestOptions::new(&method_str, &url_str)
        .with_session(session_id);
    opts.transparent_decompression = transparent_decompression;

    if !body.is_null() && body_len > 0 {
        let body_slice = unsafe { std::slice::from_raw_parts(body, body_len) };
        opts.body = Some(body_slice.to_vec());
    }

    if !header_names.is_null() && !header_values.is_null() && header_count > 0 {
        for i in 0..header_count {
            unsafe {
                let name_ptr = *header_names.add(i);
                let val_ptr = *header_values.add(i);
                if !name_ptr.is_null() && !val_ptr.is_null() {
                    let k = std::ffi::CStr::from_ptr(name_ptr).to_string_lossy().into_owned();
                    let v = std::ffi::CStr::from_ptr(val_ptr).to_string_lossy().into_owned();
                    opts.headers.push((k, v));
                }
            }
        }
    }

    match engine.http_engine.execute(&opts) {
        Ok(resp) => {
            let reason_c = std::ffi::CString::new(resp.reason).unwrap_or_default().into_raw();
            let count = resp.headers.len();
            let mut name_ptrs: Vec<*mut c_char> = Vec::with_capacity(count);
            let mut val_ptrs: Vec<*mut c_char> = Vec::with_capacity(count);

            for (k, v) in resp.headers {
                name_ptrs.push(std::ffi::CString::new(k).unwrap_or_default().into_raw());
                val_ptrs.push(std::ffi::CString::new(v).unwrap_or_default().into_raw());
            }

            let mut body_vec = resp.body;
            let body_len = body_vec.len();
            let body_ptr = if body_len > 0 {
                let p = body_vec.as_mut_ptr();
                std::mem::forget(body_vec);
                p
            } else {
                std::ptr::null_mut()
            };

            let names_slice = name_ptrs.leak();
            let vals_slice = val_ptrs.leak();

            let raw = Box::into_raw(Box::new(ZNetHttpRawResponse {
                status: resp.status,
                reason: reason_c,
                header_names: names_slice.as_mut_ptr(),
                header_values: vals_slice.as_mut_ptr(),
                header_count: count,
                body_data: body_ptr,
                body_len,
            }));

            unsafe {
                *out_response = raw;
            }
            NS_OK
        }
        Err(e) => {
            let err_msg = format!("{}", e);
            eprintln!("[z-net] net_http_execute failed: {}", err_msg);
            if let Ok(mut lock) = engine.last_error.lock() {
                *lock = Some(err_msg);
            }
            NS_ERROR_FAILURE
        }
    }
}

#[no_mangle]
pub extern "C" fn net_http_response_free(response: *mut ZNetHttpRawResponse) {
    if response.is_null() {
        return;
    }
    unsafe {
        let resp = Box::from_raw(response);
        if !resp.reason.is_null() {
            let _ = std::ffi::CString::from_raw(resp.reason);
        }
        if !resp.header_names.is_null() && !resp.header_values.is_null() {
            let names = Vec::from_raw_parts(resp.header_names, resp.header_count, resp.header_count);
            let values = Vec::from_raw_parts(resp.header_values, resp.header_count, resp.header_count);
            for p in names {
                if !p.is_null() {
                    let _ = std::ffi::CString::from_raw(p);
                }
            }
            for p in values {
                if !p.is_null() {
                    let _ = std::ffi::CString::from_raw(p);
                }
            }
        }
        if !resp.body_data.is_null() && resp.body_len > 0 {
            let _ = Vec::from_raw_parts(resp.body_data, resp.body_len, resp.body_len);
        }
    }
}

#[no_mangle]
pub extern "C" fn net_pool_clear_session(engine_handle: NetEngineHandle, session_id: u64) -> i32 {
    if engine_handle.is_null() {
        return NS_ERROR_FAILURE;
    }
    let engine = unsafe { &mut *(engine_handle as *mut NetEngine) };
    engine.http_engine.clear_session(session_id);
    NS_OK
}

#[repr(C)]
pub struct ZNetHttpStreamCallbacks {
    pub user_data: *mut c_void,
    pub on_headers: Option<extern "C" fn(status: u16, reason: *const c_char, header_count: usize, header_names: *const *const c_char, header_values: *const *const c_char, user_data: *mut c_void)>,
    pub on_data: Option<extern "C" fn(chunk: *const u8, chunk_len: usize, user_data: *mut c_void)>,
    pub on_complete: Option<extern "C" fn(keep_alive: bool, user_data: *mut c_void)>,
    pub is_cancelled: Option<extern "C" fn(user_data: *mut c_void) -> bool>,
}

#[no_mangle]
pub extern "C" fn net_get_last_error(
    engine_handle: NetEngineHandle,
    out_buf: *mut c_char,
    max_len: usize,
) -> i32 {
    if engine_handle.is_null() || out_buf.is_null() || max_len == 0 {
        return NS_ERROR_FAILURE;
    }
    let engine = unsafe { &*(engine_handle as *const NetEngine) };
    if let Ok(lock) = engine.last_error.lock() {
        if let Some(ref err) = *lock {
            let bytes = err.as_bytes();
            let copy_len = std::cmp::min(bytes.len(), max_len - 1);
            unsafe {
                std::ptr::copy_nonoverlapping(bytes.as_ptr() as *const c_char, out_buf, copy_len);
                *out_buf.add(copy_len) = 0;
            }
            return NS_OK;
        }
    }
    unsafe {
        *out_buf = 0;
    }
    NS_OK
}

#[no_mangle]
pub extern "C" fn net_http_execute_streaming(
    engine_handle: NetEngineHandle,
    session_id: u64,
    method: *const c_char,
    url: *const c_char,
    header_names: *const *const c_char,
    header_values: *const *const c_char,
    header_count: usize,
    body: *const u8,
    body_len: usize,
    body_ring_id: u64,
    callbacks: *const ZNetHttpStreamCallbacks,
) -> i32 {
    if engine_handle.is_null() || method.is_null() || url.is_null() || callbacks.is_null() {
        return NS_ERROR_FAILURE;
    }
    let engine = unsafe { &mut *(engine_handle as *mut NetEngine) };
    let cb = unsafe { &*callbacks };

    let method_str = unsafe { std::ffi::CStr::from_ptr(method).to_string_lossy().into_owned() };
    let url_str = unsafe { std::ffi::CStr::from_ptr(url).to_string_lossy().into_owned() };

    let mut opts = protocols::http::client::HttpRequestOptions::new(&method_str, &url_str)
        .with_session(session_id);

    if !body.is_null() && body_len > 0 {
        let body_slice = unsafe { std::slice::from_raw_parts(body, body_len) };
        opts.body = Some(body_slice.to_vec());
    }

    if !header_names.is_null() && !header_values.is_null() && header_count > 0 {
        for i in 0..header_count {
            unsafe {
                let name_ptr = *header_names.add(i);
                let val_ptr = *header_values.add(i);
                if !name_ptr.is_null() && !val_ptr.is_null() {
                    let k = std::ffi::CStr::from_ptr(name_ptr).to_string_lossy().into_owned();
                    let v = std::ffi::CStr::from_ptr(val_ptr).to_string_lossy().into_owned();
                    opts.headers.push((k, v));
                }
            }
        }
    }

    let ring_opt = if body_ring_id > 0 {
        engine.body_rings.get(&body_ring_id).map(|&ptr| unsafe { &*ptr })
    } else {
        None
    };

    let user_data = cb.user_data;
    let on_headers_fn = cb.on_headers;
    let on_data_fn = cb.on_data;
    let on_complete_fn = cb.on_complete;
    let is_cancelled_fn = cb.is_cancelled;

    let res = engine.http_engine.execute_streaming_with_cancel(
        &opts,
        ring_opt,
        |status, reason, headers| {
            if let Some(f) = on_headers_fn {
                let reason_c = std::ffi::CString::new(reason).unwrap_or_default();
                let count = headers.len();
                let mut name_cstrings = Vec::with_capacity(count);
                let mut val_cstrings = Vec::with_capacity(count);
                let mut name_ptrs = Vec::with_capacity(count);
                let mut val_ptrs = Vec::with_capacity(count);

                for (k, v) in headers {
                    let c_k = std::ffi::CString::new(k.as_str()).unwrap_or_default();
                    let c_v = std::ffi::CString::new(v.as_str()).unwrap_or_default();
                    name_ptrs.push(c_k.as_ptr());
                    val_ptrs.push(c_v.as_ptr());
                    name_cstrings.push(c_k);
                    val_cstrings.push(c_v);
                }

                f(
                    status,
                    reason_c.as_ptr(),
                    count,
                    name_ptrs.as_ptr(),
                    val_ptrs.as_ptr(),
                    user_data,
                );
            }
        },
        |chunk| {
            if let Some(f) = on_data_fn {
                f(chunk.as_ptr(), chunk.len(), user_data);
            }
        },
        |keep_alive| {
            if let Some(f) = on_complete_fn {
                f(keep_alive, user_data);
            }
        },
        || {
            if let Some(f) = is_cancelled_fn {
                f(user_data)
            } else {
                false
            }
        },
    );

    match res {
        Ok(_) => NS_OK,
        Err(e) => {
            let err_msg = format!("{}", e);
            eprintln!("[z-net] net_http_execute_streaming failed: {}", err_msg);
            if let Ok(mut lock) = engine.last_error.lock() {
                *lock = Some(err_msg);
            }
            NS_ERROR_FAILURE
        }
    }
}

#[no_mangle]
pub extern "C" fn net_cookie_jar_store(
    engine_handle: NetEngineHandle,
    session_id: u64,
    url: *const c_char,
    set_cookie_str: *const c_char,
) -> i32 {
    if engine_handle.is_null() || url.is_null() || set_cookie_str.is_null() {
        return NS_ERROR_FAILURE;
    }
    let engine = unsafe { &mut *(engine_handle as *mut NetEngine) };
    let url_str = unsafe { std::ffi::CStr::from_ptr(url).to_string_lossy() };
    let cookie_str = unsafe { std::ffi::CStr::from_ptr(set_cookie_str).to_string_lossy() };

    let parsed_url = match url::Url::parse(&url_str) {
        Ok(u) => u,
        Err(_) => return NS_ERROR_FAILURE,
    };

    if engine.http_engine.cookie_jar.process_set_cookie(session_id, &parsed_url, &cookie_str) {
        NS_OK
    } else {
        NS_ERROR_FAILURE
    }
}

#[no_mangle]
pub extern "C" fn net_cookie_jar_get_header(
    engine_handle: NetEngineHandle,
    session_id: u64,
    url: *const c_char,
    out_buf: *mut c_char,
    max_len: usize,
) -> i32 {
    if engine_handle.is_null() || url.is_null() || out_buf.is_null() || max_len == 0 {
        return NS_ERROR_FAILURE;
    }
    let engine = unsafe { &mut *(engine_handle as *mut NetEngine) };
    let url_str = unsafe { std::ffi::CStr::from_ptr(url).to_string_lossy() };

    let parsed_url = match url::Url::parse(&url_str) {
        Ok(u) => u,
        Err(_) => return NS_ERROR_FAILURE,
    };

    if let Some(header_val) = engine.http_engine.cookie_jar.get_cookie_header(session_id, &parsed_url) {
        let bytes = header_val.as_bytes();
        let copy_len = bytes.len().min(max_len - 1);
        unsafe {
            std::ptr::copy_nonoverlapping(bytes.as_ptr(), out_buf as *mut u8, copy_len);
            *out_buf.add(copy_len) = 0;
        }
        NS_OK
    } else {
        unsafe {
            *out_buf = 0;
        }
        NS_OK
    }
}

#[no_mangle]
pub extern "C" fn net_cookie_jar_clear(
    engine_handle: NetEngineHandle,
    session_id: u64,
) {
    if !engine_handle.is_null() {
        let engine = unsafe { &mut *(engine_handle as *mut NetEngine) };
        engine.http_engine.cookie_jar.clear_session(session_id);
    }
}

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

    let udp_stream = socket;

    let conn_id = engine.next_quic_id;
    engine.next_quic_id += 1;

    if engine.proactor.attach(udp_stream.as_raw_fd()).is_err() {
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

    let mut state = match TlsState::new(host_str, port, engine.tls_config.clone()) {
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
    if let Some(_endpoint_entry) = engine.quic_endpoints.remove(&conn_id) {
    }
    NS_OK
}

/// Migrate a live QUIC connection to a new local IP address and port (RFC 9000 Section 9).
/// Rebinds the local socket without resetting the connection ID, TLS handshake, or active streams.
#[no_mangle]
pub extern "C" fn net_quic_migrate(
    engine_handle: NetEngineHandle,
    conn_handle: ConnHandle,
    new_local_ip: *const c_char,
    new_local_port: u16,
) -> i32 {
    if engine_handle.is_null() || conn_handle.is_null() || new_local_ip.is_null() {
        return NS_ERROR_FAILURE;
    }
    let engine = unsafe { &mut *(engine_handle as *mut NetEngine) };
    let conn_id = conn_handle as usize;

    let ip_str = unsafe { std::ffi::CStr::from_ptr(new_local_ip) }.to_string_lossy();
    let ip: std::net::IpAddr = match ip_str.parse() {
        Ok(ip) => ip,
        Err(_) => return NS_ERROR_FAILURE,
    };
    let new_addr = std::net::SocketAddr::new(ip, new_local_port);

    let endpoint_entry = match engine.quic_endpoints.get_mut(&conn_id) {
        Some(e) => e,
        None => return NS_ERROR_FAILURE,
    };

    let new_socket = match UdpSocket::bind(new_addr) {
        Ok(s) => s,
        Err(_) => return NS_ERROR_FAILURE,
    };

    if new_socket.set_nonblocking(true).is_err() {
        return NS_ERROR_FAILURE;
    }

    if engine.proactor.attach(new_socket.as_raw_fd()).is_err() {
        return NS_ERROR_FAILURE;
    }

    let actual_local = match new_socket.local_addr() {
        Ok(a) => a,
        Err(_) => new_addr,
    };

    endpoint_entry.socket = new_socket;
    endpoint_entry.local_addr = actual_local;

    NS_OK
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn root_store_contains_trust_anchors() {
        let store = root_store();
        assert!(!store.is_empty(), "trust store must contain roots");
        assert!(store.len() >= webpki_roots::TLS_SERVER_ROOTS.len());
    }

    #[test]
    fn engine_configures_alpn_for_http11() {
        let engine = NetEngine::new().expect("engine must initialize");
        assert_eq!(
            engine.tls_config.alpn_protocols,
            vec![b"http/1.1".to_vec()],
            "ALPN must negotiate http/1.1 for streaming engine"
        );
    }

    #[test]
    fn test_load_pem_certs_parses_valid_cert() {
        let pem_sample = "\
-----BEGIN CERTIFICATE-----
MIIBdDCCARugAwIBAgIQBwX1Iqjr8MdCPXLI8fgISjAKBggqhkjOPQQDAjAZMRcw
FQYDVQQDEw5hbnRpZ3Jhdml0eSBDQTAeFw0yNjExMjEwNTUzMDlaFw0zNjExMjEw
NTUzMDlaMBkxFzAVBgNVBAMTDmFudGlncmF2aXR5IENBMFkwEwYHKoZIzj0CAQYI
KoZIzj0DAQcDQgAEl8B2nNIkTR4D1wul5vwunM97rfZXNAO8iUmvTgrYcsAI277f
IyPh6m6bXqasXnKFL62EptHqz4weaRM8i+QmUaNFMEMwDgYDVR0PAQH/BAQDAgIE
MBIGA1UdEwEB/wQIMAYBAf8CAQAwHQYDVR0OBBYEFB7Bz8ieNJXYG22erK9B1IYY
Np1AMAoGCCqGSM49BAMCA0cAMEQCIBN6PxS/+aMaOIoywLaD3/WKP0QVoZkcwGka
J0wGoFpdAiB7n+1noxTxqbLQQ/aSI9vGSov/GskEh1Zpn4xh3kNtOg==
-----END CERTIFICATE-----
";
        let temp_path = std::env::temp_dir().join("test_cert.pem");
        std::fs::write(&temp_path, pem_sample).expect("write temp pem");
        let certs = load_pem_certs(temp_path.to_str().unwrap());
        let _ = std::fs::remove_file(temp_path);
        assert_eq!(certs.len(), 1);
        assert!(!certs[0].is_empty());
    }

    #[test]
    fn test_c_abi_net_http_execute_roundtrip() {
        use std::io::{Read, Write};
        use std::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock server");
        let port = listener.local_addr().unwrap().port();

        let server_thread = std::thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut buf = [0u8; 1024];
                let _ = stream.read(&mut buf);
                let response = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 18\r\n\r\n{\"status\":\"ready\"}";
                let _ = stream.write_all(response);
            }
        });

        let engine = net_engine_create();
        assert!(!engine.is_null());

        let method = std::ffi::CString::new("GET").unwrap();
        let url = std::ffi::CString::new(format!("http://127.0.0.1:{}/status", port)).unwrap();

        let mut raw_resp: *mut ZNetHttpRawResponse = std::ptr::null_mut();
        let res = net_http_execute(
            engine,
            0,
            method.as_ptr(),
            url.as_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            0,
            std::ptr::null(),
            0,
            true,
            &mut raw_resp,
        );

        server_thread.join().unwrap();
        assert_eq!(res, NS_OK);
        assert!(!raw_resp.is_null());

        unsafe {
            assert_eq!((*raw_resp).status, 200);
            assert_eq!((*raw_resp).body_len, 18);
            let body = std::slice::from_raw_parts((*raw_resp).body_data, (*raw_resp).body_len);
            assert_eq!(body, b"{\"status\":\"ready\"}");
        }

        net_http_response_free(raw_resp);
        net_engine_destroy(engine);
    }

    #[test]
    fn test_c_abi_net_http_execute_streaming_and_cookie_jar() {
        use std::io::{Read, Write};
        use std::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock server");
        let port = listener.local_addr().unwrap().port();

        let server_thread = std::thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut buf = [0u8; 1024];
                let _ = stream.read(&mut buf);
                let response = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 10\r\n\r\n0123456789";
                let _ = stream.write_all(response);
            }
        });

        let engine = net_engine_create();
        assert!(!engine.is_null());

        struct Context {
            status: u16,
            body: Vec<u8>,
            done: bool,
        }

        let mut ctx = Context {
            status: 0,
            body: Vec::new(),
            done: false,
        };

        extern "C" fn on_headers(
            status: u16,
            _reason: *const c_char,
            _count: usize,
            _names: *const *const c_char,
            _vals: *const *const c_char,
            user_data: *mut c_void,
        ) {
            let ctx = unsafe { &mut *(user_data as *mut Context) };
            ctx.status = status;
        }

        extern "C" fn on_data(chunk: *const u8, len: usize, user_data: *mut c_void) {
            let ctx = unsafe { &mut *(user_data as *mut Context) };
            let slice = unsafe { std::slice::from_raw_parts(chunk, len) };
            ctx.body.extend_from_slice(slice);
        }

        extern "C" fn on_complete(_keep_alive: bool, user_data: *mut c_void) {
            let ctx = unsafe { &mut *(user_data as *mut Context) };
            ctx.done = true;
        }

        let callbacks = ZNetHttpStreamCallbacks {
            user_data: &mut ctx as *mut _ as *mut c_void,
            on_headers: Some(on_headers),
            on_data: Some(on_data),
            on_complete: Some(on_complete),
            is_cancelled: None,
        };

        let method = std::ffi::CString::new("GET").unwrap();
        let url = std::ffi::CString::new(format!("http://127.0.0.1:{}/stream", port)).unwrap();

        let res = net_http_execute_streaming(
            engine,
            0,
            method.as_ptr(),
            url.as_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            0,
            std::ptr::null(),
            0,
            0,
            &callbacks,
        );

        server_thread.join().unwrap();
        assert_eq!(res, NS_OK);
        assert_eq!(ctx.status, 200);
        assert_eq!(ctx.body, b"0123456789");
        assert!(ctx.done);

        // Test cookie jar C ABI
        let cookie_val = std::ffi::CString::new("pref=dark; Path=/").unwrap();
        let store_res = net_cookie_jar_store(engine, 1, url.as_ptr(), cookie_val.as_ptr());
        assert_eq!(store_res, NS_OK);

        let mut out_header = [0 as c_char; 256];
        let get_res = net_cookie_jar_get_header(engine, 1, url.as_ptr(), out_header.as_mut_ptr(), out_header.len());
        assert_eq!(get_res, NS_OK);
        let header_str = unsafe { std::ffi::CStr::from_ptr(out_header.as_ptr()).to_string_lossy() };
        assert!(header_str.contains("pref=dark"));

        net_cookie_jar_clear(engine, 1);
        let _ = net_cookie_jar_get_header(engine, 1, url.as_ptr(), out_header.as_mut_ptr(), out_header.len());
        assert_eq!(out_header[0], 0);

        net_engine_destroy(engine);
    }

    #[test]
    fn test_c_abi_quic_connection_migration() {
        let engine = net_engine_create();
        assert!(!engine.is_null());

        let mock_server = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind mock udp server");
        let server_port = mock_server.local_addr().unwrap().port();

        let host = std::ffi::CString::new("127.0.0.1").unwrap();
        let conn_handle = net_http3_connect(engine, host.as_ptr(), server_port);
        assert!(!conn_handle.is_null());

        // Migrate connection to a new local address
        let new_ip = std::ffi::CString::new("127.0.0.1").unwrap();
        let migrate_res = net_quic_migrate(engine, conn_handle, new_ip.as_ptr(), 0);
        assert_eq!(migrate_res, NS_OK);

        // Drive the connection state machine post-migration
        let drive_res = net_http3_drive(engine, conn_handle);
        assert!(drive_res >= 0);

        // Close connection cleanly
        let close_res = net_http3_close(engine, conn_handle);
        assert_eq!(close_res, NS_OK);

        net_engine_destroy(engine);
    }
}
