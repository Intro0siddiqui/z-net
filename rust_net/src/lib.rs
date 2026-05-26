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

/// Network engine state
pub struct NetEngine {
    poll: Poll,
    events: Events,
    connections: HashMap<usize, Connection>,
    next_conn_id: usize,
    tls_config: Arc<ClientConfig>,
    body_rings: HashMap<u64, *mut BodyRingDescriptor>,
    conn_body_rings: HashMap<usize, u64>,
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
            next_conn_id: 1,
            tls_config: Arc::new(config),
            body_rings: HashMap::new(),
            conn_body_rings: HashMap::new(),
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
        return NetError::InvalidHandle as i32;
    }
    
    let engine = unsafe { &mut *(engine_handle as *mut NetEngine) };
    let conn_id = conn_handle as usize;
    
    if engine.connections.remove(&conn_id).is_some() {
        NetError::None as i32
    } else {
        NetError::InvalidHandle as i32
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
        return NetError::InvalidHandle as i32;
    }
    
    let engine = unsafe { &mut *(engine_handle as *mut NetEngine) };
    let conn_id = conn_handle as usize;

    // 1. Check if we have a bound BodyRing for zero-copy Pull
    if let Some(&ring_id) = engine.conn_body_rings.get(&conn_id) {
        if let Some(&ring_ptr) = engine.body_rings.get(&ring_id) {
            let ring = unsafe { &*ring_ptr };
            let connection = match engine.connections.get_mut(&conn_id) {
                Some(c) => c,
                None => return NetError::NotConnected as i32,
            };

            let head = ring.head.load(Ordering::Acquire);
            let tail = ring.tail.load(Ordering::Acquire);
            if head.wrapping_sub(tail) >= ring.capacity as u64 {
                return NetError::WouldBlock as i32;
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
                Ok(0) => return NetError::NotConnected as i32,
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
                    return NetError::None as i32;
                }
                Err(ref e) if e.kind() == ErrorKind::WouldBlock => return NetError::WouldBlock as i32,
                Err(_) => return NetError::IoError as i32,
            }
        }
    }
    
    let connection = match engine.connections.get_mut(&conn_id) {
        Some(c) => c,
        None => return NetError::NotConnected as i32,
    };
    
    let dst = unsafe { from_raw_parts_mut(buffer, buffer_len) };
    
    if let Some(ref mut tlsconn) = connection.tlsconn {
        // 1. Try to read from socket and feed to TLS
        match connection.stream.read(&mut connection.read_buf) {
            Ok(0) => return NetError::NotConnected as i32,
            Ok(n) => {
                let mut cursor = std::io::Cursor::new(&connection.read_buf[..n]);
                if tlsconn.read_tls(&mut cursor).is_err() {
                    return NetError::TlsError as i32;
                }
                if tlsconn.process_new_packets().is_err() {
                    return NetError::TlsError as i32;
                }
            }
            Err(ref e) if e.kind() == ErrorKind::WouldBlock => {
                // No new data, check if we have pending plaintext
            }
            Err(_) => return NetError::IoError as i32,
        }
        
        // 2. Read plaintext from TLS
        match tlsconn.reader().read(dst) {
            Ok(n) => {
                unsafe {
                    if !bytes_read.is_null() {
                        *bytes_read = n;
                    }
                }
                return NetError::None as i32;
            }
            Err(ref e) if e.kind() == ErrorKind::WouldBlock => {
                return NetError::WouldBlock as i32;
            }
            Err(_) => return NetError::TlsError as i32,
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
            NetError::None as i32
        }
        Err(ref e) if e.kind() == ErrorKind::WouldBlock => NetError::WouldBlock as i32,
        Err(_) => NetError::IoError as i32,
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
        return NetError::InvalidHandle as i32;
    }
    
    let engine = unsafe { &mut *(engine_handle as *mut NetEngine) };
    let conn_id = conn_handle as usize;
    
    let connection = match engine.connections.get_mut(&conn_id) {
        Some(c) => c,
        None => return NetError::NotConnected as i32,
    };
    
    let src = unsafe { from_raw_parts(data, data_len) };
    
    if let Some(ref mut tlsconn) = connection.tlsconn {
        // 1. Write plaintext to TLS
        let n = match tlsconn.writer().write(src) {
            Ok(n) => n,
            Err(_) => return NetError::TlsError as i32,
        };
        
        // 2. Flush ciphertext to socket
        while tlsconn.wants_write() {
            match tlsconn.write_tls(&mut connection.stream) {
                Ok(_) => {},
                Err(ref e) if e.kind() == ErrorKind::WouldBlock => break,
                Err(_) => return NetError::IoError as i32,
            }
        }
        
        unsafe {
            if !bytes_written.is_null() {
                *bytes_written = n;
            }
        }
        return NetError::None as i32;
    }
    
    // Non-TLS path
    match connection.stream.write(src) {
        Ok(n) => {
            unsafe {
                if !bytes_written.is_null() {
                    *bytes_written = n;
                }
            }
            NetError::None as i32
        }
        Err(ref e) if e.kind() == ErrorKind::WouldBlock => NetError::WouldBlock as i32,
        Err(_) => NetError::IoError as i32,
    }
}

/// Poll for readiness
#[no_mangle]
pub extern "C" fn net_poll(
    engine_handle: NetEngineHandle,
    timeout_ms: i32,
) -> i32 {
    if engine_handle.is_null() {
        return NetError::InvalidHandle as i32;
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
pub extern "C" fn net_fetch_create(url: *const c_char, _options: *const FetchOptions) -> FetchHandle {
    if url.is_null() {
        return null_mut();
    }
    let url_str = unsafe { std::ffi::CStr::from_ptr(url).to_string_lossy() };
    if let Ok(parsed_url) = url::Url::parse(&url_str) {
        let mut engine = Box::new(protocols::fetch::FetchEngine::new());
        engine.fetch(parsed_url);
        return Box::into_raw(engine) as FetchHandle;
    }
    null_mut()
}

#[no_mangle]
pub extern "C" fn net_http3_connect(_engine: NetEngineHandle, _host: *const c_char, _port: u16) -> ConnHandle {
    // Scaffolding implementation
    null_mut()
}

#[no_mangle]
pub extern "C" fn net_body_ring_register(
    engine_handle: NetEngineHandle,
    id: u64,
    ptr: *mut BodyRingDescriptor,
) -> i32 {
    if engine_handle.is_null() {
        return NetError::InvalidHandle as i32;
    }
    let engine = unsafe { &mut *(engine_handle as *mut NetEngine) };
    engine.body_rings.insert(id, ptr);
    0
}

#[no_mangle]
pub extern "C" fn net_body_ring_unregister(engine_handle: NetEngineHandle, id: u64) -> i32 {
    if engine_handle.is_null() {
        return NetError::InvalidHandle as i32;
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
        return NetError::InvalidHandle as i32;
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
