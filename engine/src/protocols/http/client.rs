use std::cell::Cell;
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

static ACTIVE_STREAMS: AtomicUsize = AtomicUsize::new(0);

fn truncate_path(path: &str) -> String {
    path.chars().take(48).collect()
}

struct PerfTelemetry {
    method: String,
    host: String,
    path_prefix: String,
    proto: &'static str,
    reused: bool,
    streams: usize,
    dns_ms: f64,
    tcp_tls_ms: f64,
    ttfb_ms: f64,
    body_ms: f64,
    status: u16,
    total_start: Instant,
}

impl Drop for PerfTelemetry {
    fn drop(&mut self) {
        ACTIVE_STREAMS.fetch_sub(1, Ordering::AcqRel);
        let total_ms = self.total_start.elapsed().as_secs_f64() * 1000.0;
        eprintln!(
            "[ZNET-PERF] {} {}{} | proto={} reused={} streams={} | dns={:.1}ms tls={:.1}ms ttfb={:.1}ms body={:.1}ms total={:.1}ms status={}",
            self.method,
            self.host,
            self.path_prefix,
            self.proto,
            self.reused,
            self.streams,
            self.dns_ms,
            self.tcp_tls_ms,
            self.ttfb_ms,
            self.body_ms,
            total_ms,
            self.status,
        );
    }
}

use compio_buf::BufResult;
use compio_driver::op::{Connect, Interest, PollOnce};
use compio_driver::{AsRawFd, Key, Proactor, PushEntry, SharedFd};
use socket2::{Domain, Protocol, SockAddr, Socket as Socket2, Type};
use url::Url;

use super::alt_svc::AltSvcRegistry;
use super::cookie_jar::CookieJar;
use super::h1::{Http1FeedResult, Http1RequestBuilder, Http1ResponseParser};
use super::pool::{ConnectionPool, PoolKey};
use crate::protocols::compression::{decompress_payload, StreamDecompressor};
use crate::protocols::dns::{DnsResolver, DnsResolverConfig};
use super::h2::{is_hop_by_hop_header, H2Session, SharedH2Session};
use crate::protocols::http3::Http3Client;
use crate::protocols::tls::{
    step_boring_handshake, BoringIo, BoringMidHandshake, BoringStream, BoringTlsConfig,
    NonBlockingHandshakeStep, TlsFingerprintProfile,
};
use crate::protocols::proxy::{
    establish_http_connect_tunnel, establish_socks5_tunnel, ProxyConfig, ProxyRule, ProxyScheme,
};
use crate::BodyRingDescriptor;

/// A parsed HTTP response representation.
#[derive(Debug, Clone)]
pub struct HttpResponse {
    pub status: u16,
    pub reason: String,
    pub headers: HashMap<String, String>,
    pub body: Vec<u8>,
}

/// Request parameters for dispatching an HTTP request.
#[derive(Debug, Clone)]
pub struct HttpRequestOptions {
    pub session_id: u64,
    pub method: String,
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: Option<Vec<u8>>,
    pub transparent_decompression: bool,
    pub timeout: Duration,
}

impl HttpRequestOptions {
    pub fn new(method: &str, url: &str) -> Self {
        Self {
            session_id: 0,
            method: method.to_ascii_uppercase(),
            url: url.to_string(),
            headers: Vec::new(),
            body: None,
            transparent_decompression: true,
            timeout: Duration::from_secs(30),
        }
    }

    pub fn with_session(mut self, session_id: u64) -> Self {
        self.session_id = session_id;
        self
    }

    pub fn header(mut self, name: &str, value: &str) -> Self {
        self.headers.push((name.to_string(), value.to_string()));
        self
    }

    pub fn body(mut self, body: Vec<u8>) -> Self {
        self.body = Some(body);
        self
    }
}

enum ActiveStream {
    Plain(TcpStream),
    BoringTls(Box<BoringStream>),
}

impl Read for ActiveStream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Self::Plain(s) => s.read(buf),
            Self::BoringTls(s) => s.read(buf),
        }
    }
}

impl Write for ActiveStream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self {
            Self::Plain(s) => s.write(buf),
            Self::BoringTls(s) => s.write(buf),
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            Self::Plain(s) => s.flush(),
            Self::BoringTls(s) => s.flush(),
        }
    }
}

const HE3_CAD: Duration = Duration::from_millis(75);

enum He3Winner {
    H3 {
        quic_state: crate::protocols::http3::QuicHandshakeState,
        udp_socket: std::net::UdpSocket,
        h3_ms: f64,
    },
    H2OrH1 {
        stream: ActiveStream,
        alpn: Option<Vec<u8>>,
        h3_ms: f64,
        h2_ms: f64,
        demoted: bool,
    },
}

enum TcpTlsState {
    NotStarted,
    Connecting(Key<Connect<SharedFd<Socket2>>>),
    Handshaking {
        mid: BoringMidHandshake,
        poll_key: Option<Key<PollOnce<SharedFd<Socket2>>>>,
    },
    Failed(String),
}

/// Non-exclusive HTTP/2 connection pool sharing live `Arc<SharedH2Session>`
/// instances so concurrent requests multiplex streams on the same TCP/TLS connection.
struct SharedH2Pool {
    sessions: HashMap<PoolKey, (Arc<SharedH2Session<ActiveStream>>, Instant)>,
    idle_timeout: Duration,
}

impl SharedH2Pool {
    fn new(idle_timeout: Duration) -> Self {
        Self {
            sessions: HashMap::new(),
            idle_timeout,
        }
    }

    fn get(&mut self, key: &PoolKey) -> Option<Arc<SharedH2Session<ActiveStream>>> {
        let now = Instant::now();
        if let Some((session, last_used)) = self.sessions.get_mut(key) {
            if session.is_reusable() && now.duration_since(*last_used) <= self.idle_timeout {
                *last_used = now;
                return Some(session.clone());
            }
        }
        self.sessions.remove(key);
        None
    }

    fn put(&mut self, key: PoolKey, session: Arc<SharedH2Session<ActiveStream>>) {
        if session.is_reusable() {
            self.sessions.insert(key, (session, Instant::now()));
        }
    }

    fn remove(&mut self, key: &PoolKey) {
        self.sessions.remove(key);
    }

    fn clear_session(&mut self, session_id: u64) {
        self.sessions.retain(|k, _| k.session_id != session_id);
    }
}

/// Standalone HTTP client engine orchestrating connections, pooling, serialization, cookies, and streaming.
pub struct HttpClientEngine {
    boring_tls: Arc<BoringTlsConfig>,
    pool: ConnectionPool<ActiveStream>,
    h2_pool: SharedH2Pool,
    pub http_cache: super::cache::HttpCache,
    pub cookie_jar: Arc<CookieJar>,
    pub manage_cookies: bool,
    pub proxy_config: Option<ProxyConfig>,
    pub alt_svc_registry: Arc<AltSvcRegistry>,
    pub dns_resolver: Arc<DnsResolver>,
}

impl HttpClientEngine {
    pub fn new(boring_tls: Arc<BoringTlsConfig>) -> Self {
        let dns_resolver = Arc::new(DnsResolver::new(
            boring_tls.clone(),
            DnsResolverConfig::default(),
        ));
        Self {
            boring_tls,
            pool: ConnectionPool::new(6, Duration::from_secs(60)),
            h2_pool: SharedH2Pool::new(Duration::from_secs(60)),
            http_cache: super::cache::HttpCache::new(512, 4 * 1024 * 1024),
            cookie_jar: Arc::new(CookieJar::new()),
            manage_cookies: true,
            proxy_config: Some(ProxyConfig::from_env()),
            alt_svc_registry: Arc::new(AltSvcRegistry::new()),
            dns_resolver,
        }
    }

    /// Access the BoringSSL TLS configuration used for TCP/TLS and QUIC/HTTP3 connections.
    pub fn boring_tls(&self) -> &Arc<BoringTlsConfig> {
        &self.boring_tls
    }

    /// Switch the browser TLS fingerprint profile (`Chrome` or `Firefox`).
    pub fn set_tls_profile(&mut self, profile: TlsFingerprintProfile) -> Result<(), String> {
        let store = self.boring_tls.session_store.clone();
        self.boring_tls = Arc::new(BoringTlsConfig::new(profile, store)?);
        Ok(())
    }

    /// Helper to connect a TCP stream to `host:port` with DNS resolution, IPv4 prioritization, and timeout.
    fn connect_tcp(
        dns_resolver: &DnsResolver,
        host: &str,
        port: u16,
        timeout: Duration,
        dns_ms: &mut f64,
        tcp_ms: &mut f64,
    ) -> Result<TcpStream, String> {
        let is_ip_literal = host.parse::<std::net::IpAddr>().is_ok();
        let dns_start = Instant::now();
        let addrs_res = dns_resolver.resolve(host, port);
        if !is_ip_literal {
            *dns_ms = dns_start.elapsed().as_secs_f64() * 1000.0;
        }
        let addrs = addrs_res?;

        let tcp_start = Instant::now();
        let connect_timeout = std::cmp::min(timeout, Duration::from_secs(3));
        for addr in addrs {
            if let Ok(s) = TcpStream::connect_timeout(&addr, connect_timeout) {
                let _ = s.set_nodelay(true);
                let _ = s.set_read_timeout(Some(timeout));
                let _ = s.set_write_timeout(Some(timeout));
                *tcp_ms = tcp_start.elapsed().as_secs_f64() * 1000.0;
                return Ok(s);
            }
        }
        *tcp_ms = tcp_start.elapsed().as_secs_f64() * 1000.0;

        Err(format!("Could not connect to {}:{}", host, port))
    }

    /// Single-threaded `compio-driver::Proactor`-driven Happy Eyeballs v3 race.
    ///
    /// Starts the QUIC UDP handshake first, then after `cad` (75 ms) — or immediately if
    /// QUIC fails early — starts TCP Connect + BoringSSL TLS handshake in
    /// the same Proactor loop. Whichever completes handshake first wins.
    #[allow(clippy::too_many_arguments)]
    fn race_happy_eyeballs_v3<K>(
        host: &str,
        port: u16,
        h3_host: &str,
        h3_port: u16,
        dns_resolver: &DnsResolver,
        boring_tls: &Arc<BoringTlsConfig>,
        timeout: Duration,
        cad: Duration,
        is_cancelled: &mut K,
        dns_ms: &mut f64,
    ) -> Result<He3Winner, String>
    where
        K: FnMut() -> bool,
    {
        use crate::protocols::http3::QuicHandshakeState;

        let is_ip_literal = host.parse::<std::net::IpAddr>().is_ok();
        let dns_start = Instant::now();
        let tcp_addrs = dns_resolver.resolve(host, port)?;
        if !is_ip_literal {
            *dns_ms = dns_start.elapsed().as_secs_f64() * 1000.0;
        }
        let tcp_addr = tcp_addrs
            .iter()
            .copied()
            .find(|a| a.is_ipv4())
            .or_else(|| tcp_addrs.first().copied())
            .ok_or_else(|| format!("No addresses resolved for {}:{}", host, port))?;

        let h3_addr = if h3_host.eq_ignore_ascii_case(host) {
            let mut a = tcp_addr;
            a.set_port(h3_port);
            a
        } else {
            let h3_addrs = dns_resolver.resolve(h3_host, h3_port)?;
            h3_addrs
                .iter()
                .copied()
                .find(|a| a.is_ipv4())
                .or_else(|| h3_addrs.first().copied())
                .ok_or_else(|| format!("No addresses resolved for {}:{}", h3_host, h3_port))?
        };

        let mut proactor = Proactor::new()
            .map_err(|e| format!("Proactor::new failed in HEv3 race: {}", e))?;

        let race_start = Instant::now();
        let cad_deadline = race_start + cad;
        let total_deadline = race_start + timeout;

        // 1. Start QUIC (quiche) UDP handshake first
        let mut quic_opt: Option<(QuicHandshakeState, SharedFd<std::net::UdpSocket>)> = None;
        let mut udp_poll_key: Option<Key<PollOnce<SharedFd<std::net::UdpSocket>>>> = None;
        let mut h3_failed = false;
        let mut h3_elapsed_ms = 0.0_f64;

        match QuicHandshakeState::start(host, h3_addr.port(), dns_resolver, boring_tls) {
            Ok(mut quic_state) => {
                let udp_fd = SharedFd::new(quic_state.socket.try_clone().map_err(|e| format!("UDP clone: {}", e))?);
                if let Err(e) = proactor.attach(udp_fd.as_raw_fd()) {
                    h3_failed = true;
                    h3_elapsed_ms = race_start.elapsed().as_secs_f64() * 1000.0;
                    eprintln!("[ZNET-HE3] proactor attach UDP failed: {}", e);
                } else {
                    quic_state.flush_transmits();
                    match proactor.push(PollOnce::new(udp_fd.clone(), Interest::Readable)) {
                        PushEntry::Pending(k) => udp_poll_key = Some(k),
                        PushEntry::Ready(_) => {
                            match quic_state.poll_recv_and_advance() {
                                Ok(true) => {
                                        let h3_ms = race_start.elapsed().as_secs_f64() * 1000.0;
                                        let udp_socket = match udp_fd.try_unwrap() {
                                            Ok(s) => s,
                                            Err(shared) => shared
                                                .try_clone()
                                                .map_err(|e| format!("UDP clone failed: {}", e))?,
                                        };
                                        return Ok(He3Winner::H3 {
                                            quic_state,
                                            udp_socket,
                                            h3_ms,
                                        });
                                    }
                                    Ok(false) => {
                                        if let PushEntry::Pending(k) = proactor
                                            .push(PollOnce::new(udp_fd.clone(), Interest::Readable))
                                        {
                                            udp_poll_key = Some(k);
                                        }
                                    }
                                    Err(_) => {
                                        h3_failed = true;
                                        h3_elapsed_ms = race_start.elapsed().as_secs_f64() * 1000.0;
                                    }
                                }
                        }
                    }
                    if !h3_failed {
                        quic_opt = Some((quic_state, udp_fd));
                    }
                }
            }
            Err(_) => {
                h3_failed = true;
                h3_elapsed_ms = race_start.elapsed().as_secs_f64() * 1000.0;
            }
        }

        let mut tcp_fd_opt: Option<SharedFd<Socket2>> = None;
        let mut tcp_state = TcpTlsState::NotStarted;
        let mut tcp_start: Option<Instant> = None;

        let finish_tcp_win = |ssl_stream: BoringStream,
                              h3_ms: f64,
                              h2_ms: f64,
                              proactor: &mut Proactor,
                              udp_poll_key: &mut Option<Key<PollOnce<SharedFd<std::net::UdpSocket>>>>,
                              quic_opt: &mut Option<(QuicHandshakeState, SharedFd<std::net::UdpSocket>)>|
         -> Result<He3Winner, String> {
            if let Some(k) = udp_poll_key.take() {
                let _ = proactor.cancel(k);
            }
            *quic_opt = None;

            ssl_stream.get_ref().configure_blocking(timeout);
            let alpn = ssl_stream
                .ssl()
                .selected_alpn_protocol()
                .map(|s| s.to_vec());

            Ok(He3Winner::H2OrH1 {
                stream: ActiveStream::BoringTls(Box::new(ssl_stream)),
                alpn,
                h3_ms,
                h2_ms,
                demoted: true,
            })
        };

        loop {
            if is_cancelled() {
                if let Some(k) = udp_poll_key.take() {
                    let _ = proactor.cancel(k);
                }
                match tcp_state {
                    TcpTlsState::Connecting(k) => {
                        let _ = proactor.cancel(k);
                    }
                    TcpTlsState::Handshaking { poll_key: Some(k), .. } => {
                        let _ = proactor.cancel(k);
                    }
                    _ => {}
                }
                return Err("Request cancelled during HEv3 race".to_string());
            }

            let now = Instant::now();
            if now > total_deadline {
                if let Some(k) = udp_poll_key.take() {
                    let _ = proactor.cancel(k);
                }
                match tcp_state {
                    TcpTlsState::Connecting(k) => {
                        let _ = proactor.cancel(k);
                    }
                    TcpTlsState::Handshaking { poll_key: Some(k), .. } => {
                        let _ = proactor.cancel(k);
                    }
                    _ => {}
                }
                return Err(format!("HEv3 connection timed out for {}:{}", host, port));
            }

            // Start TCP Connect + TLS leg once CAD (75ms) elapses or QUIC fails early
            if matches!(tcp_state, TcpTlsState::NotStarted) && (now >= cad_deadline || h3_failed) {
                tcp_start = Some(now);
                let domain = Domain::for_address(tcp_addr);
                match Socket2::new(domain, Type::STREAM, Some(Protocol::TCP)) {
                    Ok(sock) => {
                        let _ = sock.set_nonblocking(true);
                        let _ = sock.set_tcp_nodelay(true);
                        let tcp_fd = SharedFd::new(sock);
                        if let Err(e) = proactor.attach(tcp_fd.as_raw_fd()) {
                            tcp_state = TcpTlsState::Failed(format!("TCP attach failed: {}", e));
                        } else {
                            tcp_fd_opt = Some(tcp_fd.clone());
                            match proactor.push(Connect::new(tcp_fd.clone(), SockAddr::from(tcp_addr))) {
                                PushEntry::Pending(k) => {
                                    tcp_state = TcpTlsState::Connecting(k);
                                }
                                PushEntry::Ready(BufResult(Ok(_), _)) => {
                                    match boring_tls.start_nonblocking(
                                        host,
                                        BoringIo::SharedSock(tcp_fd.clone()),
                                        None,
                                    ) {
                                        Ok(NonBlockingHandshakeStep::Complete(ssl_stream)) => {
                                            let h2_ms = tcp_start
                                                .map(|s| s.elapsed().as_secs_f64() * 1000.0)
                                                .unwrap_or(0.0);
                                            let h3_ms = if h3_failed {
                                                h3_elapsed_ms
                                            } else {
                                                race_start.elapsed().as_secs_f64() * 1000.0
                                            };
                                            return finish_tcp_win(
                                                ssl_stream,
                                                h3_ms,
                                                h2_ms,
                                                &mut proactor,
                                                &mut udp_poll_key,
                                                &mut quic_opt,
                                            );
                                        }
                                        Ok(NonBlockingHandshakeStep::Pending { mid, interest }) => {
                                            let poll_key = match proactor
                                                .push(PollOnce::new(tcp_fd.clone(), interest))
                                            {
                                                PushEntry::Pending(k) => Some(k),
                                                PushEntry::Ready(_) => None,
                                            };
                                            tcp_state = TcpTlsState::Handshaking { mid, poll_key };
                                        }
                                        Err(e) => tcp_state = TcpTlsState::Failed(e),
                                    }
                                }
                                PushEntry::Ready(BufResult(Err(e), _)) => {
                                    tcp_state = TcpTlsState::Failed(format!("TCP connect failed: {}", e));
                                }
                            }
                        }
                    }
                    Err(e) => {
                        tcp_state = TcpTlsState::Failed(format!("TCP socket create failed: {}", e));
                    }
                }
            }

            if let TcpTlsState::Failed(ref err) = tcp_state {
                let h3_grace_deadline = race_start + Duration::from_millis(250);
                if h3_failed || now >= h3_grace_deadline {
                    if let Some(k) = udp_poll_key.take() {
                        let _ = proactor.cancel(k);
                    }
                    return Err(err.clone());
                }
            }

            // Compute next wakeup deadline for Proactor::poll
            let mut wait_dur = total_deadline.saturating_duration_since(now).min(Duration::from_millis(25));
            if matches!(tcp_state, TcpTlsState::Failed(_)) && !h3_failed {
                let h3_grace_deadline = race_start + Duration::from_millis(250);
                wait_dur = wait_dur.min(h3_grace_deadline.saturating_duration_since(now));
            }
            if matches!(tcp_state, TcpTlsState::NotStarted) && !h3_failed {
                wait_dur = wait_dur.min(cad_deadline.saturating_duration_since(now));
            }
            if !h3_failed {
                if let Some((ref mut q, _)) = quic_opt {
                    if let Some(qt) = q.timeout() {
                        wait_dur = wait_dur.min(qt);
                    }
                }
            }

            if let Err(e) = proactor.poll(Some(wait_dur)) {
                if !matches!(
                    e.kind(),
                    std::io::ErrorKind::TimedOut | std::io::ErrorKind::Interrupted
                ) {
                    return Err(format!("Proactor::poll error: {}", e));
                }
            }

            let _now = Instant::now();

            // Drive QUIC leg
            if !h3_failed {
                if let Some((mut quic_state, udp_fd)) = quic_opt.take() {
                    if let Some(k) = udp_poll_key.take() {
                        if let PushEntry::Pending(k) = proactor.pop(k) {
                            udp_poll_key = Some(k);
                        }
                    }

                    if !h3_failed {
                        match quic_state.poll_recv_and_advance() {
                            Ok(true) => {
                                let h3_ms = race_start.elapsed().as_secs_f64() * 1000.0;
                                if let Some(k) = udp_poll_key.take() {
                                    let _ = proactor.cancel(k);
                                }
                                match tcp_state {
                                    TcpTlsState::Connecting(k) => {
                                        let _ = proactor.cancel(k);
                                    }
                                    TcpTlsState::Handshaking { poll_key: Some(k), .. } => {
                                        let _ = proactor.cancel(k);
                                    }
                                    _ => {}
                                }
                                drop(tcp_fd_opt.take());

                                let udp_socket = match udp_fd.try_unwrap() {
                                    Ok(s) => s,
                                    Err(shared) => shared
                                        .try_clone()
                                        .map_err(|e| format!("UDP clone failed: {}", e))?,
                                };
                                return Ok(He3Winner::H3 {
                                    quic_state,
                                    udp_socket,
                                    h3_ms,
                                });
                            }
                            Ok(false) => {
                                quic_state.flush_transmits();
                                if udp_poll_key.is_none() {
                                    if let PushEntry::Pending(k) =
                                        proactor.push(PollOnce::new(udp_fd.clone(), Interest::Readable))
                                    {
                                        udp_poll_key = Some(k);
                                    }
                                }
                                quic_opt = Some((quic_state, udp_fd));
                            }
                            Err(_) => {
                                h3_failed = true;
                                h3_elapsed_ms = race_start.elapsed().as_secs_f64() * 1000.0;
                                if let Some(k) = udp_poll_key.take() {
                                    let _ = proactor.cancel(k);
                                }
                            }
                        }
                    } else if let Some(k) = udp_poll_key.take() {
                        let _ = proactor.cancel(k);
                    }
                }
            }

            // Drive TCP/TLS leg
            match std::mem::replace(&mut tcp_state, TcpTlsState::NotStarted) {
                TcpTlsState::NotStarted => {}
                TcpTlsState::Failed(e) => {
                    tcp_state = TcpTlsState::Failed(e);
                }
                TcpTlsState::Connecting(k) => match proactor.pop(k) {
                    PushEntry::Pending(k) => {
                        tcp_state = TcpTlsState::Connecting(k);
                    }
                    PushEntry::Ready(BufResult(Ok(_), _)) => {
                        let tcp_fd = tcp_fd_opt.as_ref().unwrap();
                        match boring_tls.start_nonblocking(
                            host,
                            BoringIo::SharedSock(tcp_fd.clone()),
                            None,
                        ) {
                            Ok(NonBlockingHandshakeStep::Complete(ssl_stream)) => {
                                let h2_ms = tcp_start
                                    .map(|s| s.elapsed().as_secs_f64() * 1000.0)
                                    .unwrap_or(0.0);
                                let h3_ms = if h3_failed {
                                    h3_elapsed_ms
                                } else {
                                    race_start.elapsed().as_secs_f64() * 1000.0
                                };
                                return finish_tcp_win(
                                    ssl_stream,
                                    h3_ms,
                                    h2_ms,
                                    &mut proactor,
                                    &mut udp_poll_key,
                                    &mut quic_opt,
                                );
                            }
                            Ok(NonBlockingHandshakeStep::Pending { mid, interest }) => {
                                let poll_key = match proactor
                                    .push(PollOnce::new(tcp_fd.clone(), interest))
                                {
                                    PushEntry::Pending(k) => Some(k),
                                    PushEntry::Ready(_) => None,
                                };
                                tcp_state = TcpTlsState::Handshaking { mid, poll_key };
                            }
                            Err(e) => tcp_state = TcpTlsState::Failed(e),
                        }
                    }
                    PushEntry::Ready(BufResult(Err(e), _)) => {
                        tcp_state = TcpTlsState::Failed(format!("TCP connect failed: {}", e));
                    }
                },
                TcpTlsState::Handshaking { mid, poll_key } => {
                    let mut ready = poll_key.is_none();
                    let mut still_pending = None;
                    if let Some(k) = poll_key {
                        match proactor.pop(k) {
                            PushEntry::Ready(_) => ready = true,
                            PushEntry::Pending(k) => still_pending = Some(k),
                        }
                    }

                    if ready {
                        let tcp_fd = tcp_fd_opt.as_ref().unwrap();
                        match step_boring_handshake(mid) {
                            Ok(NonBlockingHandshakeStep::Complete(ssl_stream)) => {
                                let h2_ms = tcp_start
                                    .map(|s| s.elapsed().as_secs_f64() * 1000.0)
                                    .unwrap_or(0.0);
                                let h3_ms = if h3_failed {
                                    h3_elapsed_ms
                                } else {
                                    race_start.elapsed().as_secs_f64() * 1000.0
                                };
                                return finish_tcp_win(
                                    ssl_stream,
                                    h3_ms,
                                    h2_ms,
                                    &mut proactor,
                                    &mut udp_poll_key,
                                    &mut quic_opt,
                                );
                            }
                            Ok(NonBlockingHandshakeStep::Pending { mid, interest }) => {
                                let next_key = match proactor
                                    .push(PollOnce::new(tcp_fd.clone(), interest))
                                {
                                    PushEntry::Pending(k) => Some(k),
                                    PushEntry::Ready(_) => None,
                                };
                                tcp_state = TcpTlsState::Handshaking {
                                    mid,
                                    poll_key: next_key,
                                };
                            }
                            Err(e) => tcp_state = TcpTlsState::Failed(e),
                        }
                    } else {
                        tcp_state = TcpTlsState::Handshaking {
                            mid,
                            poll_key: still_pending,
                        };
                    }
                }
            }
        }
    }

    /// Clear pooled connections and cookies for a specific session.
    pub fn clear_session(&mut self, session_id: u64) {
        self.pool.clear_session(session_id);
        self.h2_pool.clear_session(session_id);
        self.http_cache.clear_session(session_id);
        self.cookie_jar.clear_session(session_id);
    }

    fn prepare_h2_options(
        cookie_jar: Option<&CookieJar>,
        options: &HttpRequestOptions,
        parsed_url: &Url,
    ) -> HttpRequestOptions {
        let mut h2_options = options.clone();
        let Some(cookie_jar) = cookie_jar else {
            return h2_options;
        };
        let mut cookie_map: HashMap<String, String> = HashMap::new();
        if let Some(cookie_val) = cookie_jar.get_cookie_header(options.session_id, parsed_url) {
            for part in cookie_val.split(';') {
                let trimmed = part.trim();
                if let Some((ck, cv)) = trimmed.split_once('=') {
                    cookie_map.insert(ck.trim().to_string(), cv.trim().to_string());
                }
            }
        }
        for (k, v) in &options.headers {
            if k.eq_ignore_ascii_case("cookie") {
                for part in v.split(';') {
                    let trimmed = part.trim();
                    if let Some((ck, cv)) = trimmed.split_once('=') {
                        cookie_map.insert(ck.trim().to_string(), cv.trim().to_string());
                    }
                }
            }
        }
        if !cookie_map.is_empty() {
            let mut cookie_pairs: Vec<String> = cookie_map
                .into_iter()
                .map(|(k, v)| format!("{}={}", k, v))
                .collect();
            cookie_pairs.sort();
            h2_options.headers.retain(|(k, _)| !k.eq_ignore_ascii_case("cookie"));
            h2_options.headers.push(("cookie".to_string(), cookie_pairs.join("; ")));
        }
        h2_options
    }

    /// Prepare HTTP/3 request options with full middleware parity to H1/H2:
    /// merges CookieJar + caller Cookie header, strips hop-by-hop headers, and
    /// injects `accept-encoding: gzip, deflate, br, zstd` when transparent decompression applies.
    pub(crate) fn prepare_h3_options(
        cookie_jar: Option<&CookieJar>,
        options: &HttpRequestOptions,
        parsed_url: &Url,
    ) -> HttpRequestOptions {
        let mut h3_options = Self::prepare_h2_options(cookie_jar, options, parsed_url);
        h3_options
            .headers
            .retain(|(k, _)| !is_hop_by_hop_header(k));

        let has_range = h3_options
            .headers
            .iter()
            .any(|(k, _)| k.eq_ignore_ascii_case("range"));
        let has_accept_encoding = h3_options
            .headers
            .iter()
            .any(|(k, _)| k.eq_ignore_ascii_case("accept-encoding"));
        if h3_options.transparent_decompression && !has_range && !has_accept_encoding {
            h3_options.headers.push((
                "accept-encoding".to_string(),
                "gzip, deflate, br, zstd".to_string(),
            ));
        }
        h3_options
    }

    #[allow(clippy::too_many_arguments)]
    fn execute_h2_session<H, D, C, K>(
        cookie_jar: Option<&Arc<CookieJar>>,
        alt_svc_registry: &Arc<AltSvcRegistry>,
        h2_pool: &mut SharedH2Pool,
        h2_session: Arc<SharedH2Session<ActiveStream>>,
        pool_key: &PoolKey,
        options: &HttpRequestOptions,
        parsed_url: &Url,
        host: &str,
        port: u16,
        body_ring: Option<&BodyRingDescriptor>,
        perf: &mut PerfTelemetry,
        on_headers: &mut H,
        on_data_chunk: &mut D,
        on_complete: &mut C,
        is_cancelled: &mut K,
    ) -> Result<bool, String>
    where
        H: FnMut(u16, &str, &[(String, String)]),
        D: FnMut(&[u8]),
        C: FnMut(bool),
        K: FnMut() -> bool,
    {
        // Register in shared pool immediately so concurrent callers can multiplex on this session
        h2_pool.put(pool_key.clone(), h2_session.clone());

        let h2_options = Self::prepare_h2_options(cookie_jar.map(|j| j.as_ref()), options, parsed_url);
        let cookie_jar = cookie_jar.cloned();
        let alt_svc_registry = alt_svc_registry.clone();
        let session_id = options.session_id;
        let parsed_url_clone = parsed_url.clone();
        let host_clone = host.to_string();

        let req_ready_at = Instant::now();
        let headers_at = Cell::new(None::<Instant>);
        let ttfb_ms_cell = Cell::new(0.0_f64);
        let body_ms_cell = Cell::new(0.0_f64);
        let status_cell = Cell::new(0_u16);

        let headers_at_ref = &headers_at;
        let ttfb_ms_ref = &ttfb_ms_cell;
        let status_ref = &status_cell;
        let headers_at_ref_2 = &headers_at;
        let body_ms_ref = &body_ms_cell;

        let res = h2_session.execute_request(
            &h2_options,
            body_ring,
            |status, reason, headers| {
                headers_at_ref.set(Some(Instant::now()));
                ttfb_ms_ref.set(req_ready_at.elapsed().as_secs_f64() * 1000.0);
                status_ref.set(status);
                for (k, v) in headers {
                    if k.eq_ignore_ascii_case("set-cookie") {
                        if let Some(ref jar) = cookie_jar {
                            jar.process_set_cookie(session_id, &parsed_url_clone, v);
                        }
                    }
                    if k.eq_ignore_ascii_case("alt-svc") {
                        alt_svc_registry.insert(&host_clone, port, v);
                    }
                }
                on_headers(status, reason, headers);
            },
            |chunk| on_data_chunk(chunk),
            |keep_alive| {
                if let Some(h_at) = headers_at_ref_2.get() {
                    body_ms_ref.set(h_at.elapsed().as_secs_f64() * 1000.0);
                }
                on_complete(keep_alive);
            },
            || is_cancelled(),
        );

        perf.ttfb_ms = ttfb_ms_cell.get();
        perf.body_ms = body_ms_cell.get();
        perf.status = status_cell.get();

        if !h2_session.is_reusable() {
            h2_pool.remove(pool_key);
        }

        res
    }

    /// Execute an HTTP request with progressive streaming and optional zero-copy BodyRing piping.
    pub fn execute_streaming<H, D, C>(
        &mut self,
        options: &HttpRequestOptions,
        body_ring: Option<&BodyRingDescriptor>,
        on_headers: H,
        on_data_chunk: D,
        on_complete: C,
    ) -> Result<bool, String>
    where
        H: FnMut(u16, &str, &[(String, String)]),
        D: FnMut(&[u8]),
        C: FnMut(bool),
    {
        self.execute_streaming_with_cancel(options, body_ring, on_headers, on_data_chunk, on_complete, || false)
    }

    /// Execute an HTTP request with progressive streaming, zero-copy BodyRing, and early cancellation check.
    /// Integrates in-memory HTTP caching (`Cache-Control` freshness + `ETag`/`Last-Modified` 304 revalidation).
    pub fn execute_streaming_with_cancel<H, D, C, K>(
        &mut self,
        options: &HttpRequestOptions,
        body_ring: Option<&BodyRingDescriptor>,
        mut on_headers: H,
        mut on_data_chunk: D,
        mut on_complete: C,
        mut is_cancelled: K,
    ) -> Result<bool, String>
    where
        H: FnMut(u16, &str, &[(String, String)]),
        D: FnMut(&[u8]),
        C: FnMut(bool),
        K: FnMut() -> bool,
    {
        use super::cache::CacheLookup;

        let mut is_revalidating = false;
        let mut reval_options: Option<HttpRequestOptions> = None;

        match self.http_cache.lookup(
            options.session_id,
            &options.method,
            &options.url,
            &options.headers,
        ) {
            CacheLookup::Fresh(entry) => {
                if is_cancelled() {
                    return Ok(false);
                }
                on_headers(entry.status, &entry.reason, &entry.headers);
                if !entry.body.is_empty() {
                    if let Some(ring) = body_ring {
                        let mut offset = 0;
                        while offset < entry.body.len() && !ring.is_closed.load(Ordering::Acquire) {
                            if is_cancelled() {
                                return Ok(true);
                            }
                            let written = ring.write_slice(&entry.body[offset..]);
                            offset += written;
                            if offset < entry.body.len() {
                                ring.wait_drain(5);
                            }
                        }
                    }
                    on_data_chunk(&entry.body);
                }
                on_complete(true);
                return Ok(true);
            }
            CacheLookup::Revalidate { etag, last_modified } => {
                is_revalidating = true;
                let mut opts = options.clone();
                if let Some(tag) = etag {
                    if !opts.headers.iter().any(|(k, _)| k.eq_ignore_ascii_case("if-none-match")) {
                        opts.headers.push(("If-None-Match".to_string(), tag));
                    }
                }
                if let Some(lm) = last_modified {
                    if !opts.headers.iter().any(|(k, _)| k.eq_ignore_ascii_case("if-modified-since")) {
                        opts.headers.push(("If-Modified-Since".to_string(), lm));
                    }
                }
                reval_options = Some(opts);
            }
            CacheLookup::Miss => {}
        }

        let effective_opts = reval_options.as_ref().unwrap_or(options);
        let should_capture = options.method.eq_ignore_ascii_case("GET")
            && !options.headers.iter().any(|(k, _)| k.eq_ignore_ascii_case("range"));

        let mut cap_status: u16 = 0;
        let mut cap_reason = String::new();
        let mut cap_headers: Vec<(String, String)> = Vec::new();
        let mut cap_body: Vec<u8> = Vec::new();
        let mut cap_overflow = false;
        let got_304 = Cell::new(false);
        const MAX_CACHE_CAPTURE: usize = 4 * 1024 * 1024;

        let res = self.execute_streaming_uncached(
            effective_opts,
            body_ring,
            |status, reason, headers| {
                cap_status = status;
                cap_reason = reason.to_string();
                cap_headers = headers.to_vec();
                if is_revalidating && status == 304 {
                    got_304.set(true);
                    return;
                }
                on_headers(status, reason, headers);
            },
            |chunk| {
                if got_304.get() {
                    return;
                }
                if should_capture && !cap_overflow {
                    if cap_body.len() + chunk.len() <= MAX_CACHE_CAPTURE {
                        cap_body.extend_from_slice(chunk);
                    } else {
                        cap_overflow = true;
                        cap_body.clear();
                        cap_body.shrink_to_fit();
                    }
                }
                on_data_chunk(chunk);
            },
            |keep_alive| {
                if got_304.get() {
                    return;
                }
                on_complete(keep_alive);
            },
            is_cancelled,
        );

        if got_304.get() {
            if let Some(refreshed) = self.http_cache.revalidate_304(
                options.session_id,
                &options.url,
                &cap_headers,
            ) {
                on_headers(refreshed.status, &refreshed.reason, &refreshed.headers);
                if !refreshed.body.is_empty() {
                    if let Some(ring) = body_ring {
                        let mut offset = 0;
                        while offset < refreshed.body.len() && !ring.is_closed.load(Ordering::Acquire) {
                            let written = ring.write_slice(&refreshed.body[offset..]);
                            offset += written;
                            if offset < refreshed.body.len() {
                                ring.wait_drain(5);
                            }
                        }
                    }
                    on_data_chunk(&refreshed.body);
                }
                on_complete(true);
                return Ok(true);
            } else {
                on_headers(cap_status, &cap_reason, &cap_headers);
                on_complete(true);
                return res;
            }
        }

        if res.is_ok() && should_capture && !cap_overflow {
            self.http_cache.store(
                options.session_id,
                &options.method,
                &options.url,
                cap_status,
                &cap_reason,
                &cap_headers,
                cap_body,
            );
        }

        res
    }

    fn execute_streaming_uncached<H, D, C, K>(
        &mut self,
        options: &HttpRequestOptions,
        body_ring: Option<&BodyRingDescriptor>,
        mut on_headers: H,
        mut on_data_chunk: D,
        mut on_complete: C,
        mut is_cancelled: K,
    ) -> Result<bool, String>
    where
        H: FnMut(u16, &str, &[(String, String)]),
        D: FnMut(&[u8]),
        C: FnMut(bool),
        K: FnMut() -> bool,
    {
        let total_start = Instant::now();
        let active_streams = ACTIVE_STREAMS.fetch_add(1, Ordering::AcqRel) + 1;
        let mut perf = PerfTelemetry {
            method: options.method.clone(),
            host: String::new(),
            path_prefix: truncate_path(&options.url),
            proto: "h1",
            reused: false,
            streams: active_streams,
            dns_ms: 0.0,
            tcp_tls_ms: 0.0,
            ttfb_ms: 0.0,
            body_ms: 0.0,
            status: 0,
            total_start,
        };

        let parsed_url = Url::parse(&options.url)
            .map_err(|e| format!("Invalid URL: {}", e))?;

        let scheme = parsed_url.scheme();
        let is_tls = match scheme {
            "https" => true,
            "http" => false,
            other => return Err(format!("Unsupported scheme: {}", other)),
        };

        let host = parsed_url.host_str().ok_or("Missing host in URL")?.to_string();
        let port = parsed_url.port_or_known_default().unwrap_or(if is_tls { 443 } else { 80 });

        let mut path_and_query = parsed_url.path().to_string();
        if let Some(q) = parsed_url.query() {
            path_and_query.push('?');
            path_and_query.push_str(q);
        }
        if path_and_query.is_empty() {
            path_and_query = "/".to_string();
        }
        perf.host = host.clone();
        perf.path_prefix = truncate_path(&path_and_query);

        // Resolve proxy configuration
        let proxy_rule = self
            .proxy_config
            .as_ref()
            .map(|pc| pc.resolve(&options.url, &host, is_tls))
            .unwrap_or(ProxyRule {
                scheme: ProxyScheme::Direct,
                host: String::new(),
                port: 0,
            });

        let pool_key = PoolKey::new(options.session_id, &host, port, is_tls);

        let active_cookie_jar = if self.manage_cookies {
            Some(&self.cookie_jar)
        } else {
            None
        };

        // 0. Check pooled HTTP/2 sessions FIRST before any H3 attempt (skips HEv3 race if warm H2Session exists)
        if let Some(pooled_h2) = self.h2_pool.get(&pool_key) {
            perf.proto = "h2";
            perf.reused = true;
            match Self::execute_h2_session(
                active_cookie_jar,
                &self.alt_svc_registry,
                &mut self.h2_pool,
                pooled_h2,
                &pool_key,
                options,
                &parsed_url,
                &host,
                port,
                body_ring,
                &mut perf,
                &mut on_headers,
                &mut on_data_chunk,
                &mut on_complete,
                &mut is_cancelled,
            ) {
                Ok(res) => return Ok(res),
                Err(e) if perf.status != 0 => return Err(e),
                Err(_) => {
                    // Pooled H2 connection went stale before headers; fall through to fresh connection
                    perf.reused = false;
                    perf.proto = "h1";
                }
            }
        }

        let mut preconnected_tls_stream: Option<ActiveStream> = None;

        // 0b. Happy Eyeballs v3 race (Proactor-driven QUIC + TCP/TLS with 75ms CAD) if direct HTTPS & active Alt-Svc
        if is_tls && proxy_rule.scheme == ProxyScheme::Direct {
            if let Some((h3_host, h3_port)) = self.alt_svc_registry.get_h3_target(&host, port) {
                let cad_ms = HE3_CAD.as_secs_f64() * 1000.0;
                match Self::race_happy_eyeballs_v3(
                    &host,
                    port,
                    &h3_host,
                    h3_port,
                    &self.dns_resolver,
                    &self.boring_tls,
                    options.timeout,
                    HE3_CAD,
                    &mut is_cancelled,
                    &mut perf.dns_ms,
                ) {
                    Ok(He3Winner::H3 {
                        quic_state,
                        udp_socket,
                        h3_ms,
                    }) => {
                        self.alt_svc_registry.mark_healthy(&host, port);
                        eprintln!(
                            "[ZNET-HE3] origin={}:{} cad_ms={:.1} h3_ms={:.1} h2_ms=0.0 winner=h3 demoted=false",
                            host, port, cad_ms, h3_ms
                        );
                        perf.tcp_tls_ms = h3_ms;

                        // Full middleware parity for HTTP/3: optional CookieJar merge/Set-Cookie, hop-by-hop strip, Accept-Encoding
                        let h3_options = Self::prepare_h3_options(active_cookie_jar.map(|j| j.as_ref()), options, &parsed_url);
                        let cookie_jar_h3 = active_cookie_jar.cloned();
                        let alt_svc_h3 = self.alt_svc_registry.clone();
                        let parsed_url_h3 = parsed_url.clone();
                        let host_h3 = host.clone();
                        let session_id_h3 = options.session_id;
                        let req_ready_at = Instant::now();
                        let headers_at = Cell::new(None::<Instant>);
                        let ttfb_ms_cell = Cell::new(0.0_f64);
                        let body_ms_cell = Cell::new(0.0_f64);
                        let status_cell = Cell::new(0_u16);

                        drop(udp_socket);
                        let h3_res = Http3Client::execute_connected_streaming(
                            quic_state,
                            &h3_options,
                            body_ring,
                            |status, reason, headers| {
                                headers_at.set(Some(Instant::now()));
                                ttfb_ms_cell.set(req_ready_at.elapsed().as_secs_f64() * 1000.0);
                                status_cell.set(status);
                                for (k, v) in headers {
                                    if k.eq_ignore_ascii_case("set-cookie") {
                                        if let Some(ref jar) = cookie_jar_h3 {
                                            jar.process_set_cookie(session_id_h3, &parsed_url_h3, v);
                                        }
                                    }
                                    if k.eq_ignore_ascii_case("alt-svc") {
                                        alt_svc_h3.insert(&host_h3, port, v);
                                    }
                                }
                                on_headers(status, reason, headers);
                            },
                            |chunk| on_data_chunk(chunk),
                            |keep_alive| {
                                if let Some(h_at) = headers_at.get() {
                                    body_ms_cell.set(h_at.elapsed().as_secs_f64() * 1000.0);
                                }
                                on_complete(keep_alive);
                            },
                            &mut is_cancelled,
                        );
                        perf.ttfb_ms = ttfb_ms_cell.get();
                        perf.body_ms = body_ms_cell.get();
                        perf.status = status_cell.get();

                        match h3_res {
                            Ok(true) => {
                                perf.proto = "h3";
                                return Ok(true);
                            }
                            Ok(false) | Err(_) => {
                                // H3 stream failed after handshake; demote origin and fall back to TCP/TLS
                                self.alt_svc_registry.mark_broken(&host, port);
                            }
                        }
                    }
                    Ok(He3Winner::H2OrH1 {
                        stream: tls_stream,
                        alpn,
                        h3_ms,
                        h2_ms,
                        demoted,
                    }) => {
                        if demoted {
                            self.alt_svc_registry.mark_broken(&host, port);
                        }
                        eprintln!(
                            "[ZNET-HE3] origin={}:{} cad_ms={:.1} h3_ms={:.1} h2_ms={:.1} winner=h2 demoted={}",
                            host, port, cad_ms, h3_ms, h2_ms, demoted
                        );
                        perf.tcp_tls_ms = h2_ms;
                        if alpn.as_deref() == Some(b"h2") {
                            perf.proto = "h2";
                            let h2_session = SharedH2Session::new(H2Session::new(tls_stream)?);
                            return Self::execute_h2_session(
                                active_cookie_jar,
                                &self.alt_svc_registry,
                                &mut self.h2_pool,
                                h2_session,
                                &pool_key,
                                options,
                                &parsed_url,
                                &host,
                                port,
                                body_ring,
                                &mut perf,
                                &mut on_headers,
                                &mut on_data_chunk,
                                &mut on_complete,
                                &mut is_cancelled,
                            );
                        }
                        preconnected_tls_stream = Some(tls_stream);
                    }
                    Err(_) => {
                        // Both legs failed or timed out in HEv3 race; demote H3 and fall through to standard path
                        self.alt_svc_registry.mark_broken(&host, port);
                    }
                }
            }
        }

        // 1. Check HTTP/1.1 connection pool or establish new connection
        let mut stream = if let Some(s) = preconnected_tls_stream {
            s
        } else if let Some(pooled) = self.pool.get(&pool_key) {
            perf.reused = true;
            pooled.socket
        } else {
            let mut tcp_ms = 0.0;
            let tcp = match proxy_rule.scheme {
                ProxyScheme::Direct => {
                    Self::connect_tcp(&self.dns_resolver, &host, port, options.timeout, &mut perf.dns_ms, &mut tcp_ms)?
                }
                ProxyScheme::Http => {
                    let mut s = Self::connect_tcp(&self.dns_resolver, &proxy_rule.host, proxy_rule.port, options.timeout, &mut perf.dns_ms, &mut tcp_ms)?;
                    let tunnel_start = Instant::now();
                    let tunnel_res = establish_http_connect_tunnel(&mut s, &host, port);
                    tcp_ms += tunnel_start.elapsed().as_secs_f64() * 1000.0;
                    tunnel_res.map_err(|e| {
                        perf.tcp_tls_ms = tcp_ms;
                        format!("HTTP CONNECT tunnel failed: {}", e)
                    })?;
                    s
                }
                ProxyScheme::Socks5 => {
                    let mut s = Self::connect_tcp(&self.dns_resolver, &proxy_rule.host, proxy_rule.port, options.timeout, &mut perf.dns_ms, &mut tcp_ms)?;
                    let tunnel_start = Instant::now();
                    let tunnel_res = establish_socks5_tunnel(&mut s, &host, port);
                    tcp_ms += tunnel_start.elapsed().as_secs_f64() * 1000.0;
                    tunnel_res.map_err(|e| {
                        perf.tcp_tls_ms = tcp_ms;
                        format!("SOCKS5 tunnel failed: {}", e)
                    })?;
                    s
                }
                ProxyScheme::Socks4 => {
                    return Err("SOCKS4 proxy is not supported, configure SOCKS5 or HTTP proxy".to_string());
                }
            };
            perf.tcp_tls_ms = tcp_ms;

            if is_tls {
                let tls_start = Instant::now();
                let ssl_stream = match self.boring_tls.connect_blocking_io(&host, BoringIo::Tcp(tcp), None) {
                    Ok(s) => s,
                    Err(e) => {
                        perf.tcp_tls_ms = tcp_ms + tls_start.elapsed().as_secs_f64() * 1000.0;
                        return Err(e);
                    }
                };
                perf.tcp_tls_ms = tcp_ms + tls_start.elapsed().as_secs_f64() * 1000.0;

                let alpn = ssl_stream
                    .ssl()
                    .selected_alpn_protocol()
                    .map(|s| s.to_vec());
                let tls_stream = ActiveStream::BoringTls(Box::new(ssl_stream));
                if alpn.as_deref() == Some(b"h2") {
                    perf.proto = "h2";
                    let h2_session = SharedH2Session::new(H2Session::new(tls_stream)?);
                    return Self::execute_h2_session(
                        active_cookie_jar,
                        &self.alt_svc_registry,
                        &mut self.h2_pool,
                        h2_session,
                        &pool_key,
                        options,
                        &parsed_url,
                        &host,
                        port,
                        body_ring,
                        &mut perf,
                        &mut on_headers,
                        &mut on_data_chunk,
                        &mut on_complete,
                        &mut is_cancelled,
                    );
                }

                tls_stream
            } else {
                ActiveStream::Plain(tcp)
            }
        };

        // 2. Format Request

        let mut req_builder = Http1RequestBuilder::new(&options.method, &path_and_query);
        let mut has_range_header = false;
        let mut has_accept_encoding = false;

        if self.manage_cookies {
            let mut cookie_map: HashMap<String, String> = HashMap::new();

            // 1. Preload matching cookies from RFC 6265 CookieJar (HttpOnly, cross-domain, session cookies)
            if let Some(cookie_val) = self.cookie_jar.get_cookie_header(options.session_id, &parsed_url) {
                for part in cookie_val.split(';') {
                    let trimmed = part.trim();
                    if let Some((ck, cv)) = trimmed.split_once('=') {
                        cookie_map.insert(ck.trim().to_string(), cv.trim().to_string());
                    }
                }
            }

            // 2. Process caller headers: merge any Cookie header with jar cookies, track range/encoding
            for (k, v) in &options.headers {
                if k.eq_ignore_ascii_case("cookie") {
                    for part in v.split(';') {
                        let trimmed = part.trim();
                        if let Some((ck, cv)) = trimmed.split_once('=') {
                            cookie_map.insert(ck.trim().to_string(), cv.trim().to_string());
                        }
                    }
                } else {
                    if k.eq_ignore_ascii_case("range") {
                        has_range_header = true;
                    }
                    if k.eq_ignore_ascii_case("accept-encoding") {
                        has_accept_encoding = true;
                    }
                    req_builder = req_builder.header(k, v);
                }
            }

            // 3. Inject unified merged Cookie header if any cookies exist
            if !cookie_map.is_empty() {
                let mut cookie_pairs: Vec<String> = cookie_map
                    .into_iter()
                    .map(|(k, v)| format!("{}={}", k, v))
                    .collect();
                cookie_pairs.sort();
                req_builder = req_builder.header("Cookie", &cookie_pairs.join("; "));
            }
        } else {
            // Caller (e.g. WebKit NetworkStorageSession) manages cookies exclusively.
            for (k, v) in &options.headers {
                if k.eq_ignore_ascii_case("range") {
                    has_range_header = true;
                }
                if k.eq_ignore_ascii_case("accept-encoding") {
                    has_accept_encoding = true;
                }
                req_builder = req_builder.header(k, v);
            }
        }

        // Range requests must not request transparent compression because partial slices cannot
        // be decompressed independently and WebKit expects raw byte ranges for media streaming.
        if options.transparent_decompression && !has_range_header && !has_accept_encoding {
            req_builder = req_builder.header("Accept-Encoding", "gzip, deflate, br, zstd");
        }

        if let Some(ref b) = options.body {
            req_builder = req_builder.body(b);
        }

        let wire_req = req_builder.serialize(&host, true);

        // 3. Send Request
        let req_ready_at = Instant::now();
        stream.write_all(&wire_req)
            .map_err(|e| format!("Failed to send request: {}", e))?;
        stream.flush()
            .map_err(|e| format!("Failed to flush request: {}", e))?;

        // 4. Progressive Read Loop
        let mut parser = Http1ResponseParser::new();
        let mut read_buf = [0u8; 8192];
        let mut headers_dispatched = false;
        let mut headers_at: Option<Instant> = None;
        let mut can_keep_alive = false;
        let mut is_completed = false;
        let mut decompressor: Option<StreamDecompressor> = None;

        while !is_completed {
            if is_cancelled() {
                return Ok(headers_dispatched);
            }

            if let Some(ring) = body_ring {
                while ring.should_stop_reading() && !ring.is_closed.load(Ordering::Acquire) {
                    if is_cancelled() {
                        return Ok(headers_dispatched);
                    }
                    ring.wait_drain(5);
                }
            }

            match stream.read(&mut read_buf) {
                Ok(0) => {
                    // EOF on stream
                    let eof_results = parser.on_eof();
                    for ev in eof_results {
                        if let Http1FeedResult::BodyData(chunk) = ev {
                            if let Some(ref mut dec) = decompressor {
                                dec.feed(&chunk, |decompressed_slice| {
                                    if let Some(ring) = body_ring {
                                        ring.write_slice(decompressed_slice);
                                    }
                                    on_data_chunk(decompressed_slice);
                                })
                                .map_err(|e| format!("Decompression error: {}", e))?;
                            } else {
                                if let Some(ring) = body_ring {
                                    ring.write_slice(&chunk);
                                }
                                on_data_chunk(&chunk);
                            }
                        }
                    }
                    if let Some(dec) = decompressor.take() {
                        dec.finish(|decompressed_slice| {
                            if let Some(ring) = body_ring {
                                ring.write_slice(decompressed_slice);
                            }
                            on_data_chunk(decompressed_slice);
                        })
                        .map_err(|e| format!("Decompression finish error: {}", e))?;
                    }
                    if let Some(h_at) = headers_at {
                        perf.body_ms = h_at.elapsed().as_secs_f64() * 1000.0;
                    }
                    on_complete(false);
                    break;
                }
                Ok(n) => {
                    let results = parser.feed(&read_buf[..n])
                        .map_err(|e| format!("HTTP parse error: {}", e))?;

                    for ev in results {
                        match ev {
                            Http1FeedResult::HeadersParsed { status_code, reason, headers, .. } => {
                                for (k, v) in &headers {
                                    // Automatic Set-Cookie processing into RFC 6265 CookieJar
                                    if self.manage_cookies && k.eq_ignore_ascii_case("set-cookie") {
                                        self.cookie_jar.process_set_cookie(options.session_id, &parsed_url, v);
                                    }
                                    // Automatic Alt-Svc discovery for HTTP/3
                                    if k.eq_ignore_ascii_case("alt-svc") {
                                        self.alt_svc_registry.insert(&host, port, v);
                                    }
                                }

                                let should_decompress = options.transparent_decompression
                                    && !has_range_header
                                    && status_code != 206;

                                let mut is_decompressing = false;
                                if should_decompress {
                                    if let Some((_, enc)) = headers.iter().find(|(k, _)| k.eq_ignore_ascii_case("content-encoding")) {
                                        if let Some(dec) = StreamDecompressor::new(enc) {
                                            decompressor = Some(dec);
                                            is_decompressing = true;
                                        }
                                    }
                                }

                                headers_at = Some(Instant::now());
                                perf.ttfb_ms = req_ready_at.elapsed().as_secs_f64() * 1000.0;
                                perf.status = status_code;
                                if is_decompressing {
                                    // Filter out Content-Encoding and Content-Length so downstream consumers
                                    // (like WebKit's NetworkProcess) receive clean uncompressed data and know
                                    // the stream length corresponds to the decoded body.
                                    let filtered_headers: Vec<(String, String)> = headers
                                        .into_iter()
                                        .filter(|(k, _)| {
                                            !k.eq_ignore_ascii_case("content-encoding")
                                                && !k.eq_ignore_ascii_case("content-length")
                                        })
                                        .collect();
                                    on_headers(status_code, &reason, &filtered_headers);
                                } else {
                                    on_headers(status_code, &reason, &headers);
                                }
                                headers_dispatched = true;
                            }
                            Http1FeedResult::BodyData(chunk) => {
                                if let Some(ref mut dec) = decompressor {
                                    dec.feed(&chunk, |decompressed_slice| {
                                        if let Some(ring) = body_ring {
                                            let mut offset = 0;
                                            while offset < decompressed_slice.len() && !ring.is_closed.load(Ordering::Acquire) {
                                                let written = ring.write_slice(&decompressed_slice[offset..]);
                                                offset += written;
                                                if offset < decompressed_slice.len() {
                                                    ring.wait_drain(5);
                                                }
                                            }
                                        }
                                        on_data_chunk(decompressed_slice);
                                    })
                                    .map_err(|e| format!("Decompression error: {}", e))?;
                                } else {
                                    // Progressive zero-copy write directly to BodyRing
                                    if let Some(ring) = body_ring {
                                        let mut offset = 0;
                                        while offset < chunk.len() && !ring.is_closed.load(Ordering::Acquire) {
                                            let written = ring.write_slice(&chunk[offset..]);
                                            offset += written;
                                            if offset < chunk.len() {
                                                ring.wait_drain(5);
                                            }
                                        }
                                    }
                                    // Invoke callback with borrowed slice
                                    on_data_chunk(&chunk);
                                }
                            }
                            Http1FeedResult::Complete { keep_alive } => {
                                if let Some(dec) = decompressor.take() {
                                    dec.finish(|decompressed_slice| {
                                        if let Some(ring) = body_ring {
                                            ring.write_slice(decompressed_slice);
                                        }
                                        on_data_chunk(decompressed_slice);
                                    })
                                    .map_err(|e| format!("Decompression finish error: {}", e))?;
                                }
                                can_keep_alive = keep_alive;
                                is_completed = true;
                                if let Some(h_at) = headers_at {
                                    perf.body_ms = h_at.elapsed().as_secs_f64() * 1000.0;
                                }
                                on_complete(keep_alive);
                                break;
                            }
                            Http1FeedResult::NeedMoreData => {}
                        }
                    }
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock || e.kind() == std::io::ErrorKind::TimedOut => {
                    return Err("HTTP request timed out".to_string());
                }
                Err(e) => return Err(format!("Socket read error: {}", e)),
            }
        }

        // Return Connection to Pool if keep-alive is active
        if can_keep_alive {
            self.pool.put(pool_key, stream, false);
        }

        Ok(headers_dispatched)
    }

    /// Execute an HTTP request, buffering the response for complete payload retrieval.
    pub fn execute(&mut self, options: &HttpRequestOptions) -> Result<HttpResponse, String> {
        let mut status_code = 0;
        let mut reason_phrase = String::new();
        let mut resp_headers = HashMap::new();
        let mut raw_body = Vec::new();

        self.execute_streaming(
            options,
            None,
            |code, reason, headers| {
                status_code = code;
                reason_phrase = reason.to_string();
                for (k, v) in headers {
                    resp_headers.insert(k.to_ascii_lowercase(), v.clone());
                }
            },
            |chunk| {
                raw_body.extend_from_slice(chunk);
            },
            |_keep_alive| {},
        )?;

        // Handle content decompression if requested, unless Range header was specified or status is 206
        let has_range_header = options.headers.iter().any(|(k, _)| k.eq_ignore_ascii_case("range"));
        let final_body = if options.transparent_decompression && !has_range_header && status_code != 206 {
            if let Some(encoding) = resp_headers.get("content-encoding") {
                decompress_payload(encoding, &raw_body).unwrap_or(raw_body)
            } else {
                raw_body
            }
        } else {
            raw_body
        };

        Ok(HttpResponse {
            status: status_code,
            reason: reason_phrase,
            headers: resp_headers,
            body: final_body,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocols::tls::BoringSessionStore;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU32, AtomicU64};

    #[test]
    fn test_http_client_request_options_builder() {
        let opts = HttpRequestOptions::new("POST", "https://example.com:8443/submit")
            .with_session(5)
            .header("X-Custom", "Val")
            .body(b"test".to_vec());

        assert_eq!(opts.session_id, 5);
        assert_eq!(opts.method, "POST");
        assert_eq!(opts.url, "https://example.com:8443/submit");
        assert_eq!(opts.headers.len(), 1);
        assert_eq!(opts.body, Some(b"test".to_vec()));
    }

    #[test]
    fn test_http_client_streaming_and_body_ring() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind local test server");
        let port = listener.local_addr().unwrap().port();

        let server_thread = std::thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut buf = [0u8; 1024];
                let _ = stream.read(&mut buf);
                let response = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nHello\r\n8\r\n, World!\r\n0\r\n\r\n";
                let _ = stream.write_all(response);
            }
        });

        let store = Arc::new(BoringSessionStore::in_memory());
        let tls_cfg = Arc::new(BoringTlsConfig::new(TlsFingerprintProfile::Chrome, store).unwrap());

        let mut client = HttpClientEngine::new(tls_cfg);
        let url = format!("http://127.0.0.1:{}/chunked", port);
        let opts = HttpRequestOptions::new("GET", &url);

        // Prepare a test BodyRingDescriptor
        let mut ring_buf = vec![0u8; 1024];
        let ring = BodyRingDescriptor {
            buffer_ptr: ring_buf.as_mut_ptr(),
            capacity: ring_buf.len(),
            _pad1: [0u8; 64],
            head: AtomicU64::new(0),
            _pad2: [0u8; 64],
            tail: AtomicU64::new(0),
            _pad3: [0u8; 48],
            pause_fd: AtomicI32::new(-1),
            futex_word: AtomicU32::new(0),
            is_closed: AtomicBool::new(false),
        };

        let mut streamed_chunks = Vec::new();
        let mut received_status = 0;
        let mut is_done = false;

        client.execute_streaming(
            &opts,
            Some(&ring),
            |status, _reason, _headers| {
                received_status = status;
            },
            |chunk| {
                streamed_chunks.extend_from_slice(chunk);
            },
            |_keep_alive| {
                is_done = true;
            },
        ).expect("execute streaming");

        server_thread.join().unwrap();

        assert_eq!(received_status, 200);
        assert!(is_done);
        assert_eq!(String::from_utf8(streamed_chunks).unwrap(), "Hello, World!");

        // Also verify BodyRing wrote the exact same data without copying
        let ring_read_len = ring.available_read();
        assert_eq!(ring_read_len, 13);
        assert_eq!(&ring_buf[..13], b"Hello, World!");
    }

    #[test]
    fn test_http_client_cookie_auto_storage_and_injection() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind local test server");
        let port = listener.local_addr().unwrap().port();

        let server_thread = std::thread::spawn(move || {
            // First request: sets cookie
            if let Ok((mut stream1, _)) = listener.accept() {
                let mut buf = [0u8; 1024];
                let _ = stream1.read(&mut buf);
                let response = b"HTTP/1.1 200 OK\r\nSet-Cookie: user_auth=secret_token_123; Path=/\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
                let _ = stream1.write_all(response);
            }

            // Second request: verifies cookie was sent back
            if let Ok((mut stream2, _)) = listener.accept() {
                let mut buf = [0u8; 2048];
                let n = stream2.read(&mut buf).unwrap();
                let req_str = String::from_utf8_lossy(&buf[..n]);
                assert!(req_str.contains("Cookie: user_auth=secret_token_123"));
                let response = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK";
                let _ = stream2.write_all(response);
            }
        });

        let store = Arc::new(BoringSessionStore::in_memory());
        let tls_cfg = Arc::new(BoringTlsConfig::new(TlsFingerprintProfile::Chrome, store).unwrap());

        let mut client = HttpClientEngine::new(tls_cfg);
        let url = format!("http://127.0.0.1:{}/auth", port);
        let opts = HttpRequestOptions::new("GET", &url).with_session(42);

        // First call
        let resp1 = client.execute(&opts).expect("first call");
        assert_eq!(resp1.status, 200);

        // Second call on same session
        let resp2 = client.execute(&opts).expect("second call");
        assert_eq!(resp2.status, 200);

        server_thread.join().unwrap();
    }

    #[test]
    fn test_http_client_range_request_omits_compression() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind local test server");
        let port = listener.local_addr().unwrap().port();

        let server_thread = std::thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut buf = [0u8; 2048];
                let n = stream.read(&mut buf).unwrap();
                let req_str = String::from_utf8_lossy(&buf[..n]);
                // Range header must be present
                assert!(req_str.contains("Range: bytes=0-1023") || req_str.contains("range: bytes=0-1023"));
                // Accept-Encoding must NOT be present
                assert!(!req_str.to_ascii_lowercase().contains("accept-encoding:"));

                let response = b"HTTP/1.1 206 Partial Content\r\nContent-Range: bytes 0-1023/2048\r\nContent-Length: 4\r\nConnection: close\r\n\r\nPART";
                let _ = stream.write_all(response);
            }
        });

        let store = Arc::new(BoringSessionStore::in_memory());
        let tls_cfg = Arc::new(BoringTlsConfig::new(TlsFingerprintProfile::Chrome, store).unwrap());
        let mut client = HttpClientEngine::new(tls_cfg);
        let url = format!("http://127.0.0.1:{}/video.mp4", port);
        let opts = HttpRequestOptions::new("GET", &url)
            .header("Range", "bytes=0-1023");

        let resp = client.execute(&opts).expect("range request");
        assert_eq!(resp.status, 206);
        assert_eq!(resp.body, b"PART");

        server_thread.join().unwrap();
    }

    #[test]
    fn test_http_client_early_cancellation() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind local test server");
        let port = listener.local_addr().unwrap().port();

        let server_thread = std::thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut buf = [0u8; 1024];
                let _ = stream.read(&mut buf);
                let response = b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n";
                let _ = stream.write_all(response);
                // Send some data then hold socket open
                let _ = stream.write_all(b"initial chunk");
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
        });

        let store = Arc::new(BoringSessionStore::in_memory());
        let tls_cfg = Arc::new(BoringTlsConfig::new(TlsFingerprintProfile::Chrome, store).unwrap());
        let mut client = HttpClientEngine::new(tls_cfg);
        let url = format!("http://127.0.0.1:{}/stream", port);
        let opts = HttpRequestOptions::new("GET", &url);

        let cancelled = AtomicBool::new(false);
        let mut headers_got = false;

        let res = client.execute_streaming_with_cancel(
            &opts,
            None,
            |_code, _reason, _hdrs| {
                headers_got = true;
                cancelled.store(true, std::sync::atomic::Ordering::SeqCst);
            },
            |_data| {},
            |_keep_alive| {},
            || cancelled.load(std::sync::atomic::Ordering::SeqCst),
        );

        assert!(res.is_ok());
        assert!(headers_got);
        server_thread.join().unwrap();
    }

    #[test]
    fn test_http_client_cookie_merging() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind local test server");
        let port = listener.local_addr().unwrap().port();

        let server_thread = std::thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut buf = [0u8; 2048];
                let n = stream.read(&mut buf).unwrap_or(0);
                let req_str = String::from_utf8_lossy(&buf[..n]);

                // Verify Cookie header contains merged values
                assert!(req_str.contains("Cookie:"));
                assert!(req_str.contains("jar_cookie=val1"));
                assert!(req_str.contains("webkit_cookie=val2"));

                let response = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK";
                let _ = stream.write_all(response);
            }
        });

        let store = Arc::new(BoringSessionStore::in_memory());
        let tls_cfg = Arc::new(BoringTlsConfig::new(TlsFingerprintProfile::Chrome, store).unwrap());
        let mut client = HttpClientEngine::new(tls_cfg);
        let url = format!("http://127.0.0.1:{}/cookie_test", port);
        let parsed_url = Url::parse(&url).unwrap();

        // 1. Preload jar with session cookie
        assert!(client.cookie_jar.process_set_cookie(1, &parsed_url, "jar_cookie=val1; Path=/; HttpOnly"));

        // 2. Caller passes WebKit DOM cookie
        let opts = HttpRequestOptions::new("GET", &url)
            .with_session(1)
            .header("Cookie", "webkit_cookie=val2");

        let resp = client.execute(&opts).expect("execute with merged cookies");
        assert_eq!(resp.status, 200);

        server_thread.join().unwrap();
    }

    #[test]
    fn test_http_client_multiple_set_cookie_preservation() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind local test server");
        let port = listener.local_addr().unwrap().port();

        let server_thread = std::thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut buf = [0u8; 1024];
                let _ = stream.read(&mut buf);

                let response = b"HTTP/1.1 200 OK\r\nSet-Cookie: sid=abc123xyz; Path=/; HttpOnly\r\nSet-Cookie: theme=dark; Path=/\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
                let _ = stream.write_all(response);
            }
        });

        let store = Arc::new(BoringSessionStore::in_memory());
        let tls_cfg = Arc::new(BoringTlsConfig::new(TlsFingerprintProfile::Chrome, store).unwrap());
        let mut client = HttpClientEngine::new(tls_cfg);
        let url = format!("http://127.0.0.1:{}/multi_cookie", port);
        let parsed_url = Url::parse(&url).unwrap();

        let mut received_set_cookie_count = 0;
        let opts = HttpRequestOptions::new("GET", &url).with_session(1);

        let res = client.execute_streaming(
            &opts,
            None,
            |_code, _reason, headers| {
                for (k, _v) in headers {
                    if k.eq_ignore_ascii_case("set-cookie") {
                        received_set_cookie_count += 1;
                    }
                }
            },
            |_data| {},
            |_keep_alive| {},
        );

        assert!(res.is_ok());
        assert_eq!(received_set_cookie_count, 2, "Both Set-Cookie headers must be preserved");

        // Verify jar stored both cookies
        let jar_header = client.cookie_jar.get_cookie_header(1, &parsed_url).expect("cookie header in jar");
        assert!(jar_header.contains("sid=abc123xyz"));
        assert!(jar_header.contains("theme=dark"));

        server_thread.join().unwrap();
    }

    #[test]
    fn test_ipv4_prioritization() {
        use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

        let mut addrs = vec![
            SocketAddr::new(IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)), 80),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 80),
            SocketAddr::new(IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2)), 80),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2)), 80),
        ];

        addrs.sort_by_key(|addr| !addr.is_ipv4());

        assert!(addrs[0].is_ipv4());
        assert!(addrs[1].is_ipv4());
        assert!(addrs[2].is_ipv6());
        assert!(addrs[3].is_ipv6());
    }

    #[test]
    fn test_streaming_transparent_decompression_gzip() {
        use flate2::write::GzEncoder;
        use flate2::Compression;

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind local test server");
        let port = listener.local_addr().unwrap().port();

        let original_body = b"<!DOCTYPE html><html><body><h1>Streaming Decompression Test</h1></body></html>";
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(original_body).unwrap();
        let gzip_body = encoder.finish().unwrap();

        let gzip_body_clone = gzip_body.clone();
        let server_thread = std::thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut buf = [0u8; 1024];
                let _ = stream.read(&mut buf);

                let header = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Encoding: gzip\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    gzip_body_clone.len()
                );
                let _ = stream.write_all(header.as_bytes());
                // Send body in two chunks
                let mid = gzip_body_clone.len() / 2;
                let _ = stream.write_all(&gzip_body_clone[..mid]);
                let _ = stream.write_all(&gzip_body_clone[mid..]);
            }
        });

        let store = Arc::new(BoringSessionStore::in_memory());
        let tls_cfg = Arc::new(BoringTlsConfig::new(TlsFingerprintProfile::Chrome, store).unwrap());
        let mut client = HttpClientEngine::new(tls_cfg);
        let url = format!("http://127.0.0.1:{}/gzip_stream", port);
        let opts = HttpRequestOptions::new("GET", &url);

        let mut received_headers = Vec::new();
        let mut received_body = Vec::new();

        let res = client.execute_streaming(
            &opts,
            None,
            |_code, _reason, headers| {
                received_headers = headers.to_vec();
            },
            |chunk| {
                received_body.extend_from_slice(chunk);
            },
            |_keep_alive| {},
        );

        assert!(res.is_ok());

        // Verify Content-Encoding and Content-Length were stripped
        assert!(!received_headers.iter().any(|(k, _)| k.eq_ignore_ascii_case("content-encoding")));
        assert!(!received_headers.iter().any(|(k, _)| k.eq_ignore_ascii_case("content-length")));

        // Verify body received in on_data_chunk was decompressed
        assert_eq!(received_body, original_body);

        server_thread.join().unwrap();
    }

    #[test]
    fn test_streaming_decompression_disabled_when_flag_false() {
        use flate2::write::GzEncoder;
        use flate2::Compression;

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind local test server");
        let port = listener.local_addr().unwrap().port();

        let original_body = b"Raw binary payload";
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(original_body).unwrap();
        let gzip_body = encoder.finish().unwrap();

        let gzip_body_clone = gzip_body.clone();
        let server_thread = std::thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut buf = [0u8; 1024];
                let _ = stream.read(&mut buf);

                let header = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Encoding: gzip\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    gzip_body_clone.len()
                );
                let _ = stream.write_all(header.as_bytes());
                let _ = stream.write_all(&gzip_body_clone);
            }
        });

        let store = Arc::new(BoringSessionStore::in_memory());
        let tls_cfg = Arc::new(BoringTlsConfig::new(TlsFingerprintProfile::Chrome, store).unwrap());
        let mut client = HttpClientEngine::new(tls_cfg);
        let url = format!("http://127.0.0.1:{}/raw_gzip", port);
        let mut opts = HttpRequestOptions::new("GET", &url);
        opts.transparent_decompression = false;

        let mut received_headers = Vec::new();
        let mut received_body = Vec::new();

        let res = client.execute_streaming(
            &opts,
            None,
            |_code, _reason, headers| {
                received_headers = headers.to_vec();
            },
            |chunk| {
                received_body.extend_from_slice(chunk);
            },
            |_keep_alive| {},
        );

        assert!(res.is_ok());

        // Verify Content-Encoding was preserved
        assert!(received_headers.iter().any(|(k, v)| k.eq_ignore_ascii_case("content-encoding") && v == "gzip"));

        // Verify body received in on_data_chunk is raw gzip bytes
        assert_eq!(received_body, gzip_body);

        server_thread.join().unwrap();
    }

    #[test]
    fn test_http_client_alt_svc_discovery_and_caching() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind local test server");
        let port = listener.local_addr().unwrap().port();

        let server_thread = std::thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut buf = [0u8; 1024];
                let _ = stream.read(&mut buf);

                let response = format!(
                    "HTTP/1.1 200 OK\r\nAlt-Svc: h3=\":443\"; ma=86400; persist=1\r\nContent-Length: 4\r\nConnection: close\r\n\r\nOK!!",
                );
                let _ = stream.write_all(response.as_bytes());
            }
        });

        let store = Arc::new(BoringSessionStore::in_memory());
        let tls_cfg = Arc::new(BoringTlsConfig::new(TlsFingerprintProfile::Chrome, store).unwrap());
        let mut client = HttpClientEngine::new(tls_cfg);
        let url = format!("http://127.0.0.1:{}/alt_svc_test", port);
        let opts = HttpRequestOptions::new("GET", &url);

        let res = client.execute_streaming(
            &opts,
            None,
            |_code, _reason, _headers| {},
            |_chunk| {},
            |_keep_alive| {},
        );

        assert!(res.is_ok());

        // Verify that the registry discovered Alt-Svc
        let h3_target = client.alt_svc_registry.get_h3_target("127.0.0.1", port);
        assert_eq!(h3_target, Some(("127.0.0.1".to_string(), 443)));

        server_thread.join().unwrap();
    }

    #[test]
    fn test_http_client_proxy_tunneling_http_connect() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock proxy");
        let proxy_port = listener.local_addr().unwrap().port();

        let proxy_thread = std::thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut buf = [0u8; 1024];
                let n = stream.read(&mut buf).unwrap();
                let req = String::from_utf8_lossy(&buf[..n]);
                assert!(req.starts_with("CONNECT mock.origin:80 HTTP/1.1"));

                // Send 200 Connection established
                stream.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n").unwrap();

                // Read forwarded HTTP request
                let n = stream.read(&mut buf).unwrap();
                let inner_req = String::from_utf8_lossy(&buf[..n]);
                assert!(inner_req.starts_with("GET /proxied HTTP/1.1"));

                // Return response
                stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\nConnection: close\r\n\r\nPROXIED").unwrap();
            }
        });

        let store = Arc::new(BoringSessionStore::in_memory());
        let tls_cfg = Arc::new(BoringTlsConfig::new(TlsFingerprintProfile::Chrome, store).unwrap());
        let mut client = HttpClientEngine::new(tls_cfg);

        let mut cfg = ProxyConfig::new();
        cfg.http_proxy = Some(ProxyRule {
            scheme: ProxyScheme::Http,
            host: "127.0.0.1".to_string(),
            port: proxy_port,
        });
        client.proxy_config = Some(cfg);

        let url = "http://mock.origin:80/proxied";
        let opts = HttpRequestOptions::new("GET", url);

        let mut received_body = Vec::new();
        let res = client.execute_streaming(
            &opts,
            None,
            |_code, _reason, _headers| {},
            |chunk| {
                received_body.extend_from_slice(chunk);
            },
            |_keep_alive| {},
        );

        assert!(res.is_ok());
        assert_eq!(received_body, b"PROXIED");

        proxy_thread.join().unwrap();
    }

    #[test]
    fn test_http_client_proxy_tunneling_socks5() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock socks5 proxy");
        let proxy_port = listener.local_addr().unwrap().port();

        let proxy_thread = std::thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                // 1. Read greeting [0x05, 0x01, 0x00]
                let mut greeting = [0u8; 3];
                stream.read_exact(&mut greeting).unwrap();
                assert_eq!(greeting, [0x05, 0x01, 0x00]);

                // Send choice [0x05, 0x00] (No Auth)
                stream.write_all(&[0x05, 0x00]).unwrap();

                // 2. Read connect request
                let mut req_header = [0u8; 5];
                stream.read_exact(&mut req_header).unwrap();
                assert_eq!(req_header[0..4], [0x05, 0x01, 0x00, 0x03]);
                let domain_len = req_header[4] as usize;
                let mut domain_buf = vec![0u8; domain_len + 2];
                stream.read_exact(&mut domain_buf).unwrap();
                let domain = String::from_utf8_lossy(&domain_buf[..domain_len]);
                assert_eq!(domain, "mock.socks5.origin");

                // Send success response
                stream.write_all(&[0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 80]).unwrap();

                // 3. Read forwarded HTTP request
                let mut buf = [0u8; 1024];
                let n = stream.read(&mut buf).unwrap();
                let req = String::from_utf8_lossy(&buf[..n]);
                assert!(req.starts_with("GET /socks5_data HTTP/1.1"));

                // Return response
                stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\nConnection: close\r\n\r\nSOCKS5").unwrap();
            }
        });

        let store = Arc::new(BoringSessionStore::in_memory());
        let tls_cfg = Arc::new(BoringTlsConfig::new(TlsFingerprintProfile::Chrome, store).unwrap());
        let mut client = HttpClientEngine::new(tls_cfg);

        let mut cfg = ProxyConfig::new();
        cfg.http_proxy = Some(ProxyRule {
            scheme: ProxyScheme::Socks5,
            host: "127.0.0.1".to_string(),
            port: proxy_port,
        });
        client.proxy_config = Some(cfg);

        let url = "http://mock.socks5.origin:80/socks5_data";
        let opts = HttpRequestOptions::new("GET", url);

        let mut received_body = Vec::new();
        let res = client.execute_streaming(
            &opts,
            None,
            |_code, _reason, _headers| {},
            |chunk| {
                received_body.extend_from_slice(chunk);
            },
            |_keep_alive| {},
        );

        assert!(res.is_ok());
        assert_eq!(received_body, b"SOCKS5");

        proxy_thread.join().unwrap();
    }

    #[test]
    fn test_he3_race_blackholed_udp_triggers_cad_and_demotes_origin() {
        // Bind a UDP socket that never responds (blackholed QUIC)
        let udp_blackhole = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let udp_port = udp_blackhole.local_addr().unwrap().port();

        // Bind and immediately drop a TCP listener to get an unused closed port
        let tcp_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let tcp_port = tcp_listener.local_addr().unwrap().port();
        drop(tcp_listener);

        let store = Arc::new(BoringSessionStore::in_memory());
        let tls_cfg = Arc::new(BoringTlsConfig::new(TlsFingerprintProfile::Chrome, store).unwrap());
        let mut client = HttpClientEngine::new(tls_cfg);
        client.alt_svc_registry.insert(
            "127.0.0.1",
            tcp_port,
            &format!("h3=\":{}\"; ma=86400", udp_port),
        );
        assert!(client.alt_svc_registry.get_h3_target("127.0.0.1", tcp_port).is_some());

        let url = format!("https://127.0.0.1:{}/he3_test", tcp_port);
        let mut opts = HttpRequestOptions::new("GET", &url);
        opts.timeout = Duration::from_secs(2);

        let start = Instant::now();
        let res = client.execute_streaming(&opts, None, |_, _, _| {}, |_| {}, |_| {});
        let elapsed = start.elapsed();

        assert!(res.is_err());
        // Should have waited ~75ms CAD before trying TCP (and failed quickly, well under 2s)
        assert!(elapsed >= Duration::from_millis(65), "elapsed {:?} < 65ms", elapsed);
        assert!(elapsed < Duration::from_millis(1500), "elapsed {:?} >= 1500ms", elapsed);
        // Origin must be demoted after H3 failed/timed out in the race
        assert_eq!(client.alt_svc_registry.get_h3_target("127.0.0.1", tcp_port), None);
    }

    #[test]
    fn test_he3_race_warm_h2_pool_skips_h3_race() {
        use h2_sans_io::{H2Codec, H2Event, H2Header, HpackEncoder};

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();

        let server_thread = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut codec = H2Codec::new();
            let mut encoder = HpackEncoder::new();
            let mut buf = [0u8; 4096];
            loop {
                let n = match stream.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => n,
                };
                if let Ok(events) = codec.process(&buf[..n]) {
                    for ev in events {
                        if let H2Event::Settings { ack: false, .. } = ev {
                            let _ = stream.write_all(&H2Codec::create_settings());
                            let _ = stream.write_all(&H2Codec::create_settings_ack());
                            let _ = stream.flush();
                        } else if let H2Event::Headers { stream_id, .. } = ev {
                            let hdrs = vec![H2Header::new(":status", "200")];
                            let hdr_block = encoder.encode(&hdrs);
                            let _ = stream.write_all(&H2Codec::create_headers_frame(
                                stream_id,
                                &hdr_block,
                                false,
                            ));
                            for f in H2Codec::create_data_frames(stream_id, b"WARM_H2", true, 16384)
                            {
                                let _ = stream.write_all(&f);
                            }
                            let _ = stream.flush();
                            let _ = stream.shutdown(std::net::Shutdown::Write);
                            while stream.read(&mut buf).unwrap_or(0) > 0 {}
                            return;
                        }
                    }
                }
            }
        });

        let store = Arc::new(BoringSessionStore::in_memory());
        let tls_cfg = Arc::new(BoringTlsConfig::new(TlsFingerprintProfile::Chrome, store).unwrap());
        let mut client = HttpClientEngine::new(tls_cfg);

        // Register an active Alt-Svc H3 target on a blackholed port
        client
            .alt_svc_registry
            .insert("127.0.0.1", port, "h3=\":443\"; ma=86400");

        // Pre-populate h2_pool with a warm H2Session for (0, "127.0.0.1", port, true)
        let tcp = TcpStream::connect(format!("127.0.0.1:{}", port)).unwrap();
        let h2_session = SharedH2Session::new(H2Session::new(ActiveStream::Plain(tcp)).unwrap());
        let pool_key = PoolKey::new(0, "127.0.0.1", port, true);
        client.h2_pool.put(pool_key, h2_session);

        let url = format!("https://127.0.0.1:{}/warm_h2", port);
        let opts = HttpRequestOptions::new("GET", &url);
        let mut body = Vec::new();
        let res = client.execute_streaming(
            &opts,
            None,
            |_, _, _| {},
            |chunk| body.extend_from_slice(chunk),
            |_| {},
        );

        assert!(res.is_ok(), "warm H2 failed: {:?}", res);
        assert_eq!(body, b"WARM_H2");
        // H3 race was skipped, so Alt-Svc target must remain healthy (not demoted)
        assert_eq!(
            client.alt_svc_registry.get_h3_target("127.0.0.1", port),
            Some(("127.0.0.1".to_string(), 443))
        );

        drop(client);
        server_thread.join().unwrap();
    }

    #[test]
    fn test_h3_middleware_parity_prepare_options() {
        let jar = CookieJar::new();
        let url = Url::parse("https://example.com/app").unwrap();
        assert!(jar.process_set_cookie(7, &url, "sid=jar_val; Path=/; HttpOnly"));

        let opts = HttpRequestOptions::new("GET", "https://example.com/app")
            .with_session(7)
            .header("Cookie", "dom=dom_val")
            .header("Connection", "keep-alive")
            .header("Host", "example.com")
            .header("Transfer-Encoding", "chunked")
            .header("User-Agent", "Zawra/1.0");

        let prepared = HttpClientEngine::prepare_h3_options(Some(&jar), &opts, &url);
        // Hop-by-hop headers must be stripped
        assert!(!prepared.headers.iter().any(|(k, _)| k.eq_ignore_ascii_case("connection")));
        assert!(!prepared.headers.iter().any(|(k, _)| k.eq_ignore_ascii_case("host")));
        assert!(!prepared.headers.iter().any(|(k, _)| k.eq_ignore_ascii_case("transfer-encoding")));
        // Cookies must be merged from jar + caller
        let cookie_hdr = prepared
            .headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("cookie"))
            .map(|(_, v)| v.as_str())
            .expect("merged cookie header");
        assert!(cookie_hdr.contains("sid=jar_val"));
        assert!(cookie_hdr.contains("dom=dom_val"));
        // Accept-Encoding must be injected
        assert!(prepared.headers.iter().any(|(k, v)| {
            k.eq_ignore_ascii_case("accept-encoding") && v.contains("zstd")
        }));

        // Range requests must NOT inject Accept-Encoding
        let range_opts = HttpRequestOptions::new("GET", "https://example.com/video.mp4")
            .header("Range", "bytes=0-1023");
        let prepared_range = HttpClientEngine::prepare_h3_options(Some(&jar), &range_opts, &url);
        assert!(!prepared_range
            .headers
            .iter()
            .any(|(k, _)| k.eq_ignore_ascii_case("accept-encoding")));
    }

    #[test]
    fn test_http_client_engine_hoists_shared_quic_and_boring_tls() {
        let store = Arc::new(BoringSessionStore::in_memory());
        let tls_cfg = Arc::new(BoringTlsConfig::new(TlsFingerprintProfile::Chrome, store).unwrap());
        let mut client = HttpClientEngine::new(tls_cfg);
        assert_eq!(client.boring_tls().profile, TlsFingerprintProfile::Chrome);
        assert!(Arc::strong_count(client.boring_tls()) >= 1);
        client
            .set_tls_profile(TlsFingerprintProfile::Firefox)
            .expect("switch to Firefox profile");
        assert_eq!(client.boring_tls().profile, TlsFingerprintProfile::Firefox);
    }

    #[test]
    fn test_manage_cookies_false_bypasses_cookie_jar_and_forwards_caller_cookies() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock server");
        let port = listener.local_addr().unwrap().port();

        let (tx, rx) = std::sync::mpsc::channel::<String>();
        let server_thread = std::thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut buf = [0u8; 2048];
                let n = stream.read(&mut buf).unwrap_or(0);
                let _ = tx.send(String::from_utf8_lossy(&buf[..n]).to_string());
                let response = "HTTP/1.1 200 OK\r\nSet-Cookie: server_cookie=abc; Path=/\r\nContent-Length: 2\r\n\r\nok";
                let _ = stream.write_all(response.as_bytes());
            }
        });

        let store = Arc::new(BoringSessionStore::in_memory());
        let tls_cfg = Arc::new(BoringTlsConfig::new(TlsFingerprintProfile::Chrome, store).unwrap());
        let mut client = HttpClientEngine::new(tls_cfg);
        client.manage_cookies = false;

        let url = format!("http://127.0.0.1:{}/test", port);
        let parsed = Url::parse(&url).unwrap();
        assert!(client.cookie_jar.process_set_cookie(1, &parsed, "jar_only=should_not_send; Path=/"));

        let opts = HttpRequestOptions::new("GET", &url)
            .with_session(1)
            .header("Cookie", "webkit_cookie=from_webkit");

        let mut emitted_set_cookie = false;
        let _ = client
            .execute_streaming(
                &opts,
                None,
                |_status, _reason, headers| {
                    if headers.iter().any(|(k, v)| k.eq_ignore_ascii_case("set-cookie") && v.contains("server_cookie=abc")) {
                        emitted_set_cookie = true;
                    }
                },
                |_chunk| {},
                |_ka| {},
            )
            .expect("request succeeds");
        let _ = server_thread.join();

        let raw_req = rx.recv().expect("received request");
        assert!(raw_req.contains("Cookie: webkit_cookie=from_webkit"), "expected caller Cookie untouched, got: {}", raw_req);
        assert!(!raw_req.contains("jar_only=should_not_send"), "jar cookie must not be merged when manage_cookies=false");
        assert!(emitted_set_cookie, "Set-Cookie must still be emitted to on_headers");

        let jar_after = client.cookie_jar.get_cookie_header(1, &parsed).unwrap_or_default();
        assert!(!jar_after.contains("server_cookie=abc"), "Set-Cookie must not be stored in z-net CookieJar when manage_cookies=false");
    }
}
