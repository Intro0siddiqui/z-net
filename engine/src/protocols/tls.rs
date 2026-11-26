//! Browser-grade TLS ClientHello fingerprinting (BoringSSL) and persistent
//! disk-backed session ticket resumption with safe in-memory fallback.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use boring::ssl::{
    HandshakeError, MidHandshakeSslStream, Ssl, SslConnector, SslMethod, SslSession,
    SslSessionCacheMode, SslStream, SslVersion,
};
use boring::x509::X509;
use compio_driver::op::Interest;
use compio_driver::SharedFd;
use rustls::client::{ClientSessionMemoryCache, ClientSessionStore, Resumption};
use rustls::pki_types::ServerName;
use rustls::NamedGroup;
use socket2::Socket as Socket2;

/// Browser TLS fingerprint profile for outgoing TCP/TLS connections.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsFingerprintProfile {
    /// Modern Chromium / Chrome profile: TLS GREASE, extension permutation,
    /// Chrome cipher & sigalg ordering, PQ X25519MLKEM768, ECH GREASE.
    Chrome,
    /// Modern Firefox profile: fixed extension order, Firefox cipher & sigalg
    /// ordering, PQ X25519MLKEM768, ECH GREASE.
    Firefox,
}

impl Default for TlsFingerprintProfile {
    fn default() -> Self {
        Self::Chrome
    }
}

const CHROME_CIPHERS: &str = "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-RSA-AES128-SHA:ECDHE-RSA-AES256-SHA:AES128-GCM-SHA256:AES256-GCM-SHA384:AES128-SHA:AES256-SHA";
const CHROME_SIGALGS: &str = "ecdsa_secp256r1_sha256:rsa_pss_rsae_sha256:rsa_pkcs1_sha256:ecdsa_secp384r1_sha384:rsa_pss_rsae_sha384:rsa_pkcs1_sha384:rsa_pss_rsae_sha512:rsa_pkcs1_sha512";

const FIREFOX_CIPHERS: &str = "TLS_AES_128_GCM_SHA256:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_256_GCM_SHA384:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES128-SHA:ECDHE-RSA-AES256-SHA:AES128-GCM-SHA256:AES256-GCM-SHA384:AES128-SHA:AES256-SHA";
const FIREFOX_SIGALGS: &str = "ecdsa_secp256r1_sha256:ecdsa_secp384r1_sha384:ecdsa_secp521r1_sha512:rsa_pss_rsae_sha256:rsa_pss_rsae_sha384:rsa_pss_rsae_sha512:rsa_pkcs1_sha256:rsa_pkcs1_sha384:rsa_pkcs1_sha512";

/// ALPN wire format for `h2` + `http/1.1`.
const ALPN_H2_HTTP11: &[u8] = b"\x02h2\x08http/1.1";

const DEFAULT_MAX_SESSION_ENTRIES: usize = 512;

/// Resolve default cache file path for persistent TLS session state.
pub fn default_session_store_path(filename: &str) -> Option<PathBuf> {
    if let Ok(xdg) = std::env::var("XDG_CACHE_HOME") {
        if !xdg.is_empty() {
            return Some(PathBuf::from(xdg).join("z-net").join(filename));
        }
    }
    if let Ok(home) = std::env::var("HOME") {
        if !home.is_empty() {
            return Some(PathBuf::from(home).join(".cache").join("z-net").join(filename));
        }
    }
    None
}

/// Atomic file write helper with 0600 permissions on Unix.
/// Failures are swallowed by callers to guarantee safe in-memory fallback.
fn atomic_write_private(path: &Path, content: &[u8]) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let tmp_path = path.with_extension("tmp");
    {
        let mut f = std::fs::File::create(&tmp_path)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = f.set_permissions(std::fs::Permissions::from_mode(0o600));
        }
        f.write_all(content)?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp_path, path)?;
    Ok(())
}

/// Persistent disk-backed BoringSSL session ticket store with safe in-memory fallback.
#[derive(Debug)]
pub struct BoringSessionStore {
    inner: Mutex<HashMap<String, Vec<u8>>>,
    path: Option<PathBuf>,
    max_entries: usize,
}

impl BoringSessionStore {
    /// Open or initialize a disk-backed store at `path`. If `path` is `None` or
    /// unreadable/unwritable, safely falls back to in-memory operation.
    pub fn with_path(path: Option<PathBuf>) -> Self {
        let mut map = HashMap::new();
        if let Some(ref p) = path {
            if let Ok(text) = std::fs::read_to_string(p) {
                use base64::Engine;
                for line in text.lines() {
                    if let Some((host, b64)) = line.split_once('\t') {
                        if let Ok(der) = base64::engine::general_purpose::STANDARD.decode(b64.trim()) {
                            if !der.is_empty() && map.len() < DEFAULT_MAX_SESSION_ENTRIES {
                                map.insert(host.to_string(), der);
                            }
                        }
                    }
                }
            }
        }
        Self {
            inner: Mutex::new(map),
            path,
            max_entries: DEFAULT_MAX_SESSION_ENTRIES,
        }
    }

    pub fn new_default() -> Self {
        Self::with_path(default_session_store_path("boring_sessions.db"))
    }

    pub fn in_memory() -> Self {
        Self::with_path(None)
    }

    pub fn get(&self, host: &str) -> Option<Vec<u8>> {
        let key = host.to_ascii_lowercase();
        self.inner.lock().ok()?.get(&key).cloned()
    }

    pub fn insert(&self, host: &str, der: Vec<u8>) {
        if der.is_empty() {
            return;
        }
        let key = host.to_ascii_lowercase();
        let snapshot = {
            let mut guard = match self.inner.lock() {
                Ok(g) => g,
                Err(_) => return,
            };
            if guard.len() >= self.max_entries && !guard.contains_key(&key) {
                if let Some(first_key) = guard.keys().next().cloned() {
                    guard.remove(&first_key);
                }
            }
            guard.insert(key, der);
            if self.path.is_some() {
                Some(guard.clone())
            } else {
                None
            }
        };

        if let (Some(ref p), Some(map)) = (&self.path, snapshot) {
            use base64::Engine;
            let mut out = String::new();
            for (k, v) in map {
                let encoded = base64::engine::general_purpose::STANDARD.encode(&v);
                out.push_str(&k);
                out.push('\t');
                out.push_str(&encoded);
                out.push('\n');
            }
            // Safe fallback: ignore disk write errors, in-memory cache still works
            let _ = atomic_write_private(p, out.as_bytes());
        }
    }

    pub fn len(&self) -> usize {
        self.inner.lock().map(|g| g.len()).unwrap_or(0)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Persistent disk-backed `rustls::client::ClientSessionStore` with safe in-memory fallback.
///
/// Wraps `ClientSessionMemoryCache` for TLS 1.2/1.3 tickets and persists key-exchange
/// group hints (`NamedGroup` per `ServerName`) to disk so subsequent restarts avoid
/// HelloRetryRequest round-trips.
#[derive(Debug)]
pub struct PersistentRustlsSessionStore {
    memory: ClientSessionMemoryCache,
    kx_hints: Mutex<HashMap<String, u16>>,
    path: Option<PathBuf>,
    max_entries: usize,
}

impl PersistentRustlsSessionStore {
    pub fn with_path(path: Option<PathBuf>, capacity: usize) -> Self {
        let mut kx_hints = HashMap::new();
        if let Some(ref p) = path {
            if let Ok(text) = std::fs::read_to_string(p) {
                for line in text.lines() {
                    if let Some((host, group_str)) = line.split_once('\t') {
                        if let Ok(code) = group_str.trim().parse::<u16>() {
                            if kx_hints.len() < capacity {
                                kx_hints.insert(host.to_string(), code);
                            }
                        }
                    }
                }
            }
        }
        Self {
            memory: ClientSessionMemoryCache::new(capacity),
            kx_hints: Mutex::new(kx_hints),
            path,
            max_entries: capacity,
        }
    }

    pub fn new_default(capacity: usize) -> Self {
        Self::with_path(default_session_store_path("rustls_sessions.db"), capacity)
    }

    pub fn into_resumption(self: Arc<Self>) -> Resumption {
        Resumption::store(self)
    }

    fn persist_kx_hints(&self, map: &HashMap<String, u16>) {
        if let Some(ref p) = self.path {
            let mut out = String::new();
            for (k, v) in map {
                out.push_str(k);
                out.push('\t');
                out.push_str(&v.to_string());
                out.push('\n');
            }
            let _ = atomic_write_private(p, out.as_bytes());
        }
    }
}

impl ClientSessionStore for PersistentRustlsSessionStore {
    fn set_kx_hint(&self, server_name: ServerName<'static>, group: NamedGroup) {
        let key = server_name.to_str().to_ascii_lowercase();
        let code = u16::from(group);
        self.memory.set_kx_hint(server_name, group);

        let snapshot = {
            let mut guard = match self.kx_hints.lock() {
                Ok(g) => g,
                Err(_) => return,
            };
            if guard.len() >= self.max_entries && !guard.contains_key(&key) {
                if let Some(first_key) = guard.keys().next().cloned() {
                    guard.remove(&first_key);
                }
            }
            guard.insert(key, code);
            if self.path.is_some() {
                Some(guard.clone())
            } else {
                None
            }
        };
        if let Some(map) = snapshot {
            self.persist_kx_hints(&map);
        }
    }

    fn kx_hint(&self, server_name: &ServerName<'_>) -> Option<NamedGroup> {
        if let Some(g) = self.memory.kx_hint(server_name) {
            return Some(g);
        }
        let key = server_name.to_str().to_ascii_lowercase();
        let code = self.kx_hints.lock().ok()?.get(&key).copied()?;
        Some(NamedGroup::from(code))
    }

    fn set_tls12_session(
        &self,
        server_name: ServerName<'static>,
        value: rustls::client::Tls12ClientSessionValue,
    ) {
        self.memory.set_tls12_session(server_name, value);
    }

    fn tls12_session(
        &self,
        server_name: &ServerName<'_>,
    ) -> Option<rustls::client::Tls12ClientSessionValue> {
        self.memory.tls12_session(server_name)
    }

    fn remove_tls12_session(&self, server_name: &ServerName<'static>) {
        self.memory.remove_tls12_session(server_name);
    }

    fn insert_tls13_ticket(
        &self,
        server_name: ServerName<'static>,
        value: rustls::client::Tls13ClientSessionValue,
    ) {
        self.memory.insert_tls13_ticket(server_name, value);
    }

    fn take_tls13_ticket(
        &self,
        server_name: &ServerName<'static>,
    ) -> Option<rustls::client::Tls13ClientSessionValue> {
        self.memory.take_tls13_ticket(server_name)
    }
}

/// Shared BoringSSL client connector configured with browser-grade ClientHello
/// fingerprinting (GREASE, extension permutation, cipher/sigalg order, PQ
/// X25519MLKEM768 when supported by BoringSSL, ECH GREASE, and persistent resumption).
pub struct BoringTlsConfig {
    connector: SslConnector,
    pub profile: TlsFingerprintProfile,
    pub pq_enabled: bool,
    pub ech_grease_enabled: bool,
    pub session_store: Arc<BoringSessionStore>,
}

impl BoringTlsConfig {
    pub fn new(
        profile: TlsFingerprintProfile,
        session_store: Arc<BoringSessionStore>,
    ) -> Result<Self, String> {
        let mut builder = SslConnector::builder(SslMethod::tls())
            .map_err(|e| format!("BoringSSL connector builder failed: {}", e))?;

        // Load system trust anchors
        let _ = builder.set_default_verify_paths();
        if let Ok(pem) = std::fs::read("/etc/ssl/certs/ca-certificates.crt") {
            if let Ok(certs) = X509::stack_from_pem(&pem) {
                let store = builder.cert_store_mut();
                for cert in certs {
                    let _ = store.add_cert(cert);
                }
            }
        }

        builder
            .set_min_proto_version(Some(SslVersion::TLS1_2))
            .map_err(|e| format!("BoringSSL min proto failed: {}", e))?;
        builder
            .set_max_proto_version(Some(SslVersion::TLS1_3))
            .map_err(|e| format!("BoringSSL max proto failed: {}", e))?;

        builder
            .set_alpn_protos(ALPN_H2_HTTP11)
            .map_err(|e| format!("BoringSSL ALPN failed: {}", e))?;

        builder.enable_ocsp_stapling();
        builder.enable_signed_cert_timestamps();

        let (ciphers, sigalgs, pq_curves, fallback_curves, grease, permute) = match profile {
            TlsFingerprintProfile::Chrome => (
                CHROME_CIPHERS,
                CHROME_SIGALGS,
                &[
                    "X25519MLKEM768:X25519:P-256:P-384",
                    "X25519Kyber768Draft00:X25519:P-256:P-384",
                ][..],
                "X25519:P-256:P-384",
                true,
                true,
            ),
            TlsFingerprintProfile::Firefox => (
                FIREFOX_CIPHERS,
                FIREFOX_SIGALGS,
                &[
                    "X25519MLKEM768:X25519:P-256:P-384:P-521",
                    "X25519Kyber768Draft00:X25519:P-256:P-384:P-521",
                ][..],
                "X25519:P-256:P-384:P-521",
                false,
                false,
            ),
        };

        builder.set_grease_enabled(grease);
        builder.set_permute_extensions(permute);

        builder
            .set_cipher_list(ciphers)
            .map_err(|e| format!("BoringSSL cipher list failed: {}", e))?;
        builder
            .set_sigalgs_list(sigalgs)
            .map_err(|e| format!("BoringSSL sigalgs failed: {}", e))?;

        let mut pq_enabled = false;
        for curves in pq_curves {
            if builder.set_curves_list(curves).is_ok() {
                pq_enabled = true;
                break;
            }
        }
        if !pq_enabled {
            builder
                .set_curves_list(fallback_curves)
                .map_err(|e| format!("BoringSSL curves list failed: {}", e))?;
        }

        // Enable client session caching and persist new tickets to disk-backed store
        builder.set_session_cache_mode(SslSessionCacheMode::CLIENT);
        let store_cb = session_store.clone();
        builder.set_new_session_callback(move |ssl, session| {
            if let Some(host) = ssl.servername(boring::ssl::NameType::HOST_NAME) {
                if let Ok(der) = session.to_der() {
                    store_cb.insert(host, der);
                }
            }
        });

        Ok(Self {
            connector: builder.build(),
            profile,
            pq_enabled,
            ech_grease_enabled: true,
            session_store,
        })
    }

    /// Build a configured `Ssl` instance for `host` with ECH GREASE (or explicit
    /// ECHConfigList) and cached session ticket restoration.
    pub fn build_ssl(&self, host: &str, ech_config_list: Option<&[u8]>) -> Result<Ssl, String> {
        let cfg = self
            .connector
            .configure()
            .map_err(|e| format!("BoringSSL configure failed: {}", e))?;

        let mut ssl = cfg
            .into_ssl(host)
            .map_err(|e| format!("BoringSSL into_ssl failed: {}", e))?;

        if let Some(ech) = ech_config_list {
            let _ = ssl.set_ech_config_list(ech);
        } else if self.ech_grease_enabled {
            ssl.set_enable_ech_grease(true);
        }

        if let Some(der) = self.session_store.get(host) {
            if let Ok(sess) = SslSession::from_der(&der) {
                let _ = unsafe { ssl.set_session(&sess) };
            }
        }

        Ok(ssl)
    }

    /// Perform a blocking BoringSSL handshake over `TcpStream`.
    pub fn connect_blocking(
        &self,
        host: &str,
        stream: TcpStream,
        ech_config_list: Option<&[u8]>,
    ) -> Result<SslStream<TcpStream>, String> {
        let ssl = self.build_ssl(host, ech_config_list)?;
        ssl.connect(stream)
            .map_err(|e| format!("BoringSSL handshake failed: {}", e))
    }

    /// Perform a blocking BoringSSL handshake over `BoringIo`.
    pub fn connect_blocking_io(
        &self,
        host: &str,
        io: BoringIo,
        ech_config_list: Option<&[u8]>,
    ) -> Result<SslStream<BoringIo>, String> {
        let ssl = self.build_ssl(host, ech_config_list)?;
        ssl.connect(io)
            .map_err(|e| format!("BoringSSL handshake failed: {}", e))
    }

    /// Initiate a non-blocking BoringSSL handshake over `S` for `compio-driver::Proactor`.
    pub fn start_nonblocking<S: Read + Write>(
        &self,
        host: &str,
        sock: S,
        ech_config_list: Option<&[u8]>,
    ) -> Result<NonBlockingHandshakeStep<S>, String> {
        let ssl = self.build_ssl(host, ech_config_list)?;
        let mid = ssl.setup_connect(sock);
        step_boring_handshake(mid)
    }
}

/// Outcome of driving one step of a non-blocking BoringSSL handshake.
pub enum NonBlockingHandshakeStep<S> {
    Complete(SslStream<S>),
    Pending {
        mid: MidHandshakeSslStream<S>,
        interest: Interest,
    },
}

/// Drive a non-blocking `MidHandshakeSslStream<S>` until it completes or needs I/O readiness.
pub fn step_boring_handshake<S: Read + Write>(
    mid: MidHandshakeSslStream<S>,
) -> Result<NonBlockingHandshakeStep<S>, String> {
    match mid.handshake() {
        Ok(stream) => Ok(NonBlockingHandshakeStep::Complete(stream)),
        Err(HandshakeError::WouldBlock(mid)) => {
            let interest = match mid.error().code() {
                boring::ssl::ErrorCode::WANT_WRITE => Interest::Writable,
                _ => Interest::Readable,
            };
            Ok(NonBlockingHandshakeStep::Pending { mid, interest })
        }
        Err(HandshakeError::Failure(mid)) => {
            Err(format!("BoringSSL handshake failed: {}", mid.error()))
        }
        Err(HandshakeError::SetupFailure(e)) => {
            Err(format!("BoringSSL setup failed: {}", e))
        }
    }
}

/// Unified transport I/O wrapper for BoringSSL streams supporting both blocking
/// `TcpStream` and `compio-driver::SharedFd<Socket2>` from HEv3 racing.
pub enum BoringIo {
    Tcp(TcpStream),
    SharedSock(SharedFd<Socket2>),
}

impl BoringIo {
    pub fn configure_blocking(&self, timeout: std::time::Duration) {
        match self {
            Self::Tcp(s) => {
                let _ = s.set_nonblocking(false);
                let _ = s.set_nodelay(true);
                let _ = s.set_read_timeout(Some(timeout));
                let _ = s.set_write_timeout(Some(timeout));
            }
            Self::SharedSock(s) => {
                let _ = s.set_nonblocking(false);
                let _ = s.set_tcp_nodelay(true);
                let _ = s.set_read_timeout(Some(timeout));
                let _ = s.set_write_timeout(Some(timeout));
            }
        }
    }
}

impl Read for BoringIo {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Self::Tcp(s) => s.read(buf),
            Self::SharedSock(s) => (&**s).read(buf),
        }
    }
}

impl Write for BoringIo {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self {
            Self::Tcp(s) => s.write(buf),
            Self::SharedSock(s) => (&**s).write(buf),
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            Self::Tcp(s) => s.flush(),
            Self::SharedSock(s) => (&**s).flush(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    #[test]
    fn test_boring_chrome_and_firefox_profiles_init() {
        let store = Arc::new(BoringSessionStore::in_memory());
        let chrome = BoringTlsConfig::new(TlsFingerprintProfile::Chrome, store.clone())
            .expect("Chrome profile should initialize");
        assert_eq!(chrome.profile, TlsFingerprintProfile::Chrome);
        assert!(chrome.ech_grease_enabled);

        let firefox = BoringTlsConfig::new(TlsFingerprintProfile::Firefox, store)
            .expect("Firefox profile should initialize");
        assert_eq!(firefox.profile, TlsFingerprintProfile::Firefox);
        assert!(firefox.ech_grease_enabled);
    }

    #[test]
    fn test_boring_client_hello_contains_grease_and_alpn() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
        let addr = listener.local_addr().unwrap();

        let server = std::thread::spawn(move || {
            let (mut conn, _) = listener.accept().expect("accept");
            let mut buf = [0u8; 4096];
            let n = conn.read(&mut buf).unwrap_or(0);
            buf[..n].to_vec()
        });

        let store = Arc::new(BoringSessionStore::in_memory());
        let cfg = BoringTlsConfig::new(TlsFingerprintProfile::Chrome, store)
            .expect("Chrome BoringTlsConfig");
        let tcp = TcpStream::connect(addr).expect("connect loopback");
        // Handshake will fail once server closes, after ClientHello is sent
        let _ = cfg.connect_blocking("example.com", tcp, None);

        let client_hello = server.join().expect("server join");
        assert!(client_hello.len() > 64, "ClientHello too short: {}", client_hello.len());
        // TLS record header: 0x16 (Handshake), 0x03 0x01 (TLS 1.0 record version), ...
        assert_eq!(client_hello[0], 0x16);
        // Handshake type: 0x01 (ClientHello)
        assert_eq!(client_hello[5], 0x01);

        // Verify ALPN "h2" and "http/1.1" are present in the ClientHello
        assert!(
            client_hello.windows(2).any(|w| w == b"h2"),
            "ClientHello missing h2 ALPN"
        );
        assert!(
            client_hello.windows(8).any(|w| w == b"http/1.1"),
            "ClientHello missing http/1.1 ALPN"
        );

        // Verify at least one RFC 8701 GREASE 2-byte value (0x?A 0x?A) appears in ClientHello
        let has_grease = client_hello
            .windows(2)
            .any(|w| w[0] == w[1] && (w[0] & 0x0F) == 0x0A);
        assert!(has_grease, "Chrome ClientHello must include TLS GREASE values");
    }

    #[test]
    fn test_persistent_boring_session_store_disk_roundtrip_and_fallback() {
        let dir = std::env::temp_dir().join(format!("znet_test_sessions_{}", std::process::id()));
        let path = dir.join("boring_sessions.db");
        let _ = std::fs::remove_dir_all(&dir);

        {
            let store = BoringSessionStore::with_path(Some(path.clone()));
            store.insert("Example.COM", vec![0x30, 0x82, 0x01, 0x02]);
            assert_eq!(store.get("example.com"), Some(vec![0x30, 0x82, 0x01, 0x02]));
        }

        // Reload from disk
        {
            let reloaded = BoringSessionStore::with_path(Some(path.clone()));
            assert_eq!(
                reloaded.get("example.com"),
                Some(vec![0x30, 0x82, 0x01, 0x02])
            );
        }
        let _ = std::fs::remove_dir_all(&dir);

        // Unwritable path must safely fall back to in-memory without panicking
        let bad_path = PathBuf::from("/proc/nonexistent_znet_dir/sessions.db");
        let fallback = BoringSessionStore::with_path(Some(bad_path));
        fallback.insert("fallback.test", vec![1, 2, 3, 4]);
        assert_eq!(fallback.get("fallback.test"), Some(vec![1, 2, 3, 4]));
    }

    #[test]
    fn test_persistent_rustls_session_store_kx_hint_roundtrip_and_fallback() {
        let dir = std::env::temp_dir().join(format!("znet_test_rustls_{}", std::process::id()));
        let path = dir.join("rustls_sessions.db");
        let _ = std::fs::remove_dir_all(&dir);

        let sni = ServerName::try_from("quic.example.com".to_string()).unwrap();
        {
            let store = PersistentRustlsSessionStore::with_path(Some(path.clone()), 64);
            store.set_kx_hint(sni.clone(), NamedGroup::X25519);
            assert_eq!(store.kx_hint(&sni), Some(NamedGroup::X25519));
        }
        {
            let reloaded = PersistentRustlsSessionStore::with_path(Some(path.clone()), 64);
            assert_eq!(reloaded.kx_hint(&sni), Some(NamedGroup::X25519));
        }
        let _ = std::fs::remove_dir_all(&dir);

        let bad_store = PersistentRustlsSessionStore::with_path(
            Some(PathBuf::from("/proc/nonexistent_znet_dir/rustls.db")),
            64,
        );
        bad_store.set_kx_hint(sni.clone(), NamedGroup::secp256r1);
        assert_eq!(bad_store.kx_hint(&sni), Some(NamedGroup::secp256r1));
    }
}
