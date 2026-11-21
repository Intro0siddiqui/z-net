use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::time::Duration;

use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, StreamOwned};
use url::Url;

use super::cookie_jar::CookieJar;
use super::h1::{Http1FeedResult, Http1RequestBuilder, Http1ResponseParser};
use super::pool::{ConnectionPool, PoolKey};
use crate::protocols::compression::decompress_payload;
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
    Tls(Box<StreamOwned<ClientConnection, TcpStream>>),
}

impl Read for ActiveStream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Self::Plain(s) => s.read(buf),
            Self::Tls(s) => s.read(buf),
        }
    }
}

impl Write for ActiveStream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self {
            Self::Plain(s) => s.write(buf),
            Self::Tls(s) => s.write(buf),
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            Self::Plain(s) => s.flush(),
            Self::Tls(s) => s.flush(),
        }
    }
}

/// Standalone HTTP client engine orchestrating connections, pooling, serialization, cookies, and streaming.
pub struct HttpClientEngine {
    tls_config: Arc<ClientConfig>,
    pool: ConnectionPool<ActiveStream>,
    pub cookie_jar: Arc<CookieJar>,
}

impl HttpClientEngine {
    pub fn new(tls_config: Arc<ClientConfig>) -> Self {
        Self {
            tls_config,
            pool: ConnectionPool::new(6, Duration::from_secs(60)),
            cookie_jar: Arc::new(CookieJar::new()),
        }
    }

    /// Clear pooled connections and cookies for a specific session.
    pub fn clear_session(&mut self, session_id: u64) {
        self.pool.clear_session(session_id);
        self.cookie_jar.clear_session(session_id);
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

        let pool_key = PoolKey::new(options.session_id, &host, port, is_tls);

        // 1. Check connection pool or establish new connection
        let mut stream = if let Some(pooled) = self.pool.get(&pool_key) {
            pooled.socket
        } else {
            let addr_str = format!("{}:{}", host, port);
            let mut resolved_stream = None;
            let addrs = addr_str.to_socket_addrs()
                .map_err(|e| format!("DNS resolution failed for {}: {}", addr_str, e))?;

            for addr in addrs {
                if let Ok(s) = TcpStream::connect_timeout(&addr, options.timeout) {
                    let _ = s.set_nodelay(true);
                    let _ = s.set_read_timeout(Some(options.timeout));
                    let _ = s.set_write_timeout(Some(options.timeout));
                    resolved_stream = Some(s);
                    break;
                }
            }

            let tcp = resolved_stream.ok_or(format!("Could not connect to {}:{}", host, port))?;

            if is_tls {
                let server_name = ServerName::try_from(host.as_str())
                    .map_err(|e| format!("Invalid TLS server name: {}", e))?
                    .to_owned();

                let tls_conn = ClientConnection::new(self.tls_config.clone(), server_name)
                    .map_err(|e| format!("TLS handshake init failed: {}", e))?;

                ActiveStream::Tls(Box::new(StreamOwned::new(tls_conn, tcp)))
            } else {
                ActiveStream::Plain(tcp)
            }
        };

        // 2. Format Request
        let mut path_and_query = parsed_url.path().to_string();
        if let Some(q) = parsed_url.query() {
            path_and_query.push('?');
            path_and_query.push_str(q);
        }
        if path_and_query.is_empty() {
            path_and_query = "/".to_string();
        }

        let mut req_builder = Http1RequestBuilder::new(&options.method, &path_and_query);
        let mut has_range_header = false;
        let mut has_accept_encoding = false;

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
        stream.write_all(&wire_req)
            .map_err(|e| format!("Failed to send request: {}", e))?;
        stream.flush()
            .map_err(|e| format!("Failed to flush request: {}", e))?;

        // 4. Progressive Read Loop
        let mut parser = Http1ResponseParser::new();
        let mut read_buf = [0u8; 8192];
        let mut headers_dispatched = false;
        let mut can_keep_alive = false;
        let mut is_completed = false;

        while !is_completed {
            if is_cancelled() {
                return Ok(headers_dispatched);
            }

            match stream.read(&mut read_buf) {
                Ok(0) => {
                    // EOF on stream
                    let eof_results = parser.on_eof();
                    for ev in eof_results {
                        if let Http1FeedResult::BodyData(chunk) = ev {
                            if let Some(ring) = body_ring {
                                ring.write_slice(&chunk);
                            }
                            on_data_chunk(&chunk);
                        }
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
                                    if k.eq_ignore_ascii_case("set-cookie") {
                                        self.cookie_jar.process_set_cookie(options.session_id, &parsed_url, v);
                                    }
                                }
                                on_headers(status_code, &reason, &headers);
                                headers_dispatched = true;
                            }
                            Http1FeedResult::BodyData(chunk) => {
                                // Progressive zero-copy write directly to BodyRing
                                if let Some(ring) = body_ring {
                                    ring.write_slice(&chunk);
                                }
                                // Invoke callback with borrowed slice
                                on_data_chunk(&chunk);
                            }
                            Http1FeedResult::Complete { keep_alive } => {
                                can_keep_alive = keep_alive;
                                is_completed = true;
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
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::atomic::{AtomicBool, AtomicU64};

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

        let mut roots = rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let tls_cfg = Arc::new(ClientConfig::builder().with_root_certificates(roots).with_no_client_auth());

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
            _pad3: [0u8; 64],
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

        let mut roots = rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let tls_cfg = Arc::new(ClientConfig::builder().with_root_certificates(roots).with_no_client_auth());

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

        let roots = rustls::RootCertStore::empty();
        let tls_cfg = Arc::new(ClientConfig::builder().with_root_certificates(roots).with_no_client_auth());
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

        let roots = rustls::RootCertStore::empty();
        let tls_cfg = Arc::new(ClientConfig::builder().with_root_certificates(roots).with_no_client_auth());
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

        let roots = rustls::RootCertStore::empty();
        let tls_cfg = Arc::new(ClientConfig::builder().with_root_certificates(roots).with_no_client_auth());
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

        let roots = rustls::RootCertStore::empty();
        let tls_cfg = Arc::new(ClientConfig::builder().with_root_certificates(roots).with_no_client_auth());
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
}
