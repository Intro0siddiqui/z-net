use std::collections::HashMap;
use std::io::{Read, Write};
use std::sync::atomic::Ordering;
use bytes::Bytes;
use http::{HeaderMap, HeaderName, HeaderValue, Method, Request, Uri};
use rustls::ClientConnection;

use crate::protocols::compression::StreamDecompressor;
use crate::protocols::http::client::HttpRequestOptions;
use crate::BodyRingDescriptor;

/// Formats and prepares an HTTP/2 request with pseudo-headers.
pub struct Http2RequestBuilder {
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Option<Bytes>,
}

impl Http2RequestBuilder {
    pub fn new(method_str: &str, uri_str: &str) -> Result<Self, String> {
        let method = Method::from_bytes(method_str.as_bytes())
            .map_err(|e| format!("Invalid HTTP method: {}", e))?;
        let uri = uri_str.parse::<Uri>()
            .map_err(|e| format!("Invalid URI: {}", e))?;

        Ok(Self {
            method,
            uri,
            headers: HeaderMap::new(),
            body: None,
        })
    }

    pub fn header(mut self, name: &str, value: &str) -> Result<Self, String> {
        let h_name = HeaderName::from_bytes(name.as_bytes())
            .map_err(|e| format!("Invalid header name: {}", e))?;
        let h_val = HeaderValue::from_str(value)
            .map_err(|e| format!("Invalid header value: {}", e))?;
        self.headers.insert(h_name, h_val);
        Ok(self)
    }

    pub fn body(mut self, body: Bytes) -> Self {
        self.body = Some(body);
        self
    }

    /// Build the standard `http::Request` containing pseudo-headers (:method, :scheme, :authority, :path).
    pub fn build(mut self) -> Result<(Request<()>, Option<Bytes>), String> {
        let mut builder = Request::builder()
            .method(self.method)
            .uri(self.uri);

        if let Some(headers_mut) = builder.headers_mut() {
            for (k, v) in self.headers.drain() {
                if let Some(name) = k {
                    headers_mut.insert(name, v);
                }
            }
        }

        let request = builder.body(()).map_err(|e| format!("Failed to build request: {}", e))?;
        Ok((request, self.body))
    }
}

/// Parsed HTTP/2 response metadata.
#[derive(Debug, PartialEq, Clone)]
pub struct Http2ResponseHeader {
    pub status: u16,
    pub headers: HashMap<String, String>,
}

impl Http2ResponseHeader {
    pub fn from_header_map(status_code: u16, header_map: &HeaderMap) -> Self {
        let mut headers = HashMap::with_capacity(header_map.len());
        for (key, val) in header_map.iter() {
            let key_str = key.as_str().to_string();
            let val_str = String::from_utf8_lossy(val.as_bytes()).to_string();
            headers.insert(key_str, val_str);
        }

        Self {
            status: status_code,
            headers,
        }
    }
}

struct TokioReader<'a>(&'a tokio::net::TcpStream);

impl<'a> Read for TokioReader<'a> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.0.try_read(buf)
    }
}

struct TokioWriter<'a>(&'a tokio::net::TcpStream);

impl<'a> Write for TokioWriter<'a> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.try_write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Asynchronous TLS stream adapter wrapping a `rustls::ClientConnection` and `tokio::net::TcpStream`.
pub struct AsyncTlsStream {
    pub tls: ClientConnection,
    pub io: tokio::net::TcpStream,
}

impl AsyncTlsStream {
    pub fn new(tls: ClientConnection, io: tokio::net::TcpStream) -> Self {
        Self { tls, io }
    }
}

impl tokio::io::AsyncRead for AsyncTlsStream {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let this = self.as_mut().get_mut();

        loop {
            let unfilled = buf.initialize_unfilled();
            if !unfilled.is_empty() {
                match this.tls.reader().read(unfilled) {
                    Ok(n) if n > 0 => {
                        buf.advance(n);
                        return std::task::Poll::Ready(Ok(()));
                    }
                    Ok(_) => {}
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                    Err(e) => return std::task::Poll::Ready(Err(e)),
                }
            }

            match this.io.poll_read_ready(cx) {
                std::task::Poll::Ready(Ok(())) => {}
                std::task::Poll::Ready(Err(e)) => return std::task::Poll::Ready(Err(e)),
                std::task::Poll::Pending => return std::task::Poll::Pending,
            }

            match this.tls.read_tls(&mut TokioReader(&this.io)) {
                Ok(0) => return std::task::Poll::Ready(Ok(())),
                Ok(_) => {
                    if let Err(e) = this.tls.process_new_packets() {
                        return std::task::Poll::Ready(Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            e,
                        )));
                    }
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    return std::task::Poll::Pending;
                }
                Err(e) => return std::task::Poll::Ready(Err(e)),
            }
        }
    }
}

impl tokio::io::AsyncWrite for AsyncTlsStream {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        let this = self.as_mut().get_mut();

        while this.tls.wants_write() {
            match this.io.poll_write_ready(cx) {
                std::task::Poll::Ready(Ok(())) => {}
                std::task::Poll::Ready(Err(e)) => return std::task::Poll::Ready(Err(e)),
                std::task::Poll::Pending => return std::task::Poll::Pending,
            }

            match this.tls.write_tls(&mut TokioWriter(&this.io)) {
                Ok(0) => break,
                Ok(_) => {}
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    return std::task::Poll::Pending;
                }
                Err(e) => return std::task::Poll::Ready(Err(e)),
            }
        }

        let n = this.tls.writer().write(buf)?;

        while this.tls.wants_write() {
            match this.io.poll_write_ready(cx) {
                std::task::Poll::Ready(Ok(())) => {}
                std::task::Poll::Ready(Err(e)) => return std::task::Poll::Ready(Err(e)),
                std::task::Poll::Pending => break,
            }

            match this.tls.write_tls(&mut TokioWriter(&this.io)) {
                Ok(0) => break,
                Ok(_) => {}
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(e) => return std::task::Poll::Ready(Err(e)),
            }
        }

        std::task::Poll::Ready(Ok(n))
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let this = self.as_mut().get_mut();
        while this.tls.wants_write() {
            match this.io.poll_write_ready(cx) {
                std::task::Poll::Ready(Ok(())) => {}
                std::task::Poll::Ready(Err(e)) => return std::task::Poll::Ready(Err(e)),
                std::task::Poll::Pending => return std::task::Poll::Pending,
            }

            match this.tls.write_tls(&mut TokioWriter(&this.io)) {
                Ok(0) => break,
                Ok(_) => {}
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    return std::task::Poll::Pending;
                }
                Err(e) => return std::task::Poll::Ready(Err(e)),
            }
        }
        std::task::Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        self.poll_flush(cx)
    }
}

pub struct Http2Client;

impl Http2Client {
    /// Execute an HTTP/2 request with progressive streaming over an async transport.
    pub fn execute_streaming<S, H, D, C, K>(
        stream: S,
        options: &HttpRequestOptions,
        body_ring: Option<&BodyRingDescriptor>,
        mut on_headers: H,
        mut on_data_chunk: D,
        mut on_complete: C,
        mut is_cancelled: K,
    ) -> Result<bool, String>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
        H: FnMut(u16, &str, &[(String, String)]),
        D: FnMut(&[u8]),
        C: FnMut(bool),
        K: FnMut() -> bool,
    {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| format!("Failed to create tokio runtime for h2: {}", e))?;

        let has_range_header = options.headers.iter().any(|(k, _)| k.eq_ignore_ascii_case("range"));
        let has_accept_encoding = options.headers.iter().any(|(k, _)| k.eq_ignore_ascii_case("accept-encoding"));

        let mut req_builder = Http2RequestBuilder::new(&options.method, &options.url)?;
        for (k, v) in &options.headers {
            req_builder = req_builder.header(k, v)?;
        }
        if options.transparent_decompression && !has_range_header && !has_accept_encoding {
            req_builder = req_builder.header("accept-encoding", "gzip, deflate, br, zstd")?;
        }
        if let Some(ref b) = options.body {
            req_builder = req_builder.body(Bytes::copy_from_slice(b));
        }
        let (request, body_bytes) = req_builder.build()?;

        rt.block_on(async move {
            let (mut client, h2_conn) = h2::client::handshake(stream)
                .await
                .map_err(|e| format!("h2 handshake error: {}", e))?;

            tokio::spawn(async move {
                let _ = h2_conn.await;
            });

            let (response, mut send_stream) = client
                .send_request(request, body_bytes.is_none())
                .map_err(|e| format!("h2 send_request error: {}", e))?;

            if let Some(bytes) = body_bytes {
                send_stream
                    .send_data(bytes, true)
                    .map_err(|e| format!("h2 send_data error: {}", e))?;
            }

            let response = response
                .await
                .map_err(|e| format!("h2 response header error: {}", e))?;

            let (head, mut body) = response.into_parts();
            let status = head.status.as_u16();
            let reason = head.status.canonical_reason().unwrap_or("OK");

            let mut headers_vec = Vec::with_capacity(head.headers.len());
            for (k, v) in head.headers.iter() {
                headers_vec.push((
                    k.as_str().to_string(),
                    String::from_utf8_lossy(v.as_bytes()).to_string(),
                ));
            }

            let should_decompress = options.transparent_decompression
                && !has_range_header
                && status != 206;

            let mut decompressor: Option<StreamDecompressor> = None;
            if should_decompress {
                if let Some((_, enc)) = headers_vec.iter().find(|(k, _)| k.eq_ignore_ascii_case("content-encoding")) {
                    if let Some(dec) = StreamDecompressor::new(enc) {
                        decompressor = Some(dec);
                    }
                }
            }

            if decompressor.is_some() {
                let filtered_headers: Vec<(String, String)> = headers_vec
                    .into_iter()
                    .filter(|(k, _)| {
                        !k.eq_ignore_ascii_case("content-encoding")
                            && !k.eq_ignore_ascii_case("content-length")
                    })
                    .collect();
                on_headers(status, reason, &filtered_headers);
            } else {
                on_headers(status, reason, &headers_vec);
            }

            while let Some(chunk_res) = body.data().await {
                if is_cancelled() {
                    return Ok(true);
                }
                let chunk = chunk_res.map_err(|e| format!("h2 body chunk error: {}", e))?;
                let chunk_len = chunk.len();
                if chunk_len > 0 {
                    let _ = body.flow_control().release_capacity(chunk_len);

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
                        }).map_err(|e| format!("h2 decompression error: {}", e))?;
                    } else {
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
                }).map_err(|e| format!("h2 decompression finish error: {}", e))?;
            }

            on_complete(true);
            Ok(true)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_h2_request_builder_get() {
        let builder = Http2RequestBuilder::new("GET", "https://example.com/api/data")
            .expect("valid request")
            .header("User-Agent", "Zawra/H2")
            .expect("valid header");

        let (req, body) = builder.build().expect("build request");
        assert_eq!(req.method(), Method::GET);
        assert_eq!(req.uri().path(), "/api/data");
        assert_eq!(req.uri().host(), Some("example.com"));
        assert_eq!(req.headers().get("user-agent").unwrap(), "Zawra/H2");
        assert!(body.is_none());
    }

    #[test]
    fn test_h2_request_builder_post_with_body() {
        let payload = Bytes::from_static(b"{\"action\":\"ping\"}");
        let builder = Http2RequestBuilder::new("POST", "https://api.example.com/v1/ping")
            .expect("valid request")
            .header("Content-Type", "application/json")
            .expect("valid header")
            .body(payload.clone());

        let (req, body) = builder.build().expect("build request");
        assert_eq!(req.method(), Method::POST);
        assert_eq!(req.headers().get("content-type").unwrap(), "application/json");
        assert_eq!(body, Some(payload));
    }

    #[test]
    fn test_h2_response_header_conversion() {
        let mut map = HeaderMap::new();
        map.insert(HeaderName::from_static("content-type"), HeaderValue::from_static("text/html"));
        map.insert(HeaderName::from_static("server"), HeaderValue::from_static("cloudflare"));

        let resp = Http2ResponseHeader::from_header_map(200, &map);
        assert_eq!(resp.status, 200);
        assert_eq!(resp.headers.get("content-type").unwrap(), "text/html");
        assert_eq!(resp.headers.get("server").unwrap(), "cloudflare");
    }

    #[test]
    fn test_h2_client_execute_streaming_roundtrip() {
        let (client_io, server_io) = tokio::io::duplex(65536);

        std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            rt.block_on(async move {
                let mut server = h2::server::handshake(server_io).await.unwrap();
                if let Some(Ok((request, mut respond))) = server.accept().await {
                    assert_eq!(request.method(), Method::GET);
                    let response = http::Response::builder()
                        .status(200)
                        .header("content-type", "text/plain")
                        .body(())
                        .unwrap();
                    let mut send = respond.send_response(response, false).unwrap();
                    send.send_data(Bytes::from_static(b"hello "), false).unwrap();
                    send.send_data(Bytes::from_static(b"world!"), true).unwrap();
                }
                while let Some(_) = server.accept().await {}
            });
        });

        let opts = HttpRequestOptions::new("GET", "https://example.com/stream");
        let mut got_status = 0;
        let mut got_headers = Vec::new();
        let mut got_body = Vec::new();
        let mut got_complete = false;

        let res = Http2Client::execute_streaming(
            client_io,
            &opts,
            None,
            |status, _reason, headers| {
                got_status = status;
                got_headers = headers.to_vec();
            },
            |chunk| {
                got_body.extend_from_slice(chunk);
            },
            |comp| {
                got_complete = comp;
            },
            || false,
        );

        assert!(res.is_ok(), "res error: {:?}", res.err());
        assert_eq!(got_status, 200);
        assert_eq!(got_body, b"hello world!");
        assert!(got_complete);
        assert!(got_headers.iter().any(|(k, v)| k == "content-type" && v == "text/plain"));
    }

    #[test]
    fn test_h2_client_execute_streaming_gzip_decompression() {
        use flate2::write::GzEncoder;
        use flate2::Compression;

        let raw_payload = b"Hello from compressed HTTP/2 streaming with transparent decompression!";
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(raw_payload).unwrap();
        let compressed_bytes = Bytes::from(encoder.finish().unwrap());

        let (client_io, server_io) = tokio::io::duplex(65536);

        std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            rt.block_on(async move {
                let mut server = h2::server::handshake(server_io).await.unwrap();
                if let Some(Ok((request, mut respond))) = server.accept().await {
                    assert_eq!(request.method(), Method::GET);
                    let response = http::Response::builder()
                        .status(200)
                        .header("content-type", "text/plain")
                        .header("content-encoding", "gzip")
                        .body(())
                        .unwrap();
                    let mut send = respond.send_response(response, false).unwrap();
                    send.send_data(compressed_bytes, true).unwrap();
                }
                while let Some(_) = server.accept().await {}
            });
        });

        let opts = HttpRequestOptions::new("GET", "https://example.com/gzip-stream");
        let mut got_status = 0;
        let mut got_headers = Vec::new();
        let mut got_body = Vec::new();
        let mut got_complete = false;

        let res = Http2Client::execute_streaming(
            client_io,
            &opts,
            None,
            |status, _reason, headers| {
                got_status = status;
                got_headers = headers.to_vec();
            },
            |chunk| {
                got_body.extend_from_slice(chunk);
            },
            |comp| {
                got_complete = comp;
            },
            || false,
        );

        assert!(res.is_ok(), "res error: {:?}", res.err());
        assert_eq!(got_status, 200);
        assert_eq!(got_body, raw_payload);
        assert!(got_complete);
        // Verify Content-Encoding was stripped on transparent decompression
        assert!(!got_headers.iter().any(|(k, _)| k.eq_ignore_ascii_case("content-encoding")));
    }
}
