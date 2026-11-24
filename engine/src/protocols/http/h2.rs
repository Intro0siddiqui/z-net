use std::collections::HashMap;
use std::io::{ErrorKind, Read, Write};
use std::sync::atomic::Ordering;

use bytes::Bytes;
use h2_sans_io::{
    H2Codec, H2Event, H2Header, HpackDecoder, HpackEncoder, CONNECTION_PREFACE,
};
use http::{HeaderMap, HeaderName, HeaderValue, Method, Request, StatusCode, Uri};
use url::Url;

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
        let uri = uri_str
            .parse::<Uri>()
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
        let mut builder = Request::builder().method(self.method).uri(self.uri);

        if let Some(headers_mut) = builder.headers_mut() {
            for (k, v) in self.headers.drain() {
                if let Some(name) = k {
                    headers_mut.insert(name, v);
                }
            }
        }

        let request = builder
            .body(())
            .map_err(|e| format!("Failed to build request: {}", e))?;
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

fn write_slice_to_ring(ring: &BodyRingDescriptor, slice: &[u8]) {
    let mut offset = 0;
    while offset < slice.len() && !ring.is_closed.load(Ordering::Acquire) {
        let written = ring.write_slice(&slice[offset..]);
        offset += written;
        if offset < slice.len() {
            ring.wait_drain(5);
        }
    }
}

fn is_hop_by_hop_header(name: &str) -> bool {
    name.eq_ignore_ascii_case("connection")
        || name.eq_ignore_ascii_case("keep-alive")
        || name.eq_ignore_ascii_case("proxy-connection")
        || name.eq_ignore_ascii_case("transfer-encoding")
        || name.eq_ignore_ascii_case("upgrade")
        || name.eq_ignore_ascii_case("host")
}

pub struct Http2Client;

impl Http2Client {
    /// Execute an HTTP/2 request with progressive streaming using `h2-sans-io` (zero async runtime).
    pub fn execute_streaming<S, H, D, C, K>(
        mut stream: S,
        options: &HttpRequestOptions,
        body_ring: Option<&BodyRingDescriptor>,
        mut on_headers: H,
        mut on_data_chunk: D,
        mut on_complete: C,
        mut is_cancelled: K,
    ) -> Result<bool, String>
    where
        S: Read + Write,
        H: FnMut(u16, &str, &[(String, String)]),
        D: FnMut(&[u8]),
        C: FnMut(bool),
        K: FnMut() -> bool,
    {
        let parsed_url = Url::parse(&options.url)
            .map_err(|e| format!("Invalid URL for h2: {}", e))?;
        let scheme = parsed_url.scheme();
        let host = parsed_url.host_str().ok_or("Missing host in URL")?;
        let authority = match parsed_url.port() {
            Some(p) => format!("{}:{}", host, p),
            None => host.to_string(),
        };
        let mut path_and_query = parsed_url.path().to_string();
        if let Some(q) = parsed_url.query() {
            path_and_query.push('?');
            path_and_query.push_str(q);
        }
        if path_and_query.is_empty() {
            path_and_query = "/".to_string();
        }

        let has_range_header = options.headers.iter().any(|(k, _)| k.eq_ignore_ascii_case("range"));
        let has_accept_encoding = options
            .headers
            .iter()
            .any(|(k, _)| k.eq_ignore_ascii_case("accept-encoding"));

        // 1. Encode HTTP/2 pseudo-headers and request headers via HPACK
        let mut h2_headers = Vec::with_capacity(4 + options.headers.len() + 1);
        h2_headers.push(H2Header::new(":method", options.method.as_bytes()));
        h2_headers.push(H2Header::new(":scheme", scheme.as_bytes()));
        h2_headers.push(H2Header::new(":authority", authority.as_bytes()));
        h2_headers.push(H2Header::new(":path", path_and_query.as_bytes()));

        for (k, v) in &options.headers {
            if is_hop_by_hop_header(k) {
                continue;
            }
            h2_headers.push(H2Header::new(k.to_ascii_lowercase().into_bytes(), v.as_bytes()));
        }
        if options.transparent_decompression && !has_range_header && !has_accept_encoding {
            h2_headers.push(H2Header::new("accept-encoding", "gzip, deflate, br, zstd"));
        }

        let mut encoder = HpackEncoder::new();
        let header_block = encoder.encode(&h2_headers);

        // 2. Send client connection preface, SETTINGS, connection window update, and request frames
        stream
            .write_all(CONNECTION_PREFACE)
            .map_err(|e| format!("h2 preface write failed: {}", e))?;
        stream
            .write_all(&H2Codec::create_settings_with_window(1024 * 1024))
            .map_err(|e| format!("h2 settings write failed: {}", e))?;
        stream
            .write_all(&H2Codec::create_window_update(0, 1024 * 1024))
            .map_err(|e| format!("h2 window update write failed: {}", e))?;

        let stream_id: u32 = 1;
        let max_frame_size: u32 = 16384;
        let has_body = options.body.as_ref().map_or(false, |b| !b.is_empty());
        for frame in H2Codec::create_headers_frames(stream_id, &header_block, !has_body, max_frame_size) {
            stream
                .write_all(&frame)
                .map_err(|e| format!("h2 headers write failed: {}", e))?;
        }
        if let Some(ref body) = options.body {
            if !body.is_empty() {
                for frame in H2Codec::create_data_frames(stream_id, body, true, max_frame_size) {
                    stream
                        .write_all(&frame)
                        .map_err(|e| format!("h2 data write failed: {}", e))?;
                }
            }
        }
        stream
            .flush()
            .map_err(|e| format!("h2 flush failed: {}", e))?;

        // 3. Progressive frame read & decode loop
        let mut codec = H2Codec::new();
        codec.set_preface_received(true);
        let mut decoder = HpackDecoder::new();

        let mut read_buf = [0u8; 16384];
        let mut headers_dispatched = false;
        let mut stream_ended = false;
        let mut decompressor: Option<StreamDecompressor> = None;

        while !stream_ended {
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

            let n = match stream.read(&mut read_buf) {
                Ok(0) => {
                    if headers_dispatched {
                        break;
                    }
                    return Err("h2 connection closed before response headers".to_string());
                }
                Ok(n) => n,
                Err(ref e) if e.kind() == ErrorKind::WouldBlock || e.kind() == ErrorKind::Interrupted => {
                    std::thread::sleep(std::time::Duration::from_millis(2));
                    continue;
                }
                Err(e) => return Err(format!("h2 read error: {}", e)),
            };

            let events = codec
                .process(&read_buf[..n])
                .map_err(|e| format!("h2 frame decode error: {}", e))?;

            for event in events {
                match event {
                    H2Event::Settings { ack: false, .. } => {
                        let _ = stream.write_all(&H2Codec::create_settings_ack());
                        let _ = stream.flush();
                    }
                    H2Event::Ping { ack: false, data } => {
                        let _ = stream.write_all(&H2Codec::create_ping_ack(data));
                        let _ = stream.flush();
                    }
                    H2Event::Headers {
                        stream_id: ev_sid,
                        header_block,
                        end_stream,
                    } if ev_sid == stream_id => {
                        let decoded = decoder
                            .decode(&header_block)
                            .map_err(|e| format!("h2 HPACK decode error: {}", e))?;

                        let mut status: u16 = 200;
                        let mut headers_vec = Vec::with_capacity(decoded.len());
                        for h in decoded {
                            let name = String::from_utf8_lossy(&h.name).to_string();
                            let value = String::from_utf8_lossy(&h.value).to_string();
                            if name == ":status" {
                                if let Ok(code) = value.parse::<u16>() {
                                    status = code;
                                }
                            } else if !name.starts_with(':') {
                                headers_vec.push((name, value));
                            }
                        }

                        // Skip 1xx informational headers
                        if (100..200).contains(&status) {
                            continue;
                        }

                        let reason = StatusCode::from_u16(status)
                            .ok()
                            .and_then(|s| s.canonical_reason())
                            .unwrap_or("OK");

                        let should_decompress = options.transparent_decompression
                            && !has_range_header
                            && status != 206;

                        if should_decompress {
                            if let Some((_, enc)) = headers_vec
                                .iter()
                                .find(|(k, _)| k.eq_ignore_ascii_case("content-encoding"))
                            {
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

                        headers_dispatched = true;
                        if end_stream {
                            stream_ended = true;
                        }
                    }
                    H2Event::Data {
                        stream_id: ev_sid,
                        data,
                        end_stream,
                    } if ev_sid == stream_id => {
                        if !data.is_empty() {
                            let len_u32 = data.len() as u32;
                            let _ = stream.write_all(&H2Codec::create_window_update(0, len_u32));
                            let _ = stream.write_all(&H2Codec::create_window_update(stream_id, len_u32));
                            let _ = stream.flush();

                            if let Some(ref mut dec) = decompressor {
                                dec.feed(&data, |decompressed_slice| {
                                    if let Some(ring) = body_ring {
                                        write_slice_to_ring(ring, decompressed_slice);
                                    }
                                    on_data_chunk(decompressed_slice);
                                })
                                .map_err(|e| format!("h2 decompression error: {}", e))?;
                            } else {
                                if let Some(ring) = body_ring {
                                    write_slice_to_ring(ring, &data);
                                }
                                on_data_chunk(&data);
                            }
                        }
                        if end_stream {
                            stream_ended = true;
                        }
                    }
                    H2Event::StreamReset {
                        stream_id: ev_sid,
                        error_code,
                    } if ev_sid == stream_id => {
                        return Err(format!("h2 stream reset (error code {})", error_code));
                    }
                    H2Event::GoAway { error_code, .. } => {
                        if !headers_dispatched {
                            return Err(format!("h2 GOAWAY before headers (error code {})", error_code));
                        }
                        stream_ended = true;
                    }
                    _ => {}
                }
            }
        }

        if let Some(dec) = decompressor.take() {
            dec.finish(|decompressed_slice| {
                if let Some(ring) = body_ring {
                    write_slice_to_ring(ring, decompressed_slice);
                }
                on_data_chunk(decompressed_slice);
            })
            .map_err(|e| format!("h2 decompression finish error: {}", e))?;
        }

        on_complete(true);
        Ok(headers_dispatched)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Shutdown, TcpListener, TcpStream};

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
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind local h2 server");
        let addr = listener.local_addr().unwrap();

        let server_thread = std::thread::spawn(move || {
            let (mut conn, _) = listener.accept().expect("accept");
            let mut codec = H2Codec::new();
            let mut dec = HpackDecoder::new();
            let mut enc = HpackEncoder::new();
            let mut buf = [0u8; 4096];

            loop {
                let n = conn.read(&mut buf).unwrap_or(0);
                if n == 0 {
                    break;
                }
                let events = codec.process(&buf[..n]).expect("server decode");
                for ev in events {
                    if let H2Event::Settings { ack: false, .. } = ev {
                        conn.write_all(&H2Codec::create_settings()).unwrap();
                        conn.write_all(&H2Codec::create_settings_ack()).unwrap();
                        conn.flush().unwrap();
                    } else if let H2Event::Headers { stream_id, header_block, .. } = ev {
                        let hdrs = dec.decode(&header_block).expect("decode req headers");
                        assert!(hdrs.iter().any(|h| h.name == b":method" && h.value == b"GET"));
                        assert!(hdrs.iter().any(|h| h.name == b":path" && h.value == b"/stream"));

                        let resp_hdrs = vec![
                            H2Header::new(":status", "200"),
                            H2Header::new("content-type", "text/plain"),
                        ];
                        let block = enc.encode(&resp_hdrs);
                        conn.write_all(&H2Codec::create_headers_frame(stream_id, &block, false))
                            .unwrap();
                        for f in H2Codec::create_data_frames(stream_id, b"hello ", false, 16384) {
                            conn.write_all(&f).unwrap();
                        }
                        for f in H2Codec::create_data_frames(stream_id, b"world!", true, 16384) {
                            conn.write_all(&f).unwrap();
                        }
                        conn.flush().unwrap();
                        let _ = conn.shutdown(Shutdown::Write);
                        while conn.read(&mut buf).unwrap_or(0) > 0 {}
                        return;
                    }
                }
            }
        });

        let client_tcp = TcpStream::connect(addr).expect("connect to local h2 server");
        let opts = HttpRequestOptions::new("GET", &format!("http://{}/stream", addr));
        let mut got_status = 0;
        let mut got_headers = Vec::new();
        let mut got_body = Vec::new();
        let mut got_complete = false;

        let res = Http2Client::execute_streaming(
            client_tcp,
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

        server_thread.join().expect("server join");
        assert!(res.is_ok(), "res error: {:?}", res.err());
        assert_eq!(got_status, 200);
        assert_eq!(got_body, b"hello world!");
        assert!(got_complete);
        assert!(got_headers
            .iter()
            .any(|(k, v)| k == "content-type" && v == "text/plain"));
    }

    #[test]
    fn test_h2_client_execute_streaming_gzip_decompression() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind local h2 gzip server");
        let addr = listener.local_addr().unwrap();

        let server_thread = std::thread::spawn(move || {
            let (mut conn, _) = listener.accept().expect("accept");
            let mut codec = H2Codec::new();
            let mut enc = HpackEncoder::new();
            let mut buf = [0u8; 4096];

            loop {
                let n = conn.read(&mut buf).unwrap_or(0);
                if n == 0 {
                    break;
                }
                let events = codec.process(&buf[..n]).expect("server decode");
                for ev in events {
                    if let H2Event::Settings { ack: false, .. } = ev {
                        conn.write_all(&H2Codec::create_settings()).unwrap();
                        conn.write_all(&H2Codec::create_settings_ack()).unwrap();
                        conn.flush().unwrap();
                    } else if let H2Event::Headers { stream_id, .. } = ev {
                        let mut gz = flate2::write::GzEncoder::new(
                            Vec::new(),
                            flate2::Compression::default(),
                        );
                        gz.write_all(b"compressed h2 payload").unwrap();
                        let gz_bytes = gz.finish().unwrap();

                        let resp_hdrs = vec![
                            H2Header::new(":status", "200"),
                            H2Header::new("content-encoding", "gzip"),
                            H2Header::new("content-length", gz_bytes.len().to_string().as_bytes()),
                        ];
                        let block = enc.encode(&resp_hdrs);
                        conn.write_all(&H2Codec::create_headers_frame(stream_id, &block, false))
                            .unwrap();
                        for f in H2Codec::create_data_frames(stream_id, &gz_bytes, true, 16384) {
                            conn.write_all(&f).unwrap();
                        }
                        conn.flush().unwrap();
                        let _ = conn.shutdown(Shutdown::Write);
                        while conn.read(&mut buf).unwrap_or(0) > 0 {}
                        return;
                    }
                }
            }
        });

        let client_tcp = TcpStream::connect(addr).expect("connect to local h2 gzip server");
        let opts = HttpRequestOptions::new("GET", &format!("http://{}/gzip", addr));
        let mut got_status = 0;
        let mut got_headers = Vec::new();
        let mut got_body = Vec::new();
        let mut got_complete = false;

        let res = Http2Client::execute_streaming(
            client_tcp,
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

        server_thread.join().expect("server join");
        assert!(res.is_ok(), "res error: {:?}", res.err());
        assert_eq!(got_status, 200);
        assert_eq!(got_body, b"compressed h2 payload");
        assert!(got_complete);
        assert!(!got_headers
            .iter()
            .any(|(k, _)| k.eq_ignore_ascii_case("content-encoding")));
        assert!(!got_headers
            .iter()
            .any(|(k, _)| k.eq_ignore_ascii_case("content-length")));
    }
}
