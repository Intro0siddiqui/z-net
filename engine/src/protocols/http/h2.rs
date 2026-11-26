use std::collections::HashMap;
use std::io::{ErrorKind, Read, Write};
use std::sync::atomic::Ordering;
use std::sync::{mpsc, Arc, Condvar, Mutex};
use std::time::Duration;

use bytes::Bytes;
use h2_sans_io::{
    flags, frame_type, settings_id, H2Codec, H2Event, H2Header, HpackDecoder, HpackEncoder,
    CONNECTION_PREFACE,
};
use http::{HeaderMap, HeaderName, HeaderValue, Method, Request, StatusCode, Uri};
use url::Url;

use crate::protocols::compression::StreamDecompressor;
use crate::protocols::http::client::HttpRequestOptions;
use crate::BodyRingDescriptor;

/// Browser HTTP/2 fingerprint profile controlling initial SETTINGS,
/// Stream 0 WINDOW_UPDATE, and stream priority signaling.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum H2FingerprintProfile {
    /// Modern Chrome / Chromium H2 fingerprint.
    Chrome,
    /// Modern Firefox H2 fingerprint.
    Firefox,
}

impl Default for H2FingerprintProfile {
    fn default() -> Self {
        Self::Chrome
    }
}

/// RFC 7540 §6.2 stream priority fields carried in HEADERS frames.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct H2StreamPriority {
    pub exclusive: bool,
    pub stream_dependency: u32,
    /// Wire weight (actual weight = wire_weight + 1; Chrome default is 255 => 256).
    pub weight: u8,
}

impl Default for H2StreamPriority {
    fn default() -> Self {
        Self {
            exclusive: true,
            stream_dependency: 0,
            weight: 255,
        }
    }
}

/// Returns the full browser initial SETTINGS pairs for `profile`.
pub fn browser_settings_pairs(profile: H2FingerprintProfile) -> [(u16, u32); 6] {
    match profile {
        H2FingerprintProfile::Chrome => [
            (settings_id::HEADER_TABLE_SIZE, 65_536),
            (settings_id::ENABLE_PUSH, 0),
            (settings_id::MAX_CONCURRENT_STREAMS, 1_000),
            (settings_id::INITIAL_WINDOW_SIZE, 6_291_456),
            (settings_id::MAX_FRAME_SIZE, 16_384),
            (settings_id::MAX_HEADER_LIST_SIZE, 262_144),
        ],
        H2FingerprintProfile::Firefox => [
            (settings_id::HEADER_TABLE_SIZE, 65_536),
            (settings_id::ENABLE_PUSH, 0),
            (settings_id::MAX_CONCURRENT_STREAMS, 100),
            (settings_id::INITIAL_WINDOW_SIZE, 131_072),
            (settings_id::MAX_FRAME_SIZE, 16_384),
            (settings_id::MAX_HEADER_LIST_SIZE, 262_144),
        ],
    }
}

/// Build an RFC 7540 SETTINGS frame containing all 6 browser settings.
pub fn build_browser_settings_frame(profile: H2FingerprintProfile) -> Vec<u8> {
    let pairs = browser_settings_pairs(profile);
    let payload_len = pairs.len() * 6;
    let mut frame = Vec::with_capacity(9 + payload_len);
    // 24-bit payload length
    frame.push(((payload_len >> 16) & 0xFF) as u8);
    frame.push(((payload_len >> 8) & 0xFF) as u8);
    frame.push((payload_len & 0xFF) as u8);
    // Frame type = SETTINGS (0x04), flags = 0x00, stream_id = 0
    frame.push(frame_type::SETTINGS);
    frame.push(0x00);
    frame.extend_from_slice(&0u32.to_be_bytes());
    for (id, val) in pairs {
        frame.extend_from_slice(&id.to_be_bytes());
        frame.extend_from_slice(&val.to_be_bytes());
    }
    frame
}

/// Browser-sized Stream 0 WINDOW_UPDATE increment (Chrome: 15,663,105).
pub fn browser_initial_window_update(profile: H2FingerprintProfile) -> u32 {
    match profile {
        H2FingerprintProfile::Chrome => 15_663_105,
        H2FingerprintProfile::Firefox => 12_517_377,
    }
}

/// Build HEADERS (+ optional CONTINUATION) frames with RFC 7540 PRIORITY signaling.
pub fn build_headers_frames_with_priority(
    stream_id: u32,
    header_block: &[u8],
    end_stream: bool,
    max_frame_size: u32,
    priority: H2StreamPriority,
) -> Vec<Vec<u8>> {
    let max_payload = (max_frame_size as usize).max(16_384);
    let first_chunk_cap = max_payload.saturating_sub(5).max(1);
    let first_len = header_block.len().min(first_chunk_cap);
    let is_single = first_len == header_block.len();

    let mut frame_flags = flags::PRIORITY;
    if end_stream {
        frame_flags |= flags::END_STREAM;
    }
    if is_single {
        frame_flags |= flags::END_HEADERS;
    }

    let payload_len = 5 + first_len;
    let mut first_frame = Vec::with_capacity(9 + payload_len);
    first_frame.push(((payload_len >> 16) & 0xFF) as u8);
    first_frame.push(((payload_len >> 8) & 0xFF) as u8);
    first_frame.push((payload_len & 0xFF) as u8);
    first_frame.push(frame_type::HEADERS);
    first_frame.push(frame_flags);
    first_frame.extend_from_slice(&(stream_id & 0x7FFF_FFFF).to_be_bytes());

    let dep_word = if priority.exclusive {
        (priority.stream_dependency & 0x7FFF_FFFF) | 0x8000_0000
    } else {
        priority.stream_dependency & 0x7FFF_FFFF
    };
    first_frame.extend_from_slice(&dep_word.to_be_bytes());
    first_frame.push(priority.weight);
    first_frame.extend_from_slice(&header_block[..first_len]);

    let mut frames = vec![first_frame];
    let mut offset = first_len;
    while offset < header_block.len() {
        let end = (offset + max_payload).min(header_block.len());
        let is_last = end == header_block.len();
        frames.push(H2Codec::create_continuation_frame(
            stream_id,
            &header_block[offset..end],
            is_last,
        ));
        offset = end;
    }
    frames
}

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

    /// Build the standard `http::Request` containing pseudo-headers (:method, :authority, :scheme, :path).
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

pub(crate) fn is_hop_by_hop_header(name: &str) -> bool {
    name.eq_ignore_ascii_case("connection")
        || name.eq_ignore_ascii_case("keep-alive")
        || name.eq_ignore_ascii_case("proxy-connection")
        || name.eq_ignore_ascii_case("transfer-encoding")
        || name.eq_ignore_ascii_case("upgrade")
        || name.eq_ignore_ascii_case("host")
}

/// Per-stream state tracked during concurrent HTTP/2 multiplexing.
struct ActiveStreamState {
    transparent_decompression: bool,
    has_range_header: bool,
    headers_dispatched: bool,
    decompressor: Option<StreamDecompressor>,
}

/// Events emitted by `H2Session::drive_once` for multiplexed streams.
#[derive(Debug)]
pub enum H2MuxEvent {
    Headers {
        stream_id: u32,
        status: u16,
        reason: &'static str,
        headers: Vec<(String, String)>,
    },
    Data {
        stream_id: u32,
        data: Vec<u8>,
    },
    Complete {
        stream_id: u32,
    },
    StreamReset {
        stream_id: u32,
        error_code: u32,
    },
    GoAway {
        error_code: u32,
    },
}

/// Persistent HTTP/2 connection session supporting concurrent multiplexed streams,
/// browser-grade initial SETTINGS, Stream 0 WINDOW_UPDATE, Chrome pseudo-header order,
/// and priority signaling.
pub struct H2Session<S> {
    pub stream: S,
    pub codec: H2Codec,
    pub encoder: HpackEncoder,
    pub decoder: HpackDecoder,
    pub next_stream_id: u32,
    pub peer_max_frame_size: u32,
    pub peer_max_concurrent_streams: u32,
    pub goaway_received: bool,
    pub profile: H2FingerprintProfile,
    active_streams: HashMap<u32, ActiveStreamState>,
}

impl<S: Read + Write> H2Session<S> {
    /// Initialize a new HTTP/2 session with Chrome-like browser SETTINGS and Stream 0 WINDOW_UPDATE.
    pub fn new(stream: S) -> Result<Self, String> {
        Self::new_with_profile(stream, H2FingerprintProfile::Chrome)
    }

    /// Initialize a new HTTP/2 session with an explicit browser fingerprint profile.
    pub fn new_with_profile(mut stream: S, profile: H2FingerprintProfile) -> Result<Self, String> {
        stream
            .write_all(CONNECTION_PREFACE)
            .map_err(|e| format!("h2 preface write failed: {}", e))?;
        stream
            .write_all(&build_browser_settings_frame(profile))
            .map_err(|e| format!("h2 settings write failed: {}", e))?;
        stream
            .write_all(&H2Codec::create_window_update(
                0,
                browser_initial_window_update(profile),
            ))
            .map_err(|e| format!("h2 window update write failed: {}", e))?;
        stream
            .flush()
            .map_err(|e| format!("h2 preface flush failed: {}", e))?;

        let mut codec = H2Codec::new();
        codec.set_preface_received(true);

        Ok(Self {
            stream,
            codec,
            encoder: HpackEncoder::new(),
            decoder: HpackDecoder::new(),
            next_stream_id: 1,
            peer_max_frame_size: 16384,
            peer_max_concurrent_streams: 100,
            goaway_received: false,
            profile,
            active_streams: HashMap::new(),
        })
    }

    pub fn is_reusable(&self) -> bool {
        !self.goaway_received && self.next_stream_id < u32::MAX - 2
    }

    pub fn active_stream_count(&self) -> usize {
        self.active_streams.len()
    }

    /// Submit a request on a new multiplexed stream without blocking for its response.
    /// Encodes pseudo-headers in Chrome order (`:method`, `:authority`, `:scheme`, `:path`)
    /// with RFC 7540 priority signaling.
    pub fn submit_request(&mut self, options: &HttpRequestOptions) -> Result<u32, String> {
        self.submit_request_with_priority(options, H2StreamPriority::default())
    }

    /// Submit a request on a new multiplexed stream with explicit priority signaling.
    pub fn submit_request_with_priority(
        &mut self,
        options: &HttpRequestOptions,
        priority: H2StreamPriority,
    ) -> Result<u32, String> {
        if self.goaway_received {
            return Err("h2 session received GOAWAY".to_string());
        }

        let parsed_url =
            Url::parse(&options.url).map_err(|e| format!("Invalid URL for h2: {}", e))?;
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

        let has_range_header = options
            .headers
            .iter()
            .any(|(k, _)| k.eq_ignore_ascii_case("range"));
        let has_accept_encoding = options
            .headers
            .iter()
            .any(|(k, _)| k.eq_ignore_ascii_case("accept-encoding"));

        // Chrome pseudo-header order: :method, :authority, :scheme, :path
        let mut h2_headers = Vec::with_capacity(4 + options.headers.len() + 1);
        h2_headers.push(H2Header::new(":method", options.method.as_bytes()));
        h2_headers.push(H2Header::new(":authority", authority.as_bytes()));
        h2_headers.push(H2Header::new(":scheme", scheme.as_bytes()));
        h2_headers.push(H2Header::new(":path", path_and_query.as_bytes()));

        for (k, v) in &options.headers {
            if is_hop_by_hop_header(k) {
                continue;
            }
            h2_headers.push(H2Header::new(
                k.to_ascii_lowercase().into_bytes(),
                v.as_bytes(),
            ));
        }
        if options.transparent_decompression && !has_range_header && !has_accept_encoding {
            h2_headers.push(H2Header::new("accept-encoding", "gzip, deflate, br, zstd"));
        }

        let header_block = self.encoder.encode(&h2_headers);

        let stream_id = self.next_stream_id;
        self.next_stream_id = self.next_stream_id.saturating_add(2);

        let max_frame_size = self.peer_max_frame_size;
        let has_body = options.body.as_ref().map_or(false, |b| !b.is_empty());
        for frame in build_headers_frames_with_priority(
            stream_id,
            &header_block,
            !has_body,
            max_frame_size,
            priority,
        ) {
            self.stream
                .write_all(&frame)
                .map_err(|e| format!("h2 headers write failed: {}", e))?;
        }
        if let Some(ref body) = options.body {
            if !body.is_empty() {
                for frame in H2Codec::create_data_frames(stream_id, body, true, max_frame_size) {
                    self.stream
                        .write_all(&frame)
                        .map_err(|e| format!("h2 data write failed: {}", e))?;
                }
            }
        }
        self.stream
            .flush()
            .map_err(|e| format!("h2 flush failed: {}", e))?;

        self.active_streams.insert(
            stream_id,
            ActiveStreamState {
                transparent_decompression: options.transparent_decompression,
                has_range_header,
                headers_dispatched: false,
                decompressor: None,
            },
        );

        Ok(stream_id)
    }

    /// Read once from the underlying transport and demultiplex any decoded HTTP/2 events
    /// across all currently active streams. Returns `Ok(vec![])` on `WouldBlock`/`TimedOut`.
    pub fn drive_once(&mut self) -> Result<Vec<H2MuxEvent>, String> {
        let mut read_buf = [0u8; 16384];
        let n = match self.stream.read(&mut read_buf) {
            Ok(0) => {
                self.goaway_received = true;
                return Err("h2 connection closed by peer".to_string());
            }
            Ok(n) => n,
            Err(ref e)
                if e.kind() == ErrorKind::WouldBlock
                    || e.kind() == ErrorKind::TimedOut
                    || e.kind() == ErrorKind::Interrupted =>
            {
                return Ok(Vec::new());
            }
            Err(e) => {
                self.goaway_received = true;
                return Err(format!("h2 read error: {}", e));
            }
        };

        let events = self.codec.process(&read_buf[..n]).map_err(|e| {
            self.goaway_received = true;
            format!("h2 frame decode error: {}", e)
        })?;

        let mut out = Vec::new();
        for event in events {
            match event {
                H2Event::Settings {
                    ack: false,
                    settings,
                } => {
                    for (id, val) in settings {
                        if id == settings_id::MAX_FRAME_SIZE && val >= 16384 && val <= 16_777_215 {
                            self.peer_max_frame_size = val;
                        } else if id == settings_id::MAX_CONCURRENT_STREAMS && val > 0 {
                            self.peer_max_concurrent_streams = val;
                        }
                    }
                    let _ = self.stream.write_all(&H2Codec::create_settings_ack());
                    let _ = self.stream.flush();
                }
                H2Event::Ping { ack: false, data } => {
                    let _ = self.stream.write_all(&H2Codec::create_ping_ack(data));
                    let _ = self.stream.flush();
                }
                H2Event::Headers {
                    stream_id,
                    header_block,
                    end_stream,
                } => {
                    // Always decode HPACK to keep dynamic table synchronized across all streams
                    let decoded = self.decoder.decode(&header_block).map_err(|e| {
                        self.goaway_received = true;
                        format!("h2 HPACK decode error: {}", e)
                    })?;

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

                    if (100..200).contains(&status) {
                        continue;
                    }

                    let reason = StatusCode::from_u16(status)
                        .ok()
                        .and_then(|s| s.canonical_reason())
                        .unwrap_or("OK");

                    if let Some(st) = self.active_streams.get_mut(&stream_id) {
                        let should_decompress = st.transparent_decompression
                            && !st.has_range_header
                            && status != 206;

                        if should_decompress {
                            if let Some((_, enc)) = headers_vec
                                .iter()
                                .find(|(k, _)| k.eq_ignore_ascii_case("content-encoding"))
                            {
                                if let Some(dec) = StreamDecompressor::new(enc) {
                                    st.decompressor = Some(dec);
                                }
                            }
                        }

                        let emitted_headers = if st.decompressor.is_some() {
                            headers_vec
                                .into_iter()
                                .filter(|(k, _)| {
                                    !k.eq_ignore_ascii_case("content-encoding")
                                        && !k.eq_ignore_ascii_case("content-length")
                                })
                                .collect()
                        } else {
                            headers_vec
                        };

                        st.headers_dispatched = true;
                        out.push(H2MuxEvent::Headers {
                            stream_id,
                            status,
                            reason,
                            headers: emitted_headers,
                        });

                        if end_stream {
                            if let Some(dec) = st.decompressor.take() {
                                let mut tail = Vec::new();
                                dec.finish(|s| tail.extend_from_slice(s))
                                    .map_err(|e| format!("h2 decompression finish error: {}", e))?;
                                if !tail.is_empty() {
                                    out.push(H2MuxEvent::Data {
                                        stream_id,
                                        data: tail,
                                    });
                                }
                            }
                            self.active_streams.remove(&stream_id);
                            self.codec.remove_stream(stream_id);
                            out.push(H2MuxEvent::Complete { stream_id });
                        }
                    }
                }
                H2Event::Data {
                    stream_id,
                    data,
                    end_stream,
                } => {
                    if !data.is_empty() {
                        let len_u32 = data.len() as u32;
                        let _ = self
                            .stream
                            .write_all(&H2Codec::create_window_update(0, len_u32));
                        let _ = self
                            .stream
                            .write_all(&H2Codec::create_window_update(stream_id, len_u32));
                        let _ = self.stream.flush();
                    }

                    if let Some(st) = self.active_streams.get_mut(&stream_id) {
                        if !data.is_empty() {
                            if let Some(ref mut dec) = st.decompressor {
                                let mut decoded_buf = Vec::new();
                                dec.feed(&data, |s| decoded_buf.extend_from_slice(s))
                                    .map_err(|e| format!("h2 decompression error: {}", e))?;
                                if !decoded_buf.is_empty() {
                                    out.push(H2MuxEvent::Data {
                                        stream_id,
                                        data: decoded_buf,
                                    });
                                }
                            } else {
                                out.push(H2MuxEvent::Data {
                                    stream_id,
                                    data: data.to_vec(),
                                });
                            }
                        }

                        if end_stream {
                            if let Some(dec) = st.decompressor.take() {
                                let mut tail = Vec::new();
                                dec.finish(|s| tail.extend_from_slice(s))
                                    .map_err(|e| format!("h2 decompression finish error: {}", e))?;
                                if !tail.is_empty() {
                                    out.push(H2MuxEvent::Data {
                                        stream_id,
                                        data: tail,
                                    });
                                }
                            }
                            self.active_streams.remove(&stream_id);
                            self.codec.remove_stream(stream_id);
                            out.push(H2MuxEvent::Complete { stream_id });
                        }
                    }
                }
                H2Event::StreamReset {
                    stream_id,
                    error_code,
                } => {
                    self.active_streams.remove(&stream_id);
                    self.codec.remove_stream(stream_id);
                    out.push(H2MuxEvent::StreamReset {
                        stream_id,
                        error_code,
                    });
                }
                H2Event::GoAway { error_code, .. } => {
                    self.goaway_received = true;
                    out.push(H2MuxEvent::GoAway { error_code });
                }
                _ => {}
            }
        }

        Ok(out)
    }

    /// Execute a single HTTP/2 request/response stream on this persistent session.
    pub fn execute_request<H, D, C, K>(
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
        let stream_id = self.submit_request(options)?;
        let mut headers_dispatched = false;
        let mut stream_ended = false;

        while !stream_ended {
            if is_cancelled() {
                self.active_streams.remove(&stream_id);
                let _ = self
                    .stream
                    .write_all(&H2Codec::create_rst_stream(stream_id, 0x8));
                let _ = self.stream.flush();
                return Ok(headers_dispatched);
            }

            if let Some(ring) = body_ring {
                while ring.should_stop_reading() && !ring.is_closed.load(Ordering::Acquire) {
                    if is_cancelled() {
                        self.active_streams.remove(&stream_id);
                        return Ok(headers_dispatched);
                    }
                    ring.wait_drain(5);
                }
            }

            let events = match self.drive_once() {
                Ok(ev) if ev.is_empty() => {
                    std::thread::sleep(Duration::from_millis(2));
                    continue;
                }
                Ok(ev) => ev,
                Err(e) => {
                    if headers_dispatched && self.goaway_received {
                        break;
                    }
                    return Err(e);
                }
            };

            for ev in events {
                match ev {
                    H2MuxEvent::Headers {
                        stream_id: sid,
                        status,
                        reason,
                        headers,
                    } if sid == stream_id => {
                        on_headers(status, reason, &headers);
                        headers_dispatched = true;
                    }
                    H2MuxEvent::Data {
                        stream_id: sid,
                        data,
                    } if sid == stream_id => {
                        if let Some(ring) = body_ring {
                            write_slice_to_ring(ring, &data);
                        }
                        on_data_chunk(&data);
                    }
                    H2MuxEvent::Complete { stream_id: sid } if sid == stream_id => {
                        stream_ended = true;
                    }
                    H2MuxEvent::StreamReset {
                        stream_id: sid,
                        error_code,
                    } if sid == stream_id => {
                        return Err(format!("h2 stream reset (error code {})", error_code));
                    }
                    H2MuxEvent::GoAway { error_code } => {
                        if !headers_dispatched {
                            return Err(format!(
                                "h2 GOAWAY before headers (error code {})",
                                error_code
                            ));
                        }
                        stream_ended = true;
                    }
                    _ => {}
                }
            }
        }

        on_complete(true);
        Ok(headers_dispatched)
    }
}

/// Signal delivered to a caller waiting on a multiplexed stream in `SharedH2Session`.
enum SharedStreamSignal {
    Headers {
        status: u16,
        reason: &'static str,
        headers: Vec<(String, String)>,
    },
    Data(Vec<u8>),
    Complete,
    Error(String),
}

struct SharedH2Inner<S> {
    session: H2Session<S>,
    waiters: HashMap<u32, mpsc::Sender<SharedStreamSignal>>,
    closed_error: Option<String>,
}

/// Thread-safe, zero-tokio multiplexed HTTP/2 session wrapper allowing multiple
/// concurrent callers to share a single pooled HTTP/2 connection simultaneously.
pub struct SharedH2Session<S> {
    inner: Mutex<SharedH2Inner<S>>,
    wake: Condvar,
}

impl<S: Read + Write> SharedH2Session<S> {
    pub fn new(session: H2Session<S>) -> Arc<Self> {
        Arc::new(Self {
            inner: Mutex::new(SharedH2Inner {
                session,
                waiters: HashMap::new(),
                closed_error: None,
            }),
            wake: Condvar::new(),
        })
    }

    pub fn is_reusable(&self) -> bool {
        self.inner
            .lock()
            .map(|g| g.closed_error.is_none() && g.session.is_reusable())
            .unwrap_or(false)
    }

    pub fn active_streams(&self) -> usize {
        self.inner.lock().map(|g| g.waiters.len()).unwrap_or(0)
    }

    /// Execute a request concurrently on this shared HTTP/2 connection.
    /// Multiple threads can invoke this simultaneously and multiplex streams over the same socket.
    pub fn execute_request<H, D, C, K>(
        &self,
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
        let (tx, rx) = mpsc::channel();
        let stream_id = {
            let mut guard = self
                .inner
                .lock()
                .map_err(|_| "SharedH2Session lock poisoned".to_string())?;
            if let Some(ref err) = guard.closed_error {
                return Err(err.clone());
            }
            let sid = guard.session.submit_request(options)?;
            guard.waiters.insert(sid, tx);
            self.wake.notify_all();
            sid
        };

        let mut headers_dispatched = false;
        let mut completed = false;

        while !completed {
            if is_cancelled() {
                if let Ok(mut guard) = self.inner.lock() {
                    guard.waiters.remove(&stream_id);
                    guard.session.active_streams.remove(&stream_id);
                    let _ = guard
                        .session
                        .stream
                        .write_all(&H2Codec::create_rst_stream(stream_id, 0x8));
                    let _ = guard.session.stream.flush();
                }
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

            // Drain any already-dispatched signals for our stream first
            let mut got_signal = false;
            while let Ok(sig) = rx.try_recv() {
                got_signal = true;
                match sig {
                    SharedStreamSignal::Headers {
                        status,
                        reason,
                        headers,
                    } => {
                        on_headers(status, reason, &headers);
                        headers_dispatched = true;
                    }
                    SharedStreamSignal::Data(data) => {
                        if let Some(ring) = body_ring {
                            write_slice_to_ring(ring, &data);
                        }
                        on_data_chunk(&data);
                    }
                    SharedStreamSignal::Complete => {
                        completed = true;
                        break;
                    }
                    SharedStreamSignal::Error(e) => {
                        return Err(e);
                    }
                }
            }
            if completed {
                break;
            }
            if got_signal {
                continue;
            }

            // Drive one read step on the shared H2 session and fan out events to all waiting streams
            let drive_res = {
                let mut guard = self
                    .inner
                    .lock()
                    .map_err(|_| "SharedH2Session lock poisoned".to_string())?;
                // Re-check if another thread already delivered our signals while we waited on the lock
                if !guard.waiters.contains_key(&stream_id) {
                    Ok(false)
                } else {
                    match guard.session.drive_once() {
                        Ok(events) => {
                            let had_events = !events.is_empty();
                            for ev in events {
                                match ev {
                                    H2MuxEvent::Headers {
                                        stream_id: sid,
                                        status,
                                        reason,
                                        headers,
                                    } => {
                                        if let Some(w) = guard.waiters.get(&sid) {
                                            let _ = w.send(SharedStreamSignal::Headers {
                                                status,
                                                reason,
                                                headers,
                                            });
                                        }
                                    }
                                    H2MuxEvent::Data {
                                        stream_id: sid,
                                        data,
                                    } => {
                                        if let Some(w) = guard.waiters.get(&sid) {
                                            let _ = w.send(SharedStreamSignal::Data(data));
                                        }
                                    }
                                    H2MuxEvent::Complete { stream_id: sid } => {
                                        if let Some(w) = guard.waiters.remove(&sid) {
                                            let _ = w.send(SharedStreamSignal::Complete);
                                        }
                                    }
                                    H2MuxEvent::StreamReset {
                                        stream_id: sid,
                                        error_code,
                                    } => {
                                        if let Some(w) = guard.waiters.remove(&sid) {
                                            let _ = w.send(SharedStreamSignal::Error(format!(
                                                "h2 stream reset (error code {})",
                                                error_code
                                            )));
                                        }
                                    }
                                    H2MuxEvent::GoAway { error_code } => {
                                        let msg = format!(
                                            "h2 GOAWAY (error code {})",
                                            error_code
                                        );
                                        guard.closed_error = Some(msg.clone());
                                        for (_, w) in guard.waiters.drain() {
                                            let _ = w.send(SharedStreamSignal::Error(msg.clone()));
                                        }
                                    }
                                }
                            }
                            Ok(had_events)
                        }
                        Err(e) => {
                            guard.closed_error = Some(e.clone());
                            for (_, w) in guard.waiters.drain() {
                                let _ = w.send(SharedStreamSignal::Error(e.clone()));
                            }
                            Err(e)
                        }
                    }
                }
            };

            if let Ok(false) = drive_res {
                std::thread::sleep(Duration::from_millis(1));
            }
        }

        on_complete(true);
        Ok(headers_dispatched)
    }
}

pub struct Http2Client;

impl Http2Client {
    /// Execute an HTTP/2 request with progressive streaming using `h2-sans-io` (zero async runtime).
    pub fn execute_streaming<S, H, D, C, K>(
        stream: S,
        options: &HttpRequestOptions,
        body_ring: Option<&BodyRingDescriptor>,
        on_headers: H,
        on_data_chunk: D,
        on_complete: C,
        is_cancelled: K,
    ) -> Result<bool, String>
    where
        S: Read + Write,
        H: FnMut(u16, &str, &[(String, String)]),
        D: FnMut(&[u8]),
        C: FnMut(bool),
        K: FnMut() -> bool,
    {
        let mut session = H2Session::new(stream)?;
        session.execute_request(
            options,
            body_ring,
            on_headers,
            on_data_chunk,
            on_complete,
            is_cancelled,
        )
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
    fn test_h2_browser_settings_window_update_and_chrome_pseudo_header_order() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind local h2 fingerprint server");
        let addr = listener.local_addr().unwrap();

        let server_thread = std::thread::spawn(move || {
            let (mut conn, _) = listener.accept().expect("accept");
            let mut codec = H2Codec::new();
            let mut dec = HpackDecoder::new();
            let mut enc = HpackEncoder::new();
            let mut buf = [0u8; 4096];

            let mut got_settings = Vec::new();
            let mut got_win_update = 0u32;
            let mut pseudo_order = Vec::new();

            loop {
                let n = conn.read(&mut buf).unwrap_or(0);
                if n == 0 {
                    break;
                }
                let events = codec.process(&buf[..n]).expect("server decode");
                for ev in events {
                    match ev {
                        H2Event::Settings { ack: false, settings } => {
                            got_settings = settings;
                            conn.write_all(&H2Codec::create_settings()).unwrap();
                            conn.write_all(&H2Codec::create_settings_ack()).unwrap();
                            conn.flush().unwrap();
                        }
                        H2Event::WindowUpdate { stream_id: 0, increment } => {
                            got_win_update = increment;
                        }
                        H2Event::Headers { stream_id, header_block, .. } => {
                            let hdrs = dec.decode(&header_block).expect("decode req headers");
                            pseudo_order = hdrs
                                .iter()
                                .take(4)
                                .map(|h| String::from_utf8_lossy(&h.name).to_string())
                                .collect();
                            let block = enc.encode(&[H2Header::new(":status", "200")]);
                            conn.write_all(&H2Codec::create_headers_frame(stream_id, &block, true))
                                .unwrap();
                            conn.flush().unwrap();
                            let _ = conn.shutdown(Shutdown::Write);
                            return (got_settings, got_win_update, pseudo_order);
                        }
                        _ => {}
                    }
                }
            }
            (got_settings, got_win_update, pseudo_order)
        });

        let client_tcp = TcpStream::connect(addr).expect("connect");
        let opts = HttpRequestOptions::new("GET", &format!("https://{}/fp", addr));
        Http2Client::execute_streaming(
            client_tcp,
            &opts,
            None,
            |status, _, _| assert_eq!(status, 200),
            |_| {},
            |_| {},
            || false,
        )
        .expect("h2 request");

        let (settings, win_update, pseudo_order) = server_thread.join().expect("server join");
        assert_eq!(settings, browser_settings_pairs(H2FingerprintProfile::Chrome).to_vec());
        assert_eq!(win_update, 15_663_105);
        assert_eq!(
            pseudo_order,
            vec![":method", ":authority", ":scheme", ":path"]
        );
    }

    #[test]
    fn test_h2_concurrent_multiplexed_streams_on_same_session() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind local h2 mux server");
        let addr = listener.local_addr().unwrap();

        let server_thread = std::thread::spawn(move || {
            let (mut conn, _) = listener.accept().expect("accept");
            let mut codec = H2Codec::new();
            let mut dec = HpackDecoder::new();
            let mut enc = HpackEncoder::new();
            let mut buf = [0u8; 8192];
            let mut received_streams: Vec<(u32, String)> = Vec::new();

            // Wait until BOTH concurrent streams arrive before replying in reverse order (interleaved!)
            while received_streams.len() < 2 {
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
                        let hdrs = dec.decode(&header_block).expect("decode");
                        let path = hdrs
                            .iter()
                            .find(|h| h.name == b":path")
                            .map(|h| String::from_utf8_lossy(&h.value).to_string())
                            .unwrap_or_default();
                        received_streams.push((stream_id, path));
                    }
                }
            }

            assert_eq!(received_streams.len(), 2);
            // Interleave responses for both streams simultaneously
            for &(sid, _) in received_streams.iter().rev() {
                let block = enc.encode(&[H2Header::new(":status", "200")]);
                conn.write_all(&H2Codec::create_headers_frame(sid, &block, false))
                    .unwrap();
            }
            for (sid, path) in received_streams.iter().rev() {
                let payload = format!("resp:{}:{}", sid, path);
                for f in H2Codec::create_data_frames(*sid, payload.as_bytes(), true, 16384) {
                    conn.write_all(&f).unwrap();
                }
            }
            conn.flush().unwrap();
            let _ = conn.shutdown(Shutdown::Write);
            while conn.read(&mut buf).unwrap_or(0) > 0 {}
        });

        let client_tcp = TcpStream::connect(addr).expect("connect");
        client_tcp
            .set_read_timeout(Some(Duration::from_millis(10)))
            .unwrap();
        let session = H2Session::new(client_tcp).expect("H2Session::new");
        let shared = SharedH2Session::new(session);

        let shared_a = shared.clone();
        let url_a = format!("http://{}/alpha", addr);
        let t1 = std::thread::spawn(move || {
            let opts = HttpRequestOptions::new("GET", &url_a);
            let mut body = Vec::new();
            shared_a
                .execute_request(
                    &opts,
                    None,
                    |status, _, _| assert_eq!(status, 200),
                    |c| body.extend_from_slice(c),
                    |_| {},
                    || false,
                )
                .expect("stream alpha");
            String::from_utf8(body).unwrap()
        });

        let shared_b = shared.clone();
        let url_b = format!("http://{}/beta", addr);
        let t2 = std::thread::spawn(move || {
            let opts = HttpRequestOptions::new("GET", &url_b);
            let mut body = Vec::new();
            shared_b
                .execute_request(
                    &opts,
                    None,
                    |status, _, _| assert_eq!(status, 200),
                    |c| body.extend_from_slice(c),
                    |_| {},
                    || false,
                )
                .expect("stream beta");
            String::from_utf8(body).unwrap()
        });

        let r1 = t1.join().expect("t1 join");
        let r2 = t2.join().expect("t2 join");
        drop(shared);
        server_thread.join().expect("server join");

        assert!(r1.ends_with(":/alpha"), "unexpected r1: {}", r1);
        assert!(r2.ends_with(":/beta"), "unexpected r2: {}", r2);
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

    #[test]
    fn test_h2_session_reuse_multiple_streams() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind local h2 reuse server");
        let addr = listener.local_addr().unwrap();

        let server_thread = std::thread::spawn(move || {
            let (mut conn, _) = listener.accept().expect("accept");
            let mut codec = H2Codec::new();
            let mut enc = HpackEncoder::new();
            let mut buf = [0u8; 4096];
            let mut handled = 0;

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
                        handled += 1;
                        let resp_hdrs = vec![
                            H2Header::new(":status", "200"),
                            H2Header::new("content-type", "text/plain"),
                        ];
                        let block = enc.encode(&resp_hdrs);
                        conn.write_all(&H2Codec::create_headers_frame(stream_id, &block, false))
                            .unwrap();
                        let payload = format!("stream-{}", stream_id);
                        for f in H2Codec::create_data_frames(stream_id, payload.as_bytes(), true, 16384) {
                            conn.write_all(&f).unwrap();
                        }
                        conn.flush().unwrap();
                        if handled == 2 {
                            let _ = conn.shutdown(Shutdown::Write);
                            while conn.read(&mut buf).unwrap_or(0) > 0 {}
                            return;
                        }
                    }
                }
            }
        });

        let client_tcp = TcpStream::connect(addr).expect("connect");
        let mut session = H2Session::new(client_tcp).expect("H2Session::new");
        assert_eq!(session.next_stream_id, 1);

        let mut body1 = Vec::new();
        let opts1 = HttpRequestOptions::new("GET", &format!("http://{}/one", addr));
        session
            .execute_request(
                &opts1,
                None,
                |status, _, _| assert_eq!(status, 200),
                |c| body1.extend_from_slice(c),
                |_| {},
                || false,
            )
            .expect("first h2 stream");
        assert_eq!(body1, b"stream-1");
        assert_eq!(session.next_stream_id, 3);
        assert!(session.is_reusable());

        let mut body2 = Vec::new();
        let opts2 = HttpRequestOptions::new("GET", &format!("http://{}/two", addr));
        session
            .execute_request(
                &opts2,
                None,
                |status, _, _| assert_eq!(status, 200),
                |c| body2.extend_from_slice(c),
                |_| {},
                || false,
            )
            .expect("second reused h2 stream");
        assert_eq!(body2, b"stream-3");
        assert_eq!(session.next_stream_id, 5);

        drop(session);
        server_thread.join().expect("server join");
    }
}
