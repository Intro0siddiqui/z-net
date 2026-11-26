//! HTTP/3 client protocol implementation over QUIC (RFC 9114) using sans-I/O `quiche`.
//!
//! Uses `quiche::Connection` + `quiche::h3::Connection` backed by the single shared
//! BoringSSL (`boring`) build, with persistent session resumption and streaming callbacks.

use std::io::ErrorKind;
use std::net::{SocketAddr, UdpSocket};
use std::os::fd::{AsRawFd, RawFd};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant};

use quiche::h3::NameValue;

use crate::protocols::compression::StreamDecompressor;
use crate::protocols::dns::DnsResolver;
use crate::protocols::http::client::HttpRequestOptions;
use crate::protocols::tls::{BoringSessionStore, BoringTlsConfig};
use crate::BodyRingDescriptor;

pub fn encode_varint(val: u64, buf: &mut Vec<u8>) {
    if val < 64 {
        buf.push(val as u8);
    } else if val < 16384 {
        buf.push(0x40 | ((val >> 8) as u8));
        buf.push((val & 0xFF) as u8);
    } else if val < 1073741824 {
        buf.push(0x80 | ((val >> 24) as u8));
        buf.push(((val >> 16) & 0xFF) as u8);
        buf.push(((val >> 8) & 0xFF) as u8);
        buf.push((val & 0xFF) as u8);
    } else {
        buf.push(0xC0 | ((val >> 56) as u8));
        buf.push(((val >> 48) & 0xFF) as u8);
        buf.push(((val >> 40) & 0xFF) as u8);
        buf.push(((val >> 32) & 0xFF) as u8);
        buf.push(((val >> 24) & 0xFF) as u8);
        buf.push(((val >> 16) & 0xFF) as u8);
        buf.push(((val >> 8) & 0xFF) as u8);
        buf.push((val & 0xFF) as u8);
    }
}

pub fn decode_varint(slice: &[u8]) -> Option<(u64, usize)> {
    if slice.is_empty() {
        return None;
    }
    let first = slice[0];
    let prefix = first >> 6;
    let len = match prefix {
        0 => 1,
        1 => 2,
        2 => 4,
        3 => 8,
        _ => unreachable!(),
    };
    if slice.len() < len {
        return None;
    }
    let mut val = (first & 0x3F) as u64;
    for &b in &slice[1..len] {
        val = (val << 8) | (b as u64);
    }
    Some((val, len))
}

pub fn build_http3_frame(frame_type: u64, payload: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(16 + payload.len());
    encode_varint(frame_type, &mut buf);
    encode_varint(payload.len() as u64, &mut buf);
    buf.extend_from_slice(payload);
    buf
}

/// Build RFC 9114 §6.2.1 HTTP/3 client control stream initialization bytes:
/// stream type `0x00` + `SETTINGS` frame (`0x04`).
pub fn build_control_stream_init() -> Vec<u8> {
    let mut buf = Vec::with_capacity(32);
    encode_varint(0x00, &mut buf);
    let mut settings_payload = Vec::with_capacity(24);
    encode_varint(0x01, &mut settings_payload);
    encode_varint(65536, &mut settings_payload);
    encode_varint(0x06, &mut settings_payload);
    encode_varint(262144, &mut settings_payload);
    encode_varint(0x07, &mut settings_payload);
    encode_varint(100, &mut settings_payload);
    encode_varint(0x537, &mut settings_payload);
    encode_varint(1, &mut settings_payload);
    buf.extend_from_slice(&build_http3_frame(0x04, &settings_payload));
    buf
}

fn generate_scid() -> quiche::ConnectionId<'static> {
    let mut bytes = [0u8; quiche::MAX_CONN_ID_LEN];
    crate::protocols::tls::random_bytes(&mut bytes);
    quiche::ConnectionId::from_vec(bytes.to_vec())
}

/// Non-blocking QUIC handshake state driven by `compio-driver::Proactor` during HEv3 races.
pub struct QuicHandshakeState {
    pub socket: UdpSocket,
    conn: quiche::Connection,
    pub local_addr: SocketAddr,
    pub peer_addr: SocketAddr,
    pub host: String,
    pub session_store: Arc<BoringSessionStore>,
}

impl QuicHandshakeState {
    pub fn timeout(&self) -> Option<std::time::Duration> {
        self.conn.timeout()
    }

    pub fn start(
        host: &str,
        port: u16,
        dns_resolver: &DnsResolver,
        boring_tls: &BoringTlsConfig,
    ) -> Result<Self, String> {
        let addrs = dns_resolver.resolve(host, port)?;
        let server_addr = addrs
            .into_iter()
            .next()
            .ok_or_else(|| format!("No address found for {}:{}", host, port))?;

        let bind_addr = if server_addr.is_ipv6() {
            "[::]:0"
        } else {
            "0.0.0.0:0"
        };
        let socket = UdpSocket::bind(bind_addr).map_err(|e| format!("UDP bind failed: {}", e))?;
        socket
            .set_nonblocking(true)
            .map_err(|e| format!("Failed to set nonblocking UDP: {}", e))?;
        Self::connect_with_socket(socket, server_addr, host, boring_tls)
    }

    pub fn connect_with_socket(
        socket: UdpSocket,
        server_addr: SocketAddr,
        host: &str,
        boring_tls: &BoringTlsConfig,
    ) -> Result<Self, String> {
        let local_addr = socket
            .local_addr()
            .map_err(|e| format!("UDP local_addr failed: {}", e))?;

        let mut config = boring_tls.build_quiche_config()?;
        let scid = generate_scid();
        let mut conn = quiche::connect(Some(host), &scid, local_addr, server_addr, &mut config)
            .map_err(|e| format!("quiche::connect failed: {:?}", e))?;

        // Attempt 0-RTT / 1-RTT session resumption if a persisted ticket exists
        if let Some(ticket) = boring_tls
            .session_store
            .get(&format!("h3:{}:{}", host, server_addr.port()))
        {
            let _ = conn.set_session(&ticket);
        }

        let mut state = Self {
            socket,
            conn,
            local_addr,
            peer_addr: server_addr,
            host: host.to_string(),
            session_store: boring_tls.session_store.clone(),
        };
        state.flush_transmits();
        Ok(state)
    }

    pub fn drive_nonblocking(&mut self) -> i32 {
        let mut processed = 0;
        let mut rx_buf = [0u8; 4096];
        loop {
            match self.socket.recv_from(&mut rx_buf) {
                Ok((len, from)) => {
                    let recv_info = quiche::RecvInfo {
                        from,
                        to: self.local_addr,
                    };
                    let _ = self.conn.recv(&mut rx_buf[..len], recv_info);
                    processed += 1;
                }
                Err(ref e) if e.kind() == ErrorKind::WouldBlock => break,
                Err(_) => break,
            }
        }
        if let Some(timeout) = self.conn.timeout() {
            if timeout.is_zero() {
                self.conn.on_timeout();
            }
        }
        self.flush_transmits();
        processed
    }

    pub fn close_gracefully(&mut self) {
        let _ = self.conn.close(false, 0, b"client closed");
        self.flush_transmits();
    }

    pub fn migrate_socket(&mut self, new_socket: UdpSocket, new_local: SocketAddr) {
        self.socket = new_socket;
        self.local_addr = new_local;
    }

    pub fn raw_fd(&self) -> RawFd {
        self.socket.as_raw_fd()
    }

    pub fn flush_transmits(&mut self) {
        let mut out = [0u8; 1350];
        loop {
            match self.conn.send(&mut out) {
                Ok((write, send_info)) => {
                    let _ = self.socket.send_to(&out[..write], send_info.to);
                }
                Err(quiche::Error::Done) => break,
                Err(_) => break,
            }
        }
    }

    /// Drain incoming UDP packets and advance handshake state. Returns `Ok(true)` once established.
    pub fn poll_recv_and_advance(&mut self) -> Result<bool, String> {
        let mut rx_buf = [0u8; 4096];
        loop {
            match self.socket.recv_from(&mut rx_buf) {
                Ok((len, from)) => {
                    let recv_info = quiche::RecvInfo {
                        from,
                        to: self.local_addr,
                    };
                    let _ = self.conn.recv(&mut rx_buf[..len], recv_info);
                }
                Err(ref e) if e.kind() == ErrorKind::WouldBlock => break,
                Err(e) => return Err(format!("UDP socket error: {}", e)),
            }
        }

        if let Some(timeout) = self.conn.timeout() {
            if timeout.is_zero() {
                self.conn.on_timeout();
            }
        }

        self.flush_transmits();

        if self.conn.is_closed() {
            return Err("QUIC connection closed during handshake".to_string());
        }

        Ok(self.conn.is_established() || self.conn.is_in_early_data())
    }

    pub fn is_failed(&self) -> bool {
        self.conn.is_closed()
    }
}

pub struct Http3Client;

impl Http3Client {
    /// Execute an HTTP/3 request over an already-established `QuicHandshakeState` using `quiche::h3`.
    pub fn execute_connected_streaming<H, D, C, K>(
        mut state: QuicHandshakeState,
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
        // Persist any new session ticket for future 0-RTT/1-RTT resumption
        if let Some(session_bytes) = state.conn.session() {
            state.session_store.insert(
                &format!("h3:{}:{}", state.host, state.peer_addr.port()),
                session_bytes.to_vec(),
            );
        }

        let mut h3_config = quiche::h3::Config::new()
            .map_err(|e| format!("quiche::h3::Config failed: {:?}", e))?;
        h3_config.set_qpack_max_table_capacity(65536);
        h3_config.set_qpack_blocked_streams(100);
        h3_config.set_max_field_section_size(262144);

        let mut h3_conn = quiche::h3::Connection::with_transport(&mut state.conn, &h3_config)
            .map_err(|e| format!("quiche::h3::Connection failed: {:?}", e))?;

        let url = url::Url::parse(&options.url).map_err(|e| format!("Invalid URL: {}", e))?;
        let mut path_and_query = url.path().to_string();
        if let Some(q) = url.query() {
            path_and_query.push('?');
            path_and_query.push_str(q);
        }
        if path_and_query.is_empty() {
            path_and_query = "/".to_string();
        }

        let authority = match url.port() {
            Some(p) => format!("{}:{}", state.host, p),
            None => state.host.clone(),
        };

        let mut h3_headers = Vec::with_capacity(4 + options.headers.len());
        h3_headers.push(quiche::h3::Header::new(b":method", options.method.as_bytes()));
        h3_headers.push(quiche::h3::Header::new(b":scheme", url.scheme().as_bytes()));
        h3_headers.push(quiche::h3::Header::new(b":authority", authority.as_bytes()));
        h3_headers.push(quiche::h3::Header::new(b":path", path_and_query.as_bytes()));
        for (k, v) in &options.headers {
            h3_headers.push(quiche::h3::Header::new(
                k.to_ascii_lowercase().as_bytes(),
                v.as_bytes(),
            ));
        }

        let has_body = options.body.as_ref().map_or(false, |b| !b.is_empty());
        let req_stream_id = h3_conn
            .send_request(&mut state.conn, &h3_headers, !has_body)
            .map_err(|e| format!("quiche::h3 send_request failed: {:?}", e))?;

        if let Some(ref body) = options.body {
            if !body.is_empty() {
                let _ = h3_conn.send_body(&mut state.conn, req_stream_id, body, true);
            }
        }
        state.flush_transmits();

        let has_range_header = options.headers.iter().any(|(k, _)| k.eq_ignore_ascii_case("range"));
        let mut decompressor: Option<StreamDecompressor> = None;
        let mut headers_dispatched = false;
        let mut stream_finished = false;
        let mut rx_buf = [0u8; 4096];
        let request_deadline = Instant::now() + options.timeout;

        while !stream_finished {
            if is_cancelled() {
                return Err("Request cancelled".to_string());
            }
            if Instant::now() > request_deadline {
                return Err("HTTP/3 request timed out".to_string());
            }

            if let Some(ring) = body_ring {
                while ring.should_stop_reading() && !ring.is_closed.load(Ordering::Acquire) {
                    if is_cancelled() {
                        return Err("Request cancelled".to_string());
                    }
                    ring.wait_drain(5);
                }
            }

            let mut got_packet = false;
            loop {
                match state.socket.recv_from(&mut rx_buf) {
                    Ok((len, from)) => {
                        got_packet = true;
                        let recv_info = quiche::RecvInfo {
                            from,
                            to: state.local_addr,
                        };
                        let _ = state.conn.recv(&mut rx_buf[..len], recv_info);
                    }
                    Err(ref e) if e.kind() == ErrorKind::WouldBlock => break,
                    Err(e) => return Err(format!("UDP receive error: {}", e)),
                }
            }

            loop {
                match h3_conn.poll(&mut state.conn) {
                    Ok((sid, quiche::h3::Event::Headers { list, .. })) if sid == req_stream_id => {
                        let mut status: u16 = 200;
                        let mut headers_vec = Vec::with_capacity(list.len());
                        for hdr in list {
                            let name = String::from_utf8_lossy(hdr.name()).to_string();
                            let value = String::from_utf8_lossy(hdr.value()).to_string();
                            if name == ":status" {
                                status = value.parse::<u16>().unwrap_or(200);
                            } else if !name.starts_with(':') {
                                headers_vec.push((name, value));
                            }
                        }

                        if !headers_dispatched {
                            let should_decompress =
                                options.transparent_decompression && !has_range_header && status != 206;
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
                                headers_vec.retain(|(k, _)| {
                                    !k.eq_ignore_ascii_case("content-encoding")
                                        && !k.eq_ignore_ascii_case("content-length")
                                });
                            }
                            on_headers(status, "", &headers_vec);
                            headers_dispatched = true;
                        }
                    }
                    Ok((sid, quiche::h3::Event::Data)) if sid == req_stream_id => {
                        let mut body_buf = [0u8; 8192];
                        while let Ok(read) = h3_conn.recv_body(&mut state.conn, sid, &mut body_buf) {
                            if read == 0 {
                                break;
                            }
                            let chunk = &body_buf[..read];
                            if let Some(ref mut dec) = decompressor {
                                dec.feed(chunk, |decompressed| {
                                    if let Some(ring) = body_ring {
                                        let mut offset = 0;
                                        while offset < decompressed.len()
                                            && !ring.is_closed.load(Ordering::Acquire)
                                        {
                                            let written = ring.write_slice(&decompressed[offset..]);
                                            offset += written;
                                            if offset < decompressed.len() {
                                                ring.wait_drain(5);
                                            }
                                        }
                                    }
                                    on_data_chunk(decompressed);
                                })?;
                            } else {
                                if let Some(ring) = body_ring {
                                    let mut offset = 0;
                                    while offset < chunk.len()
                                        && !ring.is_closed.load(Ordering::Acquire)
                                    {
                                        let written = ring.write_slice(&chunk[offset..]);
                                        offset += written;
                                        if offset < chunk.len() {
                                            ring.wait_drain(5);
                                        }
                                    }
                                }
                                on_data_chunk(chunk);
                            }
                        }
                    }
                    Ok((sid, quiche::h3::Event::Finished)) if sid == req_stream_id => {
                        stream_finished = true;
                        break;
                    }
                    Ok((sid, quiche::h3::Event::Reset(_))) if sid == req_stream_id => {
                        return Err("HTTP/3 stream reset by peer".to_string());
                    }
                    Ok((_, quiche::h3::Event::GoAway)) => {
                        stream_finished = true;
                        break;
                    }
                    Ok(_) => {}
                    Err(quiche::h3::Error::Done) => break,
                    Err(e) => return Err(format!("quiche::h3 poll error: {:?}", e)),
                }
            }

            if let Some(timeout) = state.conn.timeout() {
                if timeout.is_zero() {
                    state.conn.on_timeout();
                }
            }
            state.flush_transmits();

            if state.conn.is_closed() && !stream_finished {
                if !headers_dispatched {
                    return Err("HTTP/3 connection closed before response headers".to_string());
                }
                stream_finished = true;
            } else if !got_packet && !stream_finished {
                std::thread::sleep(Duration::from_millis(2));
            }
        }

        if let Some(dec) = decompressor.take() {
            dec.finish(|decompressed| {
                if let Some(ring) = body_ring {
                    ring.write_slice(decompressed);
                }
                on_data_chunk(decompressed);
            })?;
        }

        if !headers_dispatched {
            return Err("HTTP/3 stream closed before response headers were received".to_string());
        }
        on_complete(false);
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_varint_roundtrip() {
        let test_values = [0, 1, 25, 63, 64, 16383, 16384, 1073741823, 1073741824, 4611686018427387903];
        for &val in &test_values {
            let mut buf = Vec::new();
            encode_varint(val, &mut buf);
            let (decoded, len) = decode_varint(&buf).expect("decode");
            assert_eq!(decoded, val);
            assert_eq!(len, buf.len());
        }
    }

    #[test]
    fn test_build_http3_frame() {
        let payload = b"hello http3";
        let frame = build_http3_frame(0x00, payload);
        let (ftype, tlen) = decode_varint(&frame).unwrap();
        assert_eq!(ftype, 0x00);
        let (flen, llen) = decode_varint(&frame[tlen..]).unwrap();
        assert_eq!(flen, payload.len() as u64);
        assert_eq!(&frame[tlen + llen..], payload);
    }

    #[test]
    fn test_build_control_stream_init() {
        let init = build_control_stream_init();
        assert!(init.len() > 3);
        let (stream_type, tlen) = decode_varint(&init).unwrap();
        assert_eq!(stream_type, 0x00);
        let (frame_type, flen) = decode_varint(&init[tlen..]).unwrap();
        assert_eq!(frame_type, 0x04);
        let (payload_len, plen) = decode_varint(&init[tlen + flen..]).unwrap();
        assert_eq!(payload_len as usize, init.len() - (tlen + flen + plen));
    }

    #[test]
    fn test_build_quiche_config_with_boring_tls() {
        let store = Arc::new(BoringSessionStore::in_memory());
        let boring_tls = BoringTlsConfig::new(
            crate::protocols::tls::TlsFingerprintProfile::Chrome,
            store,
        )
        .expect("boring tls init");
        assert!(boring_tls.build_quiche_config().is_ok());
    }
}
