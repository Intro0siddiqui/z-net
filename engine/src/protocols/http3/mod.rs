//! HTTP/3 client protocol implementation over QUIC (RFC 9114).
//!
//! Provides progressive streaming, QPACK encoding/decoding, and
//! fast-failing Happy Eyeballs fallback to TCP TLS.

pub mod qpack;

use std::io::ErrorKind;
use std::net::UdpSocket;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::protocols::http::client::HttpRequestOptions;
use crate::BodyRingDescriptor;
use qpack::QpackCodec;

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

/// Build the RFC 9114 §6.2.1 HTTP/3 client control stream initialization bytes:
/// unidirectional stream type `0x00` (Control Stream) followed by a `SETTINGS` frame (`0x04`).
pub fn build_control_stream_init() -> Vec<u8> {
    let mut buf = Vec::with_capacity(4);
    encode_varint(0x00, &mut buf);
    buf.extend_from_slice(&build_http3_frame(0x04, &[]));
    buf
}

pub struct QuicHandshakeState {
    pub endpoint: quinn_proto::Endpoint,
    pub ch: quinn_proto::ConnectionHandle,
    pub connection: quinn_proto::Connection,
    pub tx_buf: Vec<u8>,
    pub rx_buf: [u8; 4096],
}

impl QuicHandshakeState {
    /// Bind a non-blocking UDP socket and initiate a QUIC handshake to `server_addr` with SNI `sni_host`.
    pub fn start(server_addr: std::net::SocketAddr, sni_host: &str) -> Result<(Self, UdpSocket), String> {
        let bind_addr = if server_addr.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        };
        let socket = UdpSocket::bind(bind_addr)
            .map_err(|e| format!("UDP bind failed: {}", e))?;
        socket
            .set_nonblocking(true)
            .map_err(|e| format!("Failed to set nonblocking UDP: {}", e))?;

        let endpoint_config = Arc::new(quinn_proto::EndpointConfig::default());
        let mut endpoint = quinn_proto::Endpoint::new(endpoint_config, None, false, None);

        let provider = Arc::new(quinn_proto::rustls::crypto::ring::default_provider());
        let roots = crate::root_store();
        let mut rustls_client_config =
            quinn_proto::rustls::ClientConfig::builder_with_provider(provider)
                .with_protocol_versions(&[&quinn_proto::rustls::version::TLS13])
                .map_err(|e| format!("TLS 1.3 config failed: {}", e))?
                .with_root_certificates(roots)
                .with_no_client_auth();

        rustls_client_config.alpn_protocols = vec![b"h3".to_vec()];

        let quic_crypto =
            quinn_proto::crypto::rustls::QuicClientConfig::try_from(Arc::new(rustls_client_config))
                .map_err(|e| format!("QuicClientConfig failed: {:?}", e))?;

        let mut transport = quinn_proto::TransportConfig::default();
        transport.max_idle_timeout(quinn_proto::IdleTimeout::try_from(Duration::from_secs(30)).ok());
        let mut client_config = quinn_proto::ClientConfig::new(Arc::new(quic_crypto));
        client_config.transport_config(Arc::new(transport));

        let start_time = Instant::now();
        let (ch, connection) = endpoint
            .connect(start_time, client_config, server_addr, sni_host)
            .map_err(|e| format!("QUIC connect error: {:?}", e))?;

        Ok((
            Self {
                endpoint,
                ch,
                connection,
                tx_buf: Vec::new(),
                rx_buf: [0u8; 4096],
            },
            socket,
        ))
    }

    /// Flush all pending QUIC transmits to `socket`.
    pub fn flush_transmits(&mut self, socket: &UdpSocket, now: Instant) {
        while let Some(transmit) = self.connection.poll_transmit(now, 1, &mut self.tx_buf) {
            let _ = socket.send_to(&self.tx_buf[..transmit.size], transmit.destination);
            self.tx_buf.clear();
        }
    }

    /// Drain all currently readable UDP datagrams from `socket` into the QUIC endpoint/connection.
    pub fn drain_udp(&mut self, socket: &UdpSocket, now: Instant) -> Result<(), String> {
        loop {
            match socket.recv_from(&mut self.rx_buf) {
                Ok((n, remote)) => {
                    let data = bytes::BytesMut::from(&self.rx_buf[..n]);
                    let event = self.endpoint.handle(now, remote, None, None, data, &mut self.tx_buf);
                    if let Some(quinn_proto::DatagramEvent::ConnectionEvent(h, conn_event)) = event {
                        if h == self.ch {
                            let _ = self.connection.handle_event(conn_event);
                        }
                    }
                }
                Err(ref e) if e.kind() == ErrorKind::WouldBlock => break,
                Err(e) => return Err(format!("UDP socket error: {}", e)),
            }
        }
        Ok(())
    }

    /// Advance QUIC timers and events. Returns `Ok(true)` if handshake is complete,
    /// `Ok(false)` if still handshaking, or `Err` if closed/drained.
    pub fn poll_handshake_step(&mut self, now: Instant) -> Result<bool, String> {
        if let Some(timeout) = self.connection.poll_timeout() {
            if timeout <= now {
                self.connection.handle_timeout(now);
            }
        }

        let mut handshake_err: Option<String> = None;
        while let Some(ev) = self.connection.poll() {
            if let quinn_proto::Event::ConnectionLost { reason } = ev {
                handshake_err = Some(format!("{:?}", reason));
            }
        }

        if self.connection.is_closed() || self.connection.is_drained() {
            return Err(format!(
                "QUIC connection closed during handshake (reason={:?})",
                handshake_err
            ));
        }

        Ok(!self.connection.is_handshaking())
    }
}

pub struct Http3Client;

impl Http3Client {
    /// Attempt HTTP/3 request execution with progressive chunk streaming.
    ///
    /// If the QUIC handshake fails or takes longer than `handshake_timeout`
    /// (e.g. UDP blocked or packet dropped), returns `Err` quickly so the
    /// caller can fall back to TCP TLS without user-visible stalling.
    pub fn execute_streaming<H, D, C, K>(
        host: &str,
        port: u16,
        dns_resolver: &crate::protocols::dns::DnsResolver,
        options: &HttpRequestOptions,
        body_ring: Option<&BodyRingDescriptor>,
        on_headers: H,
        on_data_chunk: D,
        on_complete: C,
        mut is_cancelled: K,
        handshake_timeout: Duration,
    ) -> Result<bool, String>
    where
        H: FnMut(u16, &str, &[(String, String)]),
        D: FnMut(&[u8]),
        C: FnMut(bool),
        K: FnMut() -> bool,
    {
        let addrs = dns_resolver.resolve(host, port)?;
        let server_addr = addrs
            .into_iter()
            .find(|a| a.is_ipv4())
            .ok_or_else(|| format!("No IPv4 address found for {}:{}", host, port))?;

        let (mut state, socket) = QuicHandshakeState::start(server_addr, host)?;
        let start_time = Instant::now();
        let handshake_deadline = start_time + handshake_timeout;

        while state.connection.is_handshaking() {
            if is_cancelled() {
                return Err("Request cancelled during QUIC handshake".to_string());
            }
            let now = Instant::now();
            if now > handshake_deadline {
                return Err("QUIC handshake timed out (falling back to TCP)".to_string());
            }

            state.flush_transmits(&socket, now);
            state.drain_udp(&socket, now)?;
            if state.poll_handshake_step(now)? {
                break;
            }
            std::thread::sleep(Duration::from_millis(2));
        }

        Self::execute_connected_streaming(
            state,
            socket,
            host,
            options,
            body_ring,
            on_headers,
            on_data_chunk,
            on_complete,
            is_cancelled,
        )
    }

    /// Execute an HTTP/3 request over an already-handshaken `QuicHandshakeState` and `UdpSocket`.
    #[allow(clippy::too_many_arguments)]
    pub fn execute_connected_streaming<H, D, C, K>(
        mut state: QuicHandshakeState,
        socket: UdpSocket,
        host: &str,
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
        let QuicHandshakeState {
            ref mut endpoint,
            ch,
            ref mut connection,
            ref mut tx_buf,
            ref mut rx_buf,
        } = state;

        // 2. Open mandatory RFC 9114 §6.2.1 unidirectional control stream (0x00) and send SETTINGS (0x04).
        // Kept open for the lifetime of the connection (must NOT call send.finish()).
        let ctrl_stream_id = connection
            .streams()
            .open(quinn_proto::Dir::Uni)
            .ok_or("Failed to open QUIC unidirectional control stream".to_string())?;
        {
            let ctrl_init = build_control_stream_init();
            let mut ctrl_send = connection.send_stream(ctrl_stream_id);
            let _ = ctrl_send.write(&ctrl_init);
        }

        // 3. Open bidirectional request stream
        let stream_id = connection.streams().open(quinn_proto::Dir::Bi)
            .ok_or("Failed to open QUIC bidirectional stream".to_string())?;

        let url = url::Url::parse(&options.url)
            .map_err(|e| format!("Invalid URL: {}", e))?;
        let mut path_and_query = url.path().to_string();
        if let Some(q) = url.query() {
            path_and_query.push('?');
            path_and_query.push_str(q);
        }
        if path_and_query.is_empty() {
            path_and_query = "/".to_string();
        }

        // QPACK encode headers
        let qpack_hdr = QpackCodec::encode_headers(
            &options.method,
            url.scheme(),
            host,
            &path_and_query,
            &options.headers,
        );
        let headers_frame = build_http3_frame(0x01, &qpack_hdr);

        {
            let mut send = connection.send_stream(stream_id);
            let _ = send.write(&headers_frame);
            if let Some(ref body) = options.body {
                let data_frame = build_http3_frame(0x00, body);
                let _ = send.write(&data_frame);
            }
            let _ = send.finish();
        }

        // Transmit request frames immediately
        let now = Instant::now();
        while let Some(transmit) = connection.poll_transmit(now, 1, tx_buf) {
            let _ = socket.send_to(&tx_buf[..transmit.size], transmit.destination);
            tx_buf.clear();
        }

        // 3. Receive Response Loop (Frames: HEADERS 0x01, DATA 0x00)
        let mut stream_buffer = Vec::new();
        let mut headers_dispatched = false;
        let mut stream_finished = false;
        let mut last_conn_err: Option<String> = None;
        let request_deadline = Instant::now() + options.timeout;

        while !stream_finished {
            if is_cancelled() {
                return Err("Request cancelled".to_string());
            }
            let now = Instant::now();
            if now > request_deadline {
                return Err("HTTP/3 request timed out".to_string());
            }

            // Flush transmits
            while let Some(transmit) = connection.poll_transmit(now, 1, tx_buf) {
                let _ = socket.send_to(&tx_buf[..transmit.size], transmit.destination);
                tx_buf.clear();
            }

            // Read UDP socket
            match socket.recv_from(rx_buf) {
                Ok((n, remote)) => {
                    let data = bytes::BytesMut::from(&rx_buf[..n]);
                    let event = endpoint.handle(now, remote, None, None, data, tx_buf);
                    if let Some(quinn_proto::DatagramEvent::ConnectionEvent(h, conn_event)) = event {
                        if h == ch {
                            let _ = connection.handle_event(conn_event);
                        }
                    }
                }
                Err(ref e) if e.kind() == ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(2));
                }
                Err(e) => return Err(format!("UDP read error: {}", e)),
            }

            if let Some(timeout) = connection.poll_timeout() {
                if timeout <= now {
                    connection.handle_timeout(now);
                }
            }

            // Read incoming bytes off the stream
            let mut recv_eof = false;
            {
                let mut recv = connection.recv_stream(stream_id);
                if let Ok(mut chunks) = recv.read(true) {
                    loop {
                        match chunks.next(4096) {
                            Ok(Some(chunk)) => {
                                stream_buffer.extend_from_slice(&chunk.bytes);
                            }
                            Ok(None) => {
                                // QUIC stream FIN received (all response bytes delivered)
                                recv_eof = true;
                                break;
                            }
                            Err(quinn_proto::ReadError::Blocked) => break,
                            Err(quinn_proto::ReadError::Reset(code)) => {
                                if !headers_dispatched {
                                    eprintln!("[ZNET-H3] {} stream reset by peer (code={:?})", options.url, code);
                                }
                                recv_eof = true;
                                break;
                            }
                        }
                    }
                    let _ = chunks.finalize();
                };
            }

            // Process HTTP/3 frames from stream_buffer
            let mut pos = 0;
            while pos < stream_buffer.len() {
                let slice = &stream_buffer[pos..];
                let (frame_type, type_len) = match decode_varint(slice) {
                    Some(v) => v,
                    None => break,
                };
                let (frame_len, len_len) = match decode_varint(&slice[type_len..]) {
                    Some(v) => v,
                    None => break,
                };

                let header_size = type_len + len_len;
                let payload_len = frame_len as usize;
                if slice.len() < header_size + payload_len {
                    // Incomplete frame, wait for more data
                    break;
                }

                let payload = &slice[header_size..header_size + payload_len];

                if frame_type == 0x01 && !headers_dispatched {
                    // HEADERS frame
                    match QpackCodec::decode_response_headers(payload) {
                        Ok((status, headers)) => {
                            on_headers(status, "OK", &headers);
                            headers_dispatched = true;
                        }
                        Err(e) => {
                            eprintln!("[ZNET-H3] {} QPACK header decode failed: {}", options.url, e);
                        }
                    }
                } else if frame_type == 0x00 {
                    // DATA frame
                    if let Some(ring) = body_ring {
                        let mut offset = 0;
                        while offset < payload.len() && !ring.is_closed.load(Ordering::Acquire) {
                            let written = ring.write_slice(&payload[offset..]);
                            offset += written;
                            if offset < payload.len() {
                                ring.wait_drain(5);
                            }
                        }
                    }
                    on_data_chunk(payload);
                }

                pos += header_size + payload_len;
            }

            if pos > 0 {
                stream_buffer.drain(..pos);
            }

            while let Some(ev) = connection.poll() {
                if let quinn_proto::Event::ConnectionLost { reason } = ev {
                    last_conn_err = Some(format!("{:?}", reason));
                }
            }

            if recv_eof {
                stream_finished = true;
            }

            if connection.is_closed() || connection.is_drained() {
                if !headers_dispatched {
                    eprintln!(
                        "[ZNET-H3] {} QUIC closed/drained before headers (closed={}, drained={}, reason={:?})",
                        options.url,
                        connection.is_closed(),
                        connection.is_drained(),
                        last_conn_err
                    );
                }
                stream_finished = true;
            }
        }

        if !headers_dispatched {
            eprintln!("[ZNET-H3] {} falling back to H2 (no headers dispatched)", options.url);
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
        // Stream type 0x00 (Control) + Frame type 0x04 (SETTINGS) + Length 0x00
        assert_eq!(init, vec![0x00, 0x04, 0x00]);
    }
}
