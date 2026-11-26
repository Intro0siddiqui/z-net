//! HTTP/3 client protocol implementation over QUIC (RFC 9114).
//!
//! Provides progressive streaming, populated browser-like SETTINGS (with GREASE),
//! RFC 9204 QPACK dynamic table + Huffman encoding with unidirectional encoder/decoder
//! streams (`0x02`/`0x03`), shared `QuicClientConfig` with 0-RTT early data, and
//! fast-failing Happy Eyeballs fallback to TCP TLS.

pub mod qpack;

use std::collections::HashMap;
use std::io::ErrorKind;
use std::net::UdpSocket;
use std::sync::atomic::Ordering;
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use crate::protocols::compression::StreamDecompressor;
use crate::protocols::http::client::HttpRequestOptions;
use crate::protocols::tls::PersistentRustlsSessionStore;
use crate::BodyRingDescriptor;
use qpack::{QpackDecodeOutcome, QpackDecoder, QpackEncoder};

/// RFC 9114 / RFC 9204 HTTP/3 SETTINGS identifiers.
pub const SETTINGS_QPACK_MAX_TABLE_CAPACITY: u64 = 0x01;
pub const SETTINGS_MAX_FIELD_SECTION_SIZE: u64 = 0x06;
pub const SETTINGS_QPACK_BLOCKED_STREAMS: u64 = 0x07;
/// RFC 9114 §7.2.4.1 GREASE setting ID (`0x1f * N + 0x21`, here N = 42 => `0x537`).
pub const SETTINGS_GREASE_ID: u64 = 0x1f * 42 + 0x21;

pub const DEFAULT_QPACK_MAX_TABLE_CAPACITY: u64 = 65_536;
pub const DEFAULT_MAX_FIELD_SECTION_SIZE: u64 = 262_144;
pub const DEFAULT_QPACK_BLOCKED_STREAMS: u64 = 100;

/// RFC 9114 / RFC 9204 unidirectional stream type identifiers.
pub const H3_STREAM_TYPE_CONTROL: u64 = 0x00;
pub const H3_STREAM_TYPE_QPACK_ENCODER: u64 = 0x02;
pub const H3_STREAM_TYPE_QPACK_DECODER: u64 = 0x03;

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
/// unidirectional stream type `0x00` (Control Stream) followed by a populated
/// `SETTINGS` frame (`0x04`) containing `QPACK_MAX_TABLE_CAPACITY`,
/// `QPACK_BLOCKED_STREAMS`, `MAX_FIELD_SECTION_SIZE`, and a GREASE setting ID.
pub fn build_control_stream_init() -> Vec<u8> {
    let mut settings_payload = Vec::with_capacity(32);
    let settings = [
        (SETTINGS_QPACK_MAX_TABLE_CAPACITY, DEFAULT_QPACK_MAX_TABLE_CAPACITY),
        (SETTINGS_MAX_FIELD_SECTION_SIZE, DEFAULT_MAX_FIELD_SECTION_SIZE),
        (SETTINGS_QPACK_BLOCKED_STREAMS, DEFAULT_QPACK_BLOCKED_STREAMS),
        (SETTINGS_GREASE_ID, 0),
    ];
    for (id, val) in settings {
        encode_varint(id, &mut settings_payload);
        encode_varint(val, &mut settings_payload);
    }

    let mut buf = Vec::with_capacity(16 + settings_payload.len());
    encode_varint(H3_STREAM_TYPE_CONTROL, &mut buf);
    buf.extend_from_slice(&build_http3_frame(0x04, &settings_payload));
    buf
}

/// Build the unidirectional QPACK Encoder stream (`0x02`) header.
pub fn build_qpack_encoder_stream_init() -> Vec<u8> {
    let mut buf = Vec::with_capacity(2);
    encode_varint(H3_STREAM_TYPE_QPACK_ENCODER, &mut buf);
    buf
}

/// Build the unidirectional QPACK Decoder stream (`0x03`) header.
pub fn build_qpack_decoder_stream_init() -> Vec<u8> {
    let mut buf = Vec::with_capacity(2);
    encode_varint(H3_STREAM_TYPE_QPACK_DECODER, &mut buf);
    buf
}

/// Build a shared `Arc<quinn_proto::crypto::rustls::QuicClientConfig>` once (avoiding
/// per-connection `/etc/ssl/certs/ca-certificates.crt` disk parses), with `h3` ALPN,
/// persistent session resumption, and 0-RTT `enable_early_data = true`.
pub fn build_shared_quic_client_config() -> Result<Arc<quinn_proto::crypto::rustls::QuicClientConfig>, String> {
    let provider = Arc::new(quinn_proto::rustls::crypto::ring::default_provider());
    let roots = crate::root_store();
    let mut rustls_client_config =
        quinn_proto::rustls::ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&quinn_proto::rustls::version::TLS13])
            .map_err(|e| format!("TLS 1.3 config failed: {}", e))?
            .with_root_certificates(roots)
            .with_no_client_auth();

    rustls_client_config.alpn_protocols = vec![b"h3".to_vec()];
    let session_store = Arc::new(PersistentRustlsSessionStore::new_default(1024));
    rustls_client_config.resumption = session_store.into_resumption();
    rustls_client_config.enable_early_data = true;

    let quic_crypto =
        quinn_proto::crypto::rustls::QuicClientConfig::try_from(Arc::new(rustls_client_config))
            .map_err(|e| format!("QuicClientConfig failed: {:?}", e))?;
    Ok(Arc::new(quic_crypto))
}

fn default_shared_quic_crypto() -> Result<Arc<quinn_proto::crypto::rustls::QuicClientConfig>, String> {
    static SHARED: OnceLock<Arc<quinn_proto::crypto::rustls::QuicClientConfig>> = OnceLock::new();
    if let Some(cfg) = SHARED.get() {
        return Ok(cfg.clone());
    }
    let built = build_shared_quic_client_config()?;
    let _ = SHARED.set(built.clone());
    Ok(built)
}

pub struct QuicHandshakeState {
    pub endpoint: quinn_proto::Endpoint,
    pub ch: quinn_proto::ConnectionHandle,
    pub connection: quinn_proto::Connection,
    pub tx_buf: Vec<u8>,
    pub rx_buf: [u8; 4096],
}

impl QuicHandshakeState {
    /// Bind a non-blocking UDP socket and initiate a QUIC handshake using a shared
    /// `Arc<quinn_proto::crypto::rustls::QuicClientConfig>`.
    pub fn start_with_config(
        server_addr: std::net::SocketAddr,
        sni_host: &str,
        quic_crypto: Arc<quinn_proto::crypto::rustls::QuicClientConfig>,
    ) -> Result<(Self, UdpSocket), String> {
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

        let mut transport = quinn_proto::TransportConfig::default();
        transport.max_idle_timeout(quinn_proto::IdleTimeout::try_from(Duration::from_secs(30)).ok());
        let mut client_config = quinn_proto::ClientConfig::new(quic_crypto);
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

    /// Convenience wrapper using the process-wide cached `QuicClientConfig`.
    pub fn start(server_addr: std::net::SocketAddr, sni_host: &str) -> Result<(Self, UdpSocket), String> {
        let quic_crypto = default_shared_quic_crypto()?;
        Self::start_with_config(server_addr, sni_host, quic_crypto)
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

/// Peer unidirectional stream classification for HTTP/3 (Control, QPACK Encoder, QPACK Decoder).
enum PeerUniStreamKind {
    Unknown,
    Control,
    QpackEncoder,
    QpackDecoder,
    Ignored,
}

struct PeerUniStream {
    kind: PeerUniStreamKind,
    buf: Vec<u8>,
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

        // 1. Open mandatory RFC 9114 §6.2.1 unidirectional control stream (0x00) and send populated SETTINGS (0x04).
        let ctrl_stream_id = connection
            .streams()
            .open(quinn_proto::Dir::Uni)
            .ok_or("Failed to open QUIC unidirectional control stream".to_string())?;
        {
            let ctrl_init = build_control_stream_init();
            let mut ctrl_send = connection.send_stream(ctrl_stream_id);
            let _ = ctrl_send.write(&ctrl_init);
        }

        // 2. Open unidirectional QPACK Encoder (0x02) and Decoder (0x03) streams (RFC 9204 §4.2).
        let qpack_enc_stream_id = connection.streams().open(quinn_proto::Dir::Uni);
        if let Some(enc_sid) = qpack_enc_stream_id {
            let mut s = connection.send_stream(enc_sid);
            let _ = s.write(&build_qpack_encoder_stream_init());
        }
        let qpack_dec_stream_id = connection.streams().open(quinn_proto::Dir::Uni);
        if let Some(dec_sid) = qpack_dec_stream_id {
            let mut s = connection.send_stream(dec_sid);
            let _ = s.write(&build_qpack_decoder_stream_init());
        }

        // Start client encoder with capacity=0 until peer SETTINGS advertises QPACK capacity
        // (avoids blocking the first request before receiving server SETTINGS), while our
        // decoder supports full 64KiB dynamic table as advertised in our SETTINGS.
        let mut qpack_encoder = QpackEncoder::new(0);
        let mut qpack_decoder = QpackDecoder::new(DEFAULT_QPACK_MAX_TABLE_CAPACITY as usize);

        // 3. Open bidirectional request stream
        let stream_id = connection
            .streams()
            .open(quinn_proto::Dir::Bi)
            .ok_or("Failed to open QUIC bidirectional stream".to_string())?;

        let url = url::Url::parse(&options.url).map_err(|e| format!("Invalid URL: {}", e))?;
        let mut path_and_query = url.path().to_string();
        if let Some(q) = url.query() {
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

        // QPACK encode headers (with Huffman H=1 literal compression)
        let (enc_instructions, qpack_hdr) = qpack_encoder.encode_headers(
            &options.method,
            url.scheme(),
            host,
            &path_and_query,
            &options.headers,
        );
        if !enc_instructions.is_empty() {
            if let Some(enc_sid) = qpack_enc_stream_id {
                let mut s = connection.send_stream(enc_sid);
                let _ = s.write(&enc_instructions);
            }
        }
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

        // 4. Receive Response Loop (Frames: HEADERS 0x01, DATA 0x00 + peer unidirectional QPACK streams)
        let mut stream_buffer = Vec::new();
        let mut pending_blocked_headers: Option<Vec<u8>> = None;
        let mut peer_uni_streams: HashMap<quinn_proto::StreamId, PeerUniStream> = HashMap::new();
        let mut headers_dispatched = false;
        let mut stream_finished = false;
        let mut last_conn_err: Option<String> = None;
        let mut decompressor: Option<StreamDecompressor> = None;
        let request_deadline = Instant::now() + options.timeout;

        let req_stream_id_u64 = u64::from(stream_id);

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

            // Accept & drain peer unidirectional streams (0x00 Control, 0x02 QPACK Encoder, 0x03 QPACK Decoder)
            while let Some(uni_sid) = connection.streams().accept(quinn_proto::Dir::Uni) {
                peer_uni_streams.entry(uni_sid).or_insert_with(|| PeerUniStream {
                    kind: PeerUniStreamKind::Unknown,
                    buf: Vec::new(),
                });
            }
            for (&uni_sid, uni_state) in peer_uni_streams.iter_mut() {
                let mut recv = connection.recv_stream(uni_sid);
                if let Ok(mut chunks) = recv.read(true) {
                    loop {
                        match chunks.next(4096) {
                            Ok(Some(chunk)) => uni_state.buf.extend_from_slice(&chunk.bytes),
                            Ok(None) | Err(quinn_proto::ReadError::Blocked) => break,
                            Err(quinn_proto::ReadError::Reset(_)) => break,
                        }
                    }
                    let _ = chunks.finalize();
                }

                if matches!(uni_state.kind, PeerUniStreamKind::Unknown) {
                    if let Some((stype, slen)) = decode_varint(&uni_state.buf) {
                        uni_state.buf.drain(..slen);
                        uni_state.kind = match stype {
                            H3_STREAM_TYPE_CONTROL => PeerUniStreamKind::Control,
                            H3_STREAM_TYPE_QPACK_ENCODER => PeerUniStreamKind::QpackEncoder,
                            H3_STREAM_TYPE_QPACK_DECODER => PeerUniStreamKind::QpackDecoder,
                            _ => PeerUniStreamKind::Ignored,
                        };
                    }
                }

                match uni_state.kind {
                    PeerUniStreamKind::QpackEncoder if !uni_state.buf.is_empty() => {
                        let bytes = std::mem::take(&mut uni_state.buf);
                        if let Ok(inc_ack) = qpack_decoder.process_encoder_stream(&bytes) {
                            if !inc_ack.is_empty() {
                                if let Some(dec_sid) = qpack_dec_stream_id {
                                    let mut s = connection.send_stream(dec_sid);
                                    let _ = s.write(&inc_ack);
                                }
                            }
                        }
                    }
                    PeerUniStreamKind::QpackDecoder if !uni_state.buf.is_empty() => {
                        let bytes = std::mem::take(&mut uni_state.buf);
                        let _ = qpack_encoder.process_decoder_stream(&bytes);
                    }
                    PeerUniStreamKind::Control | PeerUniStreamKind::Ignored => {
                        uni_state.buf.clear();
                    }
                    _ => {}
                }
            }

            // Retry any blocked HEADERS frame if QPACK Insert Count caught up
            if !headers_dispatched {
                if let Some(blocked_payload) = pending_blocked_headers.take() {
                    match qpack_decoder.decode_field_section(req_stream_id_u64, &blocked_payload) {
                        Ok(QpackDecodeOutcome::Decoded {
                            status,
                            headers,
                            section_ack,
                        }) => {
                            if !section_ack.is_empty() {
                                if let Some(dec_sid) = qpack_dec_stream_id {
                                    let mut s = connection.send_stream(dec_sid);
                                    let _ = s.write(&section_ack);
                                }
                            }
                            dispatch_h3_headers(
                                status,
                                headers,
                                options.transparent_decompression,
                                has_range_header,
                                &mut decompressor,
                                &mut on_headers,
                            );
                            headers_dispatched = true;
                        }
                        Ok(QpackDecodeOutcome::Blocked { .. }) => {
                            pending_blocked_headers = Some(blocked_payload);
                        }
                        Err(e) => {
                            eprintln!("[ZNET-H3] {} QPACK header decode failed: {}", options.url, e);
                        }
                    }
                }
            }

            // Read incoming bytes off the request stream
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
                                recv_eof = true;
                                break;
                            }
                            Err(quinn_proto::ReadError::Blocked) => break,
                            Err(quinn_proto::ReadError::Reset(code)) => {
                                if !headers_dispatched {
                                    eprintln!(
                                        "[ZNET-H3] {} stream reset by peer (code={:?})",
                                        options.url, code
                                    );
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
                    break;
                }

                let payload = &slice[header_size..header_size + payload_len];

                if frame_type == 0x01 && !headers_dispatched {
                    match qpack_decoder.decode_field_section(req_stream_id_u64, payload) {
                        Ok(QpackDecodeOutcome::Decoded {
                            status,
                            headers,
                            section_ack,
                        }) => {
                            if !section_ack.is_empty() {
                                if let Some(dec_sid) = qpack_dec_stream_id {
                                    let mut s = connection.send_stream(dec_sid);
                                    let _ = s.write(&section_ack);
                                }
                            }
                            dispatch_h3_headers(
                                status,
                                headers,
                                options.transparent_decompression,
                                has_range_header,
                                &mut decompressor,
                                &mut on_headers,
                            );
                            headers_dispatched = true;
                        }
                        Ok(QpackDecodeOutcome::Blocked { .. }) => {
                            pending_blocked_headers = Some(payload.to_vec());
                        }
                        Err(e) => {
                            eprintln!("[ZNET-H3] {} QPACK header decode failed: {}", options.url, e);
                        }
                    }
                } else if frame_type == 0x00 {
                    // Wait until blocked headers are resolved before delivering DATA if needed
                    if !headers_dispatched && pending_blocked_headers.is_some() {
                        break;
                    }
                    if let Some(ref mut dec) = decompressor {
                        dec.feed(payload, |decompressed_slice| {
                            if let Some(ring) = body_ring {
                                write_h3_slice_to_ring(ring, decompressed_slice);
                            }
                            on_data_chunk(decompressed_slice);
                        })
                        .map_err(|e| format!("h3 decompression error: {}", e))?;
                    } else {
                        if let Some(ring) = body_ring {
                            write_h3_slice_to_ring(ring, payload);
                        }
                        on_data_chunk(payload);
                    }
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

            if recv_eof && pending_blocked_headers.is_none() {
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

        if let Some(dec) = decompressor.take() {
            dec.finish(|decompressed_slice| {
                if let Some(ring) = body_ring {
                    write_h3_slice_to_ring(ring, decompressed_slice);
                }
                on_data_chunk(decompressed_slice);
            })
            .map_err(|e| format!("h3 decompression finish error: {}", e))?;
        }

        if !headers_dispatched {
            eprintln!(
                "[ZNET-H3] {} falling back to H2 (no headers dispatched)",
                options.url
            );
            return Err("HTTP/3 stream closed before response headers were received".to_string());
        }
        on_complete(false);
        Ok(true)
    }
}

fn write_h3_slice_to_ring(ring: &BodyRingDescriptor, slice: &[u8]) {
    let mut offset = 0;
    while offset < slice.len() && !ring.is_closed.load(Ordering::Acquire) {
        let written = ring.write_slice(&slice[offset..]);
        offset += written;
        if offset < slice.len() {
            ring.wait_drain(5);
        }
    }
}

fn dispatch_h3_headers<H>(
    status: u16,
    headers: Vec<(String, String)>,
    transparent_decompression: bool,
    has_range_header: bool,
    decompressor: &mut Option<StreamDecompressor>,
    on_headers: &mut H,
) where
    H: FnMut(u16, &str, &[(String, String)]),
{
    let reason = http::StatusCode::from_u16(status)
        .ok()
        .and_then(|s| s.canonical_reason())
        .unwrap_or("OK");

    let should_decompress = transparent_decompression && !has_range_header && status != 206;
    if should_decompress {
        if let Some((_, enc)) = headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("content-encoding"))
        {
            if let Some(dec) = StreamDecompressor::new(enc) {
                *decompressor = Some(dec);
            }
        }
    }

    if decompressor.is_some() {
        let filtered: Vec<(String, String)> = headers
            .into_iter()
            .filter(|(k, _)| {
                !k.eq_ignore_ascii_case("content-encoding")
                    && !k.eq_ignore_ascii_case("content-length")
            })
            .collect();
        on_headers(status, reason, &filtered);
    } else {
        on_headers(status, reason, &headers);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_varint_roundtrip() {
        let test_values = [
            0,
            1,
            25,
            63,
            64,
            16383,
            16384,
            1073741823,
            1073741824,
            4611686018427387903,
        ];
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
        let (stype, slen) = decode_varint(&init).unwrap();
        assert_eq!(stype, H3_STREAM_TYPE_CONTROL);

        let (ftype, flen) = decode_varint(&init[slen..]).unwrap();
        assert_eq!(ftype, 0x04); // SETTINGS frame

        let (plen, plen_len) = decode_varint(&init[slen + flen..]).unwrap();
        let payload = &init[slen + flen + plen_len..];
        assert_eq!(payload.len(), plen as usize);

        let mut pos = 0;
        let mut settings = Vec::new();
        while pos < payload.len() {
            let (id, ilen) = decode_varint(&payload[pos..]).unwrap();
            pos += ilen;
            let (val, vlen) = decode_varint(&payload[pos..]).unwrap();
            pos += vlen;
            settings.push((id, val));
        }

        assert!(settings.contains(&(
            SETTINGS_QPACK_MAX_TABLE_CAPACITY,
            DEFAULT_QPACK_MAX_TABLE_CAPACITY
        )));
        assert!(settings.contains(&(
            SETTINGS_MAX_FIELD_SECTION_SIZE,
            DEFAULT_MAX_FIELD_SECTION_SIZE
        )));
        assert!(settings.contains(&(
            SETTINGS_QPACK_BLOCKED_STREAMS,
            DEFAULT_QPACK_BLOCKED_STREAMS
        )));
        // Verify GREASE setting ID matches RFC 9114 §7.2.4.1 (0x1f * N + 0x21)
        assert!(settings
            .iter()
            .any(|&(id, _)| id >= 0x21 && (id - 0x21) % 0x1f == 0));
    }

    #[test]
    fn test_build_shared_quic_client_config() {
        let cfg = build_shared_quic_client_config().expect("shared QuicClientConfig");
        assert!(Arc::strong_count(&cfg) == 1);
    }
}
