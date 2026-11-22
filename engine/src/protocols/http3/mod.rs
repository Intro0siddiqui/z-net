//! HTTP/3 client protocol implementation over QUIC (RFC 9114).
//!
//! Provides progressive streaming, QPACK encoding/decoding, and
//! fast-failing Happy Eyeballs fallback to TCP TLS.

pub mod qpack;

use std::io::ErrorKind;
use std::net::{ToSocketAddrs, UdpSocket};
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
        options: &HttpRequestOptions,
        body_ring: Option<&BodyRingDescriptor>,
        mut on_headers: H,
        mut on_data_chunk: D,
        mut on_complete: C,
        mut is_cancelled: K,
        handshake_timeout: Duration,
    ) -> Result<bool, String>
    where
        H: FnMut(u16, &str, &[(String, String)]),
        D: FnMut(&[u8]),
        C: FnMut(bool),
        K: FnMut() -> bool,
    {
        let addr_str = format!("{}:{}", host, port);
        let server_addr = addr_str
            .to_socket_addrs()
            .map_err(|e| format!("DNS resolution failed for {}: {}", addr_str, e))?
            .next()
            .ok_or(format!("No address found for {}", addr_str))?;

        let socket = UdpSocket::bind("0.0.0.0:0")
            .map_err(|e| format!("UDP bind failed: {}", e))?;
        socket.set_nonblocking(true)
            .map_err(|e| format!("Failed to set nonblocking UDP: {}", e))?;

        // Quinn-proto endpoint configuration
        let endpoint_config = Arc::new(quinn_proto::EndpointConfig::default());
        let mut endpoint = quinn_proto::Endpoint::new(endpoint_config, None, false, None);

        let provider = Arc::new(quinn_proto::rustls::crypto::ring::default_provider());
        let roots = quinn_proto::rustls::RootCertStore::empty();
        let mut rustls_client_config =
            quinn_proto::rustls::ClientConfig::builder_with_provider(provider.clone())
                .with_protocol_versions(&[&quinn_proto::rustls::version::TLS13])
                .map_err(|e| format!("TLS 1.3 config failed: {}", e))?
                .with_root_certificates(roots)
                .with_no_client_auth();

        // Advertise HTTP/3 ALPN
        rustls_client_config.alpn_protocols = vec![b"h3".to_vec()];

        let quic_crypto = quinn_proto::crypto::rustls::QuicClientConfig::try_from(Arc::new(rustls_client_config))
            .map_err(|e| format!("QuicClientConfig failed: {:?}", e))?;

        let mut transport = quinn_proto::TransportConfig::default();
        transport.max_idle_timeout(quinn_proto::IdleTimeout::try_from(Duration::from_secs(30)).ok());
        let mut client_config = quinn_proto::ClientConfig::new(Arc::new(quic_crypto));
        client_config.transport_config(Arc::new(transport));

        let start_time = Instant::now();
        let (ch, mut connection) = endpoint
            .connect(start_time, client_config, server_addr, host)
            .map_err(|e| format!("QUIC connect error: {:?}", e))?;

        let mut tx_buf = Vec::new();
        let mut rx_buf = [0u8; 4096];

        // 1. Handshake Phase with strict timeout
        let handshake_deadline = start_time + handshake_timeout;
        while connection.is_handshaking() {
            if is_cancelled() {
                return Err("Request cancelled during QUIC handshake".to_string());
            }
            let now = Instant::now();
            if now > handshake_deadline {
                return Err("QUIC handshake timed out (falling back to TCP)".to_string());
            }

            // Flush transmits
            while let Some(transmit) = connection.poll_transmit(now, 1, &mut tx_buf) {
                let _ = socket.send_to(&tx_buf[..transmit.size], transmit.destination);
                tx_buf.clear();
            }

            // Read UDP socket
            match socket.recv_from(&mut rx_buf) {
                Ok((n, remote)) => {
                    let data = bytes::BytesMut::from(&rx_buf[..n]);
                    let event = endpoint.handle(now, remote, None, None, data, &mut tx_buf);
                    if let Some(quinn_proto::DatagramEvent::ConnectionEvent(h, conn_event)) = event {
                        if h == ch {
                            let _ = connection.handle_event(conn_event);
                        }
                    }
                }
                Err(ref e) if e.kind() == ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(2));
                }
                Err(e) => return Err(format!("UDP socket error: {}", e)),
            }

            if let Some(timeout) = connection.poll_timeout() {
                if timeout <= now {
                    connection.handle_timeout(now);
                }
            }

            if connection.is_closed() || connection.is_drained() {
                return Err("QUIC connection closed during handshake".to_string());
            }
        }

        // 2. Open bidirectional request stream
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
        while let Some(transmit) = connection.poll_transmit(now, 1, &mut tx_buf) {
            let _ = socket.send_to(&tx_buf[..transmit.size], transmit.destination);
            tx_buf.clear();
        }

        // 3. Receive Response Loop (Frames: HEADERS 0x01, DATA 0x00)
        let mut stream_buffer = Vec::new();
        let mut headers_dispatched = false;
        let mut stream_finished = false;
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
            while let Some(transmit) = connection.poll_transmit(now, 1, &mut tx_buf) {
                let _ = socket.send_to(&tx_buf[..transmit.size], transmit.destination);
                tx_buf.clear();
            }

            // Read UDP socket
            match socket.recv_from(&mut rx_buf) {
                Ok((n, remote)) => {
                    let data = bytes::BytesMut::from(&rx_buf[..n]);
                    let event = endpoint.handle(now, remote, None, None, data, &mut tx_buf);
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
            {
                let mut recv = connection.recv_stream(stream_id);
                let mut read_res = recv.read(true);
                if let Ok(ref mut chunks) = read_res {
                    while let Ok(Some(chunk)) = chunks.next(4096) {
                        stream_buffer.extend_from_slice(&chunk.bytes);
                    }
                }
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
                    if let Ok((status, headers)) = QpackCodec::decode_response_headers(payload) {
                        on_headers(status, "OK", &headers);
                        headers_dispatched = true;
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

            if connection.is_closed() || connection.is_drained() {
                stream_finished = true;
            }
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
}
