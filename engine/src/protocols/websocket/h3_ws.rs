//! RFC 9220: Bootstrapping WebSockets with HTTP/3 (Extended CONNECT).
//!
//! Enables multiplexing multiple independent WebSocket sessions over a single
//! HTTP/3 (QUIC) connection on bidirectional streams.

use std::collections::VecDeque;

use crate::protocols::http3::qpack::QpackCodec;
use crate::protocols::http3::build_http3_frame;
use super::frame::WebSocketFrame;

pub struct H3WebSocketHandshake;

impl H3WebSocketHandshake {
    /// Build RFC 9220 Extended CONNECT HEADERS frame for WebSocket initialization.
    pub fn build_connect_request(
        authority: &str,
        path: &str,
        subprotocol: Option<&str>,
        extra_headers: &[(String, String)],
    ) -> Vec<u8> {
        let mut headers = Vec::new();
        headers.push((":protocol".to_string(), "websocket".to_string()));
        headers.push(("sec-websocket-version".to_string(), "13".to_string()));

        if let Some(sub) = subprotocol {
            headers.push(("sec-websocket-protocol".to_string(), sub.to_string()));
        }

        for (k, v) in extra_headers {
            headers.push((k.clone(), v.clone()));
        }

        let qpack_hdr = QpackCodec::encode_headers(
            "CONNECT",
            "https",
            authority,
            path,
            &headers,
        );

        // Frame Type 0x01: HEADERS
        build_http3_frame(0x01, &qpack_hdr)
    }

    /// Verify server response for Extended CONNECT. Returns Ok(status) if 200 OK.
    pub fn verify_connect_response(payload: &[u8]) -> Result<u16, String> {
        let (status, _) = QpackCodec::decode_response_headers(payload)
            .map_err(|e| format!("Failed to decode H3 response headers: {}", e))?;

        if status == 200 {
            Ok(200)
        } else {
            Err(format!("H3 Extended CONNECT rejected with HTTP status {}", status))
        }
    }
}

pub struct H3WebSocketSession {
    pub stream_id: u64,
    pub is_connected: bool,
    read_buffer: Vec<u8>,
    incoming_frames: VecDeque<WebSocketFrame>,
}

impl H3WebSocketSession {
    pub fn new(stream_id: u64) -> Self {
        Self {
            stream_id,
            is_connected: false,
            read_buffer: Vec::new(),
            incoming_frames: VecDeque::new(),
        }
    }

    /// Mark handshake complete (server returned 200 OK).
    pub fn mark_connected(&mut self) {
        self.is_connected = true;
    }

    /// Encode a text message into an RFC 6455 frame ready to send over the QUIC stream.
    pub fn format_text(&self, msg: &str) -> Vec<u8> {
        let frame = WebSocketFrame::text(msg, true); // Client-to-server frames must be masked
        frame.encode()
    }

    /// Encode a binary message into an RFC 6455 frame ready to send over the QUIC stream.
    pub fn format_binary(&self, data: &[u8]) -> Vec<u8> {
        let frame = WebSocketFrame::binary(data, true);
        frame.encode()
    }

    /// Encode a Ping frame ready to send over the QUIC stream.
    pub fn format_ping(&self, data: &[u8]) -> Vec<u8> {
        let frame = WebSocketFrame::ping(data, true);
        frame.encode()
    }

    /// Encode a Pong frame ready to send over the QUIC stream.
    pub fn format_pong(&self, data: &[u8]) -> Vec<u8> {
        let frame = WebSocketFrame::pong(data, true);
        frame.encode()
    }

    /// Encode a Close frame ready to send over the QUIC stream.
    pub fn format_close(&self, code: u16, reason: &str) -> Vec<u8> {
        let frame = WebSocketFrame::close(code, reason, true);
        frame.encode()
    }

    /// Feed incoming stream bytes from the QUIC stream and extract parsed WebSocket frames.
    pub fn feed_stream_data(&mut self, data: &[u8]) -> Result<(), String> {
        self.read_buffer.extend_from_slice(data);

        // Process WebSocket frames per RFC 6455
        while !self.read_buffer.is_empty() {
            match WebSocketFrame::decode(&self.read_buffer)? {
                Some((frame, consumed)) => {
                    self.incoming_frames.push_back(frame);
                    self.read_buffer.drain(..consumed);
                }
                None => break, // Incomplete frame, wait for more data
            }
        }

        Ok(())
    }

    /// Retrieve the next parsed WebSocket frame, if available.
    pub fn poll_frame(&mut self) -> Option<WebSocketFrame> {
        self.incoming_frames.pop_front()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::frame::Opcode;
    use crate::protocols::http3::decode_varint;

    #[test]
    fn test_h3_websocket_handshake_request_building() {
        let frame = H3WebSocketHandshake::build_connect_request(
            "chat.example.com",
            "/ws",
            Some("json-rpc"),
            &[],
        );
        let (ftype, tlen) = decode_varint(&frame).unwrap();
        assert_eq!(ftype, 0x01); // HEADERS frame
        let (flen, llen) = decode_varint(&frame[tlen..]).unwrap();
        assert!(flen > 0);
        assert_eq!(frame.len(), tlen + llen + flen as usize);
    }

    #[test]
    fn test_h3_websocket_session_feed_and_poll() {
        let mut session = H3WebSocketSession::new(4);
        session.mark_connected();
        assert!(session.is_connected);

        // Format a text frame from a remote peer (unmasked as from server)
        let server_frame = WebSocketFrame::text("Welcome to H3 WebSockets!", false);
        let frame_bytes = server_frame.encode();

        // Feed half of the frame bytes (simulate chunked network read)
        let mid = frame_bytes.len() / 2;
        session.feed_stream_data(&frame_bytes[..mid]).unwrap();
        assert_eq!(session.poll_frame(), None);

        // Feed second half
        session.feed_stream_data(&frame_bytes[mid..]).unwrap();
        let received = session.poll_frame().expect("received frame");
        assert_eq!(received.opcode, Opcode::Text);
        assert_eq!(String::from_utf8(received.payload).unwrap(), "Welcome to H3 WebSockets!");
    }
}
