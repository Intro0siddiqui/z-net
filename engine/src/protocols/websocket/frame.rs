//! RFC 6455 WebSocket Frame codec.
//!
//! Provides frame serialization, deserialization, masking, and control frame handling.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Opcode {
    Continuation = 0x0,
    Text = 0x1,
    Binary = 0x2,
    Close = 0x8,
    Ping = 0x9,
    Pong = 0xA,
}

impl Opcode {
    pub fn from_u8(b: u8) -> Option<Self> {
        match b {
            0x0 => Some(Self::Continuation),
            0x1 => Some(Self::Text),
            0x2 => Some(Self::Binary),
            0x8 => Some(Self::Close),
            0x9 => Some(Self::Ping),
            0xA => Some(Self::Pong),
            _ => None,
        }
    }

    pub fn is_control(&self) -> bool {
        matches!(self, Self::Close | Self::Ping | Self::Pong)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WebSocketFrame {
    pub fin: bool,
    pub opcode: Opcode,
    pub masked: bool,
    pub masking_key: Option<[u8; 4]>,
    pub payload: Vec<u8>,
}

impl WebSocketFrame {
    pub fn new(fin: bool, opcode: Opcode, payload: Vec<u8>, masked: bool) -> Self {
        let masking_key = if masked {
            // Generate pseudo-random masking key
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .subsec_nanos();
            Some(nanos.to_ne_bytes())
        } else {
            None
        };
        Self {
            fin,
            opcode,
            masked,
            masking_key,
            payload,
        }
    }

    pub fn text(msg: &str, masked: bool) -> Self {
        Self::new(true, Opcode::Text, msg.as_bytes().to_vec(), masked)
    }

    pub fn binary(data: &[u8], masked: bool) -> Self {
        Self::new(true, Opcode::Binary, data.to_vec(), masked)
    }

    pub fn ping(data: &[u8], masked: bool) -> Self {
        Self::new(true, Opcode::Ping, data.to_vec(), masked)
    }

    pub fn pong(data: &[u8], masked: bool) -> Self {
        Self::new(true, Opcode::Pong, data.to_vec(), masked)
    }

    pub fn close(code: u16, reason: &str, masked: bool) -> Self {
        let mut payload = Vec::with_capacity(2 + reason.len());
        payload.extend_from_slice(&code.to_be_bytes());
        payload.extend_from_slice(reason.as_bytes());
        Self::new(true, Opcode::Close, payload, masked)
    }

    /// Encode the frame into bytes ready for transmission.
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(14 + self.payload.len());

        // Byte 1: FIN (1 bit) + RSV1..3 (3 bits) + Opcode (4 bits)
        let b1 = (if self.fin { 0x80 } else { 0x00 }) | (self.opcode as u8);
        buf.push(b1);

        // Byte 2: MASK (1 bit) + Payload len (7 bits)
        let mask_bit = if self.masked { 0x80 } else { 0x00 };
        let payload_len = self.payload.len();

        if payload_len < 126 {
            buf.push(mask_bit | (payload_len as u8));
        } else if payload_len <= 65535 {
            buf.push(mask_bit | 126);
            buf.extend_from_slice(&(payload_len as u16).to_be_bytes());
        } else {
            buf.push(mask_bit | 127);
            buf.extend_from_slice(&(payload_len as u64).to_be_bytes());
        }

        // Masking key (4 bytes)
        if let Some(mask) = self.masking_key {
            buf.extend_from_slice(&mask);
            // Masked payload
            for (i, &byte) in self.payload.iter().enumerate() {
                buf.push(byte ^ mask[i % 4]);
            }
        } else {
            buf.extend_from_slice(&self.payload);
        }

        buf
    }

    /// Decode a WebSocket frame from a byte buffer. Returns `Some((frame, bytes_consumed))` or `None` if incomplete.
    pub fn decode(buf: &[u8]) -> Result<Option<(Self, usize)>, String> {
        if buf.len() < 2 {
            return Ok(None);
        }

        let b1 = buf[0];
        let fin = (b1 & 0x80) != 0;
        let opcode = Opcode::from_u8(b1 & 0x0F)
            .ok_or_else(|| format!("Invalid WebSocket opcode: {}", b1 & 0x0F))?;

        let b2 = buf[1];
        let masked = (b2 & 0x80) != 0;
        let len_code = b2 & 0x7F;

        let mut offset = 2;
        let payload_len: usize = match len_code {
            126 => {
                if buf.len() < offset + 2 {
                    return Ok(None);
                }
                let len = u16::from_be_bytes([buf[offset], buf[offset + 1]]) as usize;
                offset += 2;
                len
            }
            127 => {
                if buf.len() < offset + 8 {
                    return Ok(None);
                }
                let mut bytes = [0u8; 8];
                bytes.copy_from_slice(&buf[offset..offset + 8]);
                let len = u64::from_be_bytes(bytes) as usize;
                offset += 8;
                len
            }
            len => len as usize,
        };

        let masking_key = if masked {
            if buf.len() < offset + 4 {
                return Ok(None);
            }
            let mut key = [0u8; 4];
            key.copy_from_slice(&buf[offset..offset + 4]);
            offset += 4;
            Some(key)
        } else {
            None
        };

        if buf.len() < offset + payload_len {
            return Ok(None);
        }

        let raw_payload = &buf[offset..offset + payload_len];
        let payload = if let Some(key) = masking_key {
            raw_payload.iter().enumerate().map(|(i, &b)| b ^ key[i % 4]).collect()
        } else {
            raw_payload.to_vec()
        };

        let consumed = offset + payload_len;
        Ok(Some((
            Self {
                fin,
                opcode,
                masked,
                masking_key,
                payload,
            },
            consumed,
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_text_frame_roundtrip_unmasked() {
        let frame = WebSocketFrame::text("Hello, RFC 9220!", false);
        let encoded = frame.encode();
        let (decoded, consumed) = WebSocketFrame::decode(&encoded).expect("decode").unwrap();
        assert_eq!(consumed, encoded.len());
        assert_eq!(decoded.opcode, Opcode::Text);
        assert_eq!(String::from_utf8(decoded.payload).unwrap(), "Hello, RFC 9220!");
    }

    #[test]
    fn test_binary_frame_roundtrip_masked() {
        let payload = vec![0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02];
        let frame = WebSocketFrame::binary(&payload, true);
        let encoded = frame.encode();
        let (decoded, consumed) = WebSocketFrame::decode(&encoded).expect("decode").unwrap();
        assert_eq!(consumed, encoded.len());
        assert_eq!(decoded.opcode, Opcode::Binary);
        assert_eq!(decoded.payload, payload);
    }

    #[test]
    fn test_close_frame_roundtrip() {
        let frame = WebSocketFrame::close(1000, "Normal Closure", false);
        let encoded = frame.encode();
        let (decoded, _) = WebSocketFrame::decode(&encoded).expect("decode").unwrap();
        assert_eq!(decoded.opcode, Opcode::Close);
        assert_eq!(u16::from_be_bytes([decoded.payload[0], decoded.payload[1]]), 1000);
        assert_eq!(&decoded.payload[2..], b"Normal Closure");
    }

    #[test]
    fn test_extended_length_126() {
        let payload = vec![0x42; 300];
        let frame = WebSocketFrame::binary(&payload, false);
        let encoded = frame.encode();
        assert_eq!(encoded[1], 126);
        let (decoded, consumed) = WebSocketFrame::decode(&encoded).expect("decode").unwrap();
        assert_eq!(consumed, encoded.len());
        assert_eq!(decoded.payload.len(), 300);
    }
}
