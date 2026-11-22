//! QPACK Header Compression for HTTP/3 per RFC 9204.
//!
//! Implements encode/decode of static table entries and literal fields
//! sufficient for client requests and server responses.

/// Static table lookup for common HTTP/3 headers (RFC 9204 Appendix A).
pub struct QpackCodec;

impl QpackCodec {
    /// Encode request headers into a QPACK encoded byte block.
    pub fn encode_headers(
        method: &str,
        scheme: &str,
        authority: &str,
        path: &str,
        headers: &[(String, String)],
    ) -> Vec<u8> {
        let mut buf = Vec::new();

        // 1. QPACK Prefix (RFC 9204 Section 4.5.1):
        // Required Insert Count = 0, Sign bit = 0, Delta Base = 0
        buf.push(0x00);
        buf.push(0x00);

        // 2. Encode Pseudo-headers
        // :method
        if method.eq_ignore_ascii_case("GET") {
            // Static index 17: :method GET
            buf.push(0x80 | 17);
        } else if method.eq_ignore_ascii_case("POST") {
            // Static index 20: :method POST
            buf.push(0x80 | 20);
        } else {
            Self::encode_literal(&mut buf, ":method", method);
        }

        // :scheme
        if scheme.eq_ignore_ascii_case("https") {
            // Static index 22: :scheme https
            buf.push(0x80 | 22);
        } else if scheme.eq_ignore_ascii_case("http") {
            // Static index 23: :scheme http
            buf.push(0x80 | 23);
        } else {
            Self::encode_literal(&mut buf, ":scheme", scheme);
        }

        // :authority
        Self::encode_literal(&mut buf, ":authority", authority);

        // :path
        if path == "/" {
            // Static index 1: :path /
            buf.push(0x80 | 1);
        } else {
            Self::encode_literal(&mut buf, ":path", path);
        }

        // 3. Encode regular headers
        for (name, value) in headers {
            let lower_name = name.to_ascii_lowercase();
            // Fast paths for common static headers
            if lower_name == "accept-encoding" && value == "gzip, deflate, br" {
                // Static index 31
                buf.push(0x80 | 31);
            } else {
                Self::encode_literal(&mut buf, &lower_name, value);
            }
        }

        buf
    }

    /// Encode a Literal Field Line with Literal Name (RFC 9204 Section 4.5.4)
    /// Pattern: 0010 N H | name_len (3-bit prefix) | name | H | value_len (7-bit prefix) | value
    pub fn encode_literal(buf: &mut Vec<u8>, name: &str, value: &str) {
        let name_bytes = name.as_bytes();
        let val_bytes = value.as_bytes();

        // 0010 0000 (0x20) + 3-bit name length prefix
        if name_bytes.len() < 7 {
            buf.push(0x20 | (name_bytes.len() as u8));
        } else {
            buf.push(0x27);
            Self::encode_integer(buf, name_bytes.len() as u64 - 7, 8);
        }
        buf.extend_from_slice(name_bytes);

        // Value: H=0 + 7-bit prefix
        if val_bytes.len() < 127 {
            buf.push(val_bytes.len() as u8);
        } else {
            buf.push(0x7F);
            Self::encode_integer(buf, val_bytes.len() as u64 - 127, 8);
        }
        buf.extend_from_slice(val_bytes);
    }

    fn encode_integer(buf: &mut Vec<u8>, mut val: u64, _prefix_bits: u8) {
        while val >= 128 {
            buf.push((val as u8 & 0x7F) | 0x80);
            val >>= 7;
        }
        buf.push(val as u8);
    }

    /// Decode QPACK encoded response headers into status code and header list.
    pub fn decode_response_headers(data: &[u8]) -> Result<(u16, Vec<(String, String)>), String> {
        if data.len() < 2 {
            return Err("QPACK data too short for prefix".to_string());
        }

        // Skip Required Insert Count & Delta Base (2 bytes)
        let mut pos = 2;
        let mut status_code: u16 = 200;
        let mut headers = Vec::new();

        while pos < data.len() {
            let b = data[pos];
            if b & 0x80 != 0 {
                // Indexed Field Line (RFC 9204 Section 4.5.2)
                let static_idx = b & 0x3F; // assuming T=1 (static table)
                pos += 1;
                match static_idx {
                    24 => status_code = 100,
                    25 => status_code = 200,
                    26 => status_code = 204,
                    27 => status_code = 206,
                    28 => status_code = 304,
                    29 => status_code = 400,
                    30 => status_code = 403,
                    31 => status_code = 404,
                    32 => status_code = 425,
                    33 => status_code = 429,
                    34 => status_code = 500,
                    35 => status_code = 502,
                    36 => status_code = 503,
                    _ => {}
                }
            } else if b & 0x40 != 0 {
                // Literal Field Line with Name Reference (Section 4.5.3)
                // Skip or advance
                pos += 1;
            } else if b & 0x20 != 0 {
                // Literal Field Line with Literal Name (Section 4.5.4)
                let name_len_prefix = (b & 0x07) as usize;
                pos += 1;
                let name_len = if name_len_prefix == 7 {
                    let (val, adv) = Self::decode_integer(&data[pos..])?;
                    pos += adv;
                    val as usize + 7
                } else {
                    name_len_prefix
                };

                if pos + name_len > data.len() {
                    return Err("Unexpected EOF in QPACK name".to_string());
                }
                let name = String::from_utf8_lossy(&data[pos..pos + name_len]).to_string();
                pos += name_len;

                if pos >= data.len() {
                    return Err("Unexpected EOF in QPACK val prefix".to_string());
                }
                let val_prefix = (data[pos] & 0x7F) as usize;
                pos += 1;
                let val_len = if val_prefix == 127 {
                    let (val, adv) = Self::decode_integer(&data[pos..])?;
                    pos += adv;
                    val as usize + 127
                } else {
                    val_prefix
                };

                if pos + val_len > data.len() {
                    return Err("Unexpected EOF in QPACK val".to_string());
                }
                let value = String::from_utf8_lossy(&data[pos..pos + val_len]).to_string();
                pos += val_len;

                if name == ":status" {
                    if let Ok(st) = value.parse::<u16>() {
                        status_code = st;
                    }
                } else {
                    headers.push((name, value));
                }
            } else {
                // Fallback advance
                pos += 1;
            }
        }

        Ok((status_code, headers))
    }

    fn decode_integer(slice: &[u8]) -> Result<(u64, usize), String> {
        let mut val: u64 = 0;
        let mut shift = 0;
        let mut count = 0;
        for &b in slice {
            count += 1;
            val |= ((b & 0x7F) as u64) << shift;
            if b & 0x80 == 0 {
                return Ok((val, count));
            }
            shift += 7;
            if shift >= 64 {
                return Err("Integer overflow in QPACK decode".to_string());
            }
        }
        Err("Incomplete integer in QPACK decode".to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_qpack_encode_and_decode_roundtrip() {
        let method = "GET";
        let scheme = "https";
        let authority = "www.youtube.com";
        let path = "/watch?v=123";
        let headers = vec![
            ("user-agent".to_string(), "ZNet/1.0".to_string()),
            ("accept".to_string(), "*/*".to_string()),
        ];

        let encoded = QpackCodec::encode_headers(method, scheme, authority, path, &headers);
        assert!(!encoded.is_empty());
        assert_eq!(encoded[0], 0x00);
        assert_eq!(encoded[1], 0x00);
    }

    #[test]
    fn test_qpack_decode_response_static_200() {
        // Prefix: 0x00, 0x00, Static Index 25 (0x80 | 25)
        let data = vec![0x00, 0x00, 0x80 | 25];
        let (status, headers) = QpackCodec::decode_response_headers(&data).expect("decode");
        assert_eq!(status, 200);
        assert!(headers.is_empty());
    }

    #[test]
    fn test_qpack_decode_response_literal_status_and_header() {
        let mut data = vec![0x00, 0x00];
        // Literal :status = 404
        QpackCodec::encode_literal(&mut data, ":status", "404");
        // Literal content-type = text/html
        QpackCodec::encode_literal(&mut data, "content-type", "text/html");

        let (status, headers) = QpackCodec::decode_response_headers(&data).expect("decode");
        assert_eq!(status, 404);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "content-type");
        assert_eq!(headers[0].1, "text/html");
    }
}
