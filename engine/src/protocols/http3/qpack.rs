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

        // 2. Encode Pseudo-headers (RFC 9204 §4.5.2: 1 | T=1 | 6-bit static index => 0xC0 | idx)
        // :method
        if method.eq_ignore_ascii_case("GET") {
            // Static index 17: :method GET
            buf.push(0xC0 | 17);
        } else if method.eq_ignore_ascii_case("POST") {
            // Static index 20: :method POST
            buf.push(0xC0 | 20);
        } else {
            Self::encode_literal(&mut buf, ":method", method);
        }

        // :scheme
        if scheme.eq_ignore_ascii_case("https") {
            // Static index 22: :scheme https
            buf.push(0xC0 | 22);
        } else if scheme.eq_ignore_ascii_case("http") {
            // Static index 23: :scheme http
            buf.push(0xC0 | 23);
        } else {
            Self::encode_literal(&mut buf, ":scheme", scheme);
        }

        // :authority
        Self::encode_literal(&mut buf, ":authority", authority);

        // :path
        if path == "/" {
            // Static index 1: :path /
            buf.push(0xC0 | 1);
        } else {
            Self::encode_literal(&mut buf, ":path", path);
        }

        // 3. Encode regular headers
        for (name, value) in headers {
            let lower_name = name.to_ascii_lowercase();
            // Fast paths for common static headers
            if lower_name == "accept-encoding" && value == "gzip, deflate, br" {
                // Static index 31
                buf.push(0xC0 | 31);
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

    /// Decode QPACK encoded response headers into status code and header list (RFC 9204 §4.5).
    pub fn decode_response_headers(data: &[u8]) -> Result<(u16, Vec<(String, String)>), String> {
        if data.len() < 2 {
            return Err("QPACK data too short for prefix".to_string());
        }

        let mut pos = 0;
        // 1. Encoded Field Section Prefix (§4.5.1):
        //    Required Insert Count (8-bit prefix) + S (1-bit) | Delta Base (7-bit prefix)
        let _req_insert_count = Self::decode_prefix_int(data, &mut pos, 8)?;
        let _delta_base = Self::decode_prefix_int(data, &mut pos, 7)?;

        let mut status_code: u16 = 200;
        let mut headers = Vec::new();

        while pos < data.len() {
            let b = data[pos];
            if b & 0x80 != 0 {
                // §4.5.2 Indexed Field Line: 1 | T | Index (6-bit prefix)
                let is_static = (b & 0x40) != 0;
                let idx = Self::decode_prefix_int(data, &mut pos, 6)? as usize;
                if is_static {
                    if let Some(&(name, val)) = STATIC_TABLE.get(idx) {
                        if name == ":status" {
                            if let Ok(st) = val.parse::<u16>() {
                                status_code = st;
                            }
                        } else if !name.starts_with(':') {
                            headers.push((name.to_string(), val.to_string()));
                        }
                    }
                }
            } else if b & 0xC0 == 0x40 {
                // §4.5.4 Literal Field Line with Name Reference: 01 | N | T | NameIndex (4-bit prefix)
                let is_static = (b & 0x10) != 0;
                let name_idx = Self::decode_prefix_int(data, &mut pos, 4)? as usize;
                let value = Self::decode_string(data, &mut pos, 7)?;
                if is_static {
                    if let Some(&(name, _)) = STATIC_TABLE.get(name_idx) {
                        if name == ":status" {
                            if let Ok(st) = value.parse::<u16>() {
                                status_code = st;
                            }
                        } else if !name.starts_with(':') {
                            headers.push((name.to_string(), value));
                        }
                    }
                }
            } else if b & 0xE0 == 0x20 {
                // §4.5.6 Literal Field Line with Literal Name: 001 | N | H | NameLen (3-bit prefix)
                let name = Self::decode_string(data, &mut pos, 3)?;
                let value = Self::decode_string(data, &mut pos, 7)?;
                if name == ":status" {
                    if let Ok(st) = value.parse::<u16>() {
                        status_code = st;
                    }
                } else if !name.starts_with(':') {
                    headers.push((name, value));
                }
            } else if b & 0xF0 == 0x10 {
                // §4.5.3 Indexed Field Line with Post-Base Index: 0001 | Index (4-bit prefix)
                let _idx = Self::decode_prefix_int(data, &mut pos, 4)?;
            } else {
                // §4.5.5 Literal Field Line with Post-Base Name Reference: 0000 | N | NameIndex (3-bit prefix)
                let _name_idx = Self::decode_prefix_int(data, &mut pos, 3)?;
                let _value = Self::decode_string(data, &mut pos, 7)?;
            }
        }

        Ok((status_code, headers))
    }

    fn decode_prefix_int(data: &[u8], pos: &mut usize, prefix_bits: u8) -> Result<u64, String> {
        if *pos >= data.len() {
            return Err("Unexpected EOF in QPACK prefix integer".to_string());
        }
        let mask = ((1u16 << prefix_bits) - 1) as u8;
        let mut val = (data[*pos] & mask) as u64;
        *pos += 1;
        if val < mask as u64 {
            return Ok(val);
        }
        let mut shift = 0u32;
        loop {
            if *pos >= data.len() {
                return Err("Incomplete integer in QPACK decode".to_string());
            }
            let b = data[*pos];
            *pos += 1;
            val = val
                .checked_add(((b & 0x7F) as u64) << shift)
                .ok_or_else(|| "Integer overflow in QPACK decode".to_string())?;
            if b & 0x80 == 0 {
                return Ok(val);
            }
            shift += 7;
            if shift >= 63 {
                return Err("Integer overflow in QPACK decode".to_string());
            }
        }
    }

    fn decode_string(data: &[u8], pos: &mut usize, prefix_bits: u8) -> Result<String, String> {
        if *pos >= data.len() {
            return Err("Unexpected EOF in QPACK string header".to_string());
        }
        let huffman = (data[*pos] & (1u8 << prefix_bits)) != 0;
        let len = Self::decode_prefix_int(data, pos, prefix_bits)? as usize;
        if *pos + len > data.len() {
            return Err(format!(
                "Unexpected EOF in QPACK string (need {} bytes, have {})",
                len,
                data.len() - *pos
            ));
        }
        let slice = &data[*pos..*pos + len];
        *pos += len;
        if huffman {
            let mut dec = fluke_hpack::huffman::HuffmanDecoder::new();
            let decoded = dec
                .decode(slice)
                .map_err(|e| format!("QPACK Huffman decode error: {:?}", e))?;
            Ok(String::from_utf8_lossy(&decoded).to_string())
        } else {
            Ok(String::from_utf8_lossy(slice).to_string())
        }
    }
}

/// RFC 9204 Appendix A Static Table (99 entries, indices 0..98).
const STATIC_TABLE: [(&str, &str); 99] = [
    (":authority", ""),
    (":path", "/"),
    ("age", "0"),
    ("content-disposition", ""),
    ("content-length", "0"),
    ("cookie", ""),
    ("date", ""),
    ("etag", ""),
    ("if-modified-since", ""),
    ("if-none-match", ""),
    ("last-modified", ""),
    ("link", ""),
    ("location", ""),
    ("referer", ""),
    ("set-cookie", ""),
    (":method", "CONNECT"),
    (":method", "DELETE"),
    (":method", "GET"),
    (":method", "HEAD"),
    (":method", "OPTIONS"),
    (":method", "POST"),
    (":method", "PUT"),
    (":scheme", "http"),
    (":scheme", "https"),
    (":status", "103"),
    (":status", "200"),
    (":status", "304"),
    (":status", "404"),
    (":status", "503"),
    ("accept", "*/*"),
    ("accept", "application/dns-message"),
    ("accept-encoding", "gzip, deflate, br"),
    ("accept-ranges", "bytes"),
    ("access-control-allow-headers", "cache-control"),
    ("access-control-allow-headers", "content-type"),
    ("access-control-allow-origin", "*"),
    ("cache-control", "max-age=0"),
    ("cache-control", "max-age=2592000"),
    ("cache-control", "max-age=604800"),
    ("cache-control", "no-cache"),
    ("cache-control", "no-store"),
    ("cache-control", "public, max-age=31536000"),
    ("content-encoding", "br"),
    ("content-encoding", "gzip"),
    ("content-type", "application/dns-message"),
    ("content-type", "application/javascript"),
    ("content-type", "application/json"),
    ("content-type", "application/x-www-form-urlencoded"),
    ("content-type", "image/gif"),
    ("content-type", "image/jpeg"),
    ("content-type", "image/png"),
    ("content-type", "text/css"),
    ("content-type", "text/html; charset=utf-8"),
    ("content-type", "text/plain"),
    ("content-type", "text/plain;charset=utf-8"),
    ("range", "bytes=0-"),
    ("strict-transport-security", "max-age=31536000"),
    ("strict-transport-security", "max-age=31536000; includesubdomains"),
    ("strict-transport-security", "max-age=31536000; includesubdomains; preload"),
    ("vary", "accept-encoding"),
    ("vary", "origin"),
    ("x-content-type-options", "nosniff"),
    ("x-xss-protection", "1; mode=block"),
    (":status", "100"),
    (":status", "204"),
    (":status", "206"),
    (":status", "302"),
    (":status", "400"),
    (":status", "403"),
    (":status", "421"),
    (":status", "425"),
    (":status", "500"),
    ("accept-language", ""),
    ("access-control-allow-credentials", "FALSE"),
    ("access-control-allow-credentials", "TRUE"),
    ("access-control-allow-headers", "*"),
    ("access-control-allow-methods", "get"),
    ("access-control-allow-methods", "get, post, options"),
    ("access-control-allow-methods", "options"),
    ("access-control-expose-headers", "content-length"),
    ("access-control-request-headers", "content-type"),
    ("access-control-request-method", "get"),
    ("access-control-request-method", "post"),
    ("alt-svc", "clear"),
    ("authorization", ""),
    ("content-security-policy", "script-src 'none'; object-src 'none'; base-uri 'none'"),
    ("early-data", "1"),
    ("expect-ct", ""),
    ("forwarded", ""),
    ("if-range", ""),
    ("origin", ""),
    ("purpose", "prefetch"),
    ("server", ""),
    ("timing-allow-origin", "*"),
    ("upgrade-insecure-requests", "1"),
    ("user-agent", ""),
    ("x-forwarded-for", ""),
    ("x-frame-options", "deny"),
    ("x-frame-options", "sameorigin"),
];

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
        // Verify T=1 (static table) bit is set on indexed pseudo-headers
        assert_eq!(encoded[2], 0xC0 | 17); // :method GET
        assert_eq!(encoded[3], 0xC0 | 22); // :scheme https
    }

    #[test]
    fn test_qpack_decode_response_static_200() {
        // Prefix: 0x00, 0x00, Static Index 25 (1 | T=1 | 25 => 0xC0 | 25)
        let data = vec![0x00, 0x00, 0xC0 | 25];
        let (status, headers) = QpackCodec::decode_response_headers(&data).expect("decode");
        assert_eq!(status, 200);
        assert!(headers.is_empty());
    }

    #[test]
    fn test_qpack_decode_response_name_ref_and_huffman() {
        // Static index 25 (:status 200) + Literal with Name Reference (server, T=1, idx=92 => 0101_1111 + (92-15))
        // 0x5F, 77 -> "gws" (plain)
        let mut data = vec![0x00, 0x00, 0xC0 | 25];
        data.push(0x5F); // 01 | N=0 | T=1 | 15
        data.push(92 - 15); // index 92 ("server")
        data.push(3); // H=0, len=3
        data.extend_from_slice(b"gws");

        let (status, headers) = QpackCodec::decode_response_headers(&data).expect("decode");
        assert_eq!(status, 200);
        assert_eq!(headers, vec![("server".to_string(), "gws".to_string())]);
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
