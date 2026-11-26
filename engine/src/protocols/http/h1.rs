/// Result of feeding bytes into the HTTP/1.1 response state machine.
#[derive(Debug, PartialEq)]
pub enum Http1FeedResult {
    /// Need more data from the network to make progress.
    NeedMoreData,
    /// Response headers have been parsed. Carries (status_code, reason, headers, is_chunked, content_length, keep_alive).
    HeadersParsed {
        status_code: u16,
        reason: String,
        headers: Vec<(String, String)>,
        is_chunked: bool,
        content_length: Option<usize>,
        keep_alive: bool,
    },
    /// A slice of decoded body bytes is ready for delivery to the consumer.
    BodyData(Vec<u8>),
    /// The entire response (including all body bytes) has been received.
    Complete {
        keep_alive: bool,
    },
}

#[derive(Debug, PartialEq, Clone, Copy)]
enum ChunkState {
    ReadSize,
    ReadData(usize),
    ReadCrlf,
    ReadTrailers,
}

#[derive(Debug, PartialEq)]
enum ParserState {
    AwaitingHeaders,
    FixedBody { remaining: usize },
    ChunkedBody { state: ChunkState },
    CloseDelimited,
    Finished,
}

/// A robust, zero-allocation-where-possible HTTP/1.1 response parser and state machine.
pub struct Http1ResponseParser {
    state: ParserState,
    buffer: Vec<u8>,
    keep_alive: bool,
}

impl Default for Http1ResponseParser {
    fn default() -> Self {
        Self::new()
    }
}

impl Http1ResponseParser {
    pub fn new() -> Self {
        Self {
            state: ParserState::AwaitingHeaders,
            buffer: Vec::with_capacity(4096),
            keep_alive: true,
        }
    }

    /// Reset parser for reusing on a pooled keep-alive connection.
    pub fn reset(&mut self) {
        self.state = ParserState::AwaitingHeaders;
        self.buffer.clear();
        self.keep_alive = true;
    }

    /// Feed incoming network bytes into the parser.
    pub fn feed(&mut self, chunk: &[u8]) -> Result<Vec<Http1FeedResult>, &'static str> {
        self.buffer.extend_from_slice(chunk);
        let mut results = Vec::new();

        loop {
            match self.state {
                ParserState::AwaitingHeaders => {
                    let mut headers_storage = [httparse::EMPTY_HEADER; 64];
                    let mut resp = httparse::Response::new(&mut headers_storage);

                    match resp.parse(&self.buffer) {
                        Ok(httparse::Status::Complete(header_len)) => {
                            let status = resp.code.ok_or("Missing HTTP status code")?;
                            let reason = resp.reason.unwrap_or("").to_string();

                            let mut headers = Vec::with_capacity(resp.headers.len());
                            let mut is_chunked = false;
                            let mut content_length = None;
                            let mut conn_close = false;
                            let mut conn_keep_alive = false;

                            for h in resp.headers.iter() {
                                let name = h.name.to_string();
                                let val = String::from_utf8_lossy(h.value).trim().to_string();

                                if name.eq_ignore_ascii_case("transfer-encoding") && val.to_ascii_lowercase().contains("chunked") {
                                    is_chunked = true;
                                } else if name.eq_ignore_ascii_case("content-length") {
                                    if let Ok(len) = val.parse::<usize>() {
                                        content_length = Some(len);
                                    }
                                } else if name.eq_ignore_ascii_case("connection") {
                                    if val.eq_ignore_ascii_case("close") {
                                        conn_close = true;
                                    } else if val.eq_ignore_ascii_case("keep-alive") {
                                        conn_keep_alive = true;
                                    }
                                }
                                headers.push((name, val));
                            }

                            // HTTP/1.1 defaults to keep-alive unless "Connection: close" is specified.
                            // HTTP/1.0 defaults to close unless "Connection: keep-alive" is specified.
                            let is_http_10 = resp.version == Some(0);
                            self.keep_alive = if is_http_10 {
                                conn_keep_alive
                            } else {
                                !conn_close
                            };

                            // Check for responses that must NOT have a message body (RFC 7230 §3.3.2)
                            let is_no_body = (100..200).contains(&status) || status == 204 || status == 304;

                            let next_state = if is_no_body || content_length == Some(0) {
                                ParserState::Finished
                            } else if is_chunked {
                                ParserState::ChunkedBody {
                                    state: ChunkState::ReadSize,
                                }
                            } else if let Some(len) = content_length {
                                ParserState::FixedBody { remaining: len }
                            } else {
                                ParserState::CloseDelimited
                            };

                            self.state = next_state;
                            // Drain header bytes from buffer, retaining any initial body bytes
                            self.buffer.drain(0..header_len);

                            results.push(Http1FeedResult::HeadersParsed {
                                status_code: status,
                                reason,
                                headers,
                                is_chunked,
                                content_length,
                                keep_alive: self.keep_alive,
                            });

                            if self.state == ParserState::Finished {
                                results.push(Http1FeedResult::Complete {
                                    keep_alive: self.keep_alive,
                                });
                                break;
                            }
                        }
                        Ok(httparse::Status::Partial) => {
                            results.push(Http1FeedResult::NeedMoreData);
                            break;
                        }
                        Err(_) => return Err("Failed to parse HTTP headers"),
                    }
                }

                ParserState::FixedBody { ref mut remaining } => {
                    if self.buffer.is_empty() {
                        results.push(Http1FeedResult::NeedMoreData);
                        break;
                    }

                    let available = self.buffer.len();
                    let to_take = (*remaining).min(available);
                    let body_data: Vec<u8> = self.buffer.drain(0..to_take).collect();
                    *remaining -= to_take;

                    results.push(Http1FeedResult::BodyData(body_data));

                    if *remaining == 0 {
                        self.state = ParserState::Finished;
                        results.push(Http1FeedResult::Complete {
                            keep_alive: self.keep_alive,
                        });
                        break;
                    }
                }

                ParserState::ChunkedBody { ref mut state } => {
                    match *state {
                        ChunkState::ReadSize => {
                            // Find "\r\n" terminating the chunk-size line
                            if let Some(pos) = find_crlf(&self.buffer) {
                                let line = &self.buffer[..pos];
                                // Chunk size may be followed by optional chunk extensions: ";foo=bar"
                                let size_str = match line.split(|&b| b == b';').next() {
                                    Some(s) => std::str::from_utf8(s).map_err(|_| "Invalid UTF-8 in chunk size")?.trim(),
                                    None => "",
                                };
                                let chunk_size = usize::from_str_radix(size_str, 16)
                                    .map_err(|_| "Invalid hex in chunk size")?;

                                // Drain size line + \r\n
                                self.buffer.drain(0..pos + 2);

                                if chunk_size == 0 {
                                    *state = ChunkState::ReadTrailers;
                                } else {
                                    *state = ChunkState::ReadData(chunk_size);
                                }
                            } else {
                                results.push(Http1FeedResult::NeedMoreData);
                                break;
                            }
                        }

                        ChunkState::ReadData(remaining) => {
                            if self.buffer.is_empty() {
                                results.push(Http1FeedResult::NeedMoreData);
                                break;
                            }

                            let to_take = remaining.min(self.buffer.len());
                            let data: Vec<u8> = self.buffer.drain(0..to_take).collect();
                            results.push(Http1FeedResult::BodyData(data));

                            let new_remaining = remaining - to_take;
                            if new_remaining == 0 {
                                *state = ChunkState::ReadCrlf;
                            } else {
                                *state = ChunkState::ReadData(new_remaining);
                            }
                        }

                        ChunkState::ReadCrlf => {
                            if self.buffer.len() >= 2 {
                                if &self.buffer[..2] == b"\r\n" {
                                    self.buffer.drain(0..2);
                                    *state = ChunkState::ReadSize;
                                } else {
                                    return Err("Missing CRLF after chunk data");
                                }
                            } else {
                                results.push(Http1FeedResult::NeedMoreData);
                                break;
                            }
                        }

                        ChunkState::ReadTrailers => {
                            // Trailers terminate on an empty line "\r\n"
                            if self.buffer.starts_with(b"\r\n") {
                                self.buffer.drain(0..2);
                                self.state = ParserState::Finished;
                                results.push(Http1FeedResult::Complete {
                                    keep_alive: self.keep_alive,
                                });
                                break;
                            } else if let Some(pos) = find_crlf(&self.buffer) {
                                // Skip trailer line
                                self.buffer.drain(0..pos + 2);
                            } else {
                                results.push(Http1FeedResult::NeedMoreData);
                                break;
                            }
                        }
                    }
                }

                ParserState::CloseDelimited => {
                    if self.buffer.is_empty() {
                        results.push(Http1FeedResult::NeedMoreData);
                        break;
                    }
                    let data = std::mem::take(&mut self.buffer);
                    results.push(Http1FeedResult::BodyData(data));
                }

                ParserState::Finished => {
                    break;
                }
            }
        }

        Ok(results)
    }

    /// Notify that the connection reached EOF (useful for close-delimited streams).
    pub fn on_eof(&mut self) -> Vec<Http1FeedResult> {
        let mut results = Vec::new();
        if let ParserState::CloseDelimited = self.state {
            if !self.buffer.is_empty() {
                results.push(Http1FeedResult::BodyData(std::mem::take(&mut self.buffer)));
            }
            self.state = ParserState::Finished;
            results.push(Http1FeedResult::Complete { keep_alive: false });
        }
        results
    }
}

fn find_crlf(buf: &[u8]) -> Option<usize> {
    buf.windows(2).position(|w| w == b"\r\n")
}

/// Builds an HTTP/1.1 wire-formatted request with strict insertion-order header preservation.
pub struct Http1RequestBuilder<'a> {
    method: &'a str,
    path: &'a str,
    headers: Vec<(String, String)>,
    body: Option<&'a [u8]>,
}

impl<'a> Http1RequestBuilder<'a> {
    pub fn new(method: &'a str, path: &'a str) -> Self {
        Self {
            method,
            path,
            headers: Vec::new(),
            body: None,
        }
    }

    /// Append a header while preserving exact insertion order.
    pub fn header(mut self, name: &str, value: &str) -> Self {
        self.headers.push((name.to_string(), value.to_string()));
        self
    }

    pub fn body(mut self, body: &'a [u8]) -> Self {
        self.body = Some(body);
        self
    }

    /// Serialize into the HTTP/1.1 wire protocol buffer, preserving outgoing header order.
    pub fn serialize(mut self, host: &str, keep_alive: bool) -> Vec<u8> {
        let mut out = Vec::with_capacity(512);

        // 1. Request Line
        out.extend_from_slice(self.method.as_bytes());
        out.push(b' ');
        out.extend_from_slice(self.path.as_bytes());
        out.extend_from_slice(b" HTTP/1.1\r\n");

        // 2. Host Header (RFC 7230 mandatory)
        if !self.headers.iter().any(|(k, _)| k.eq_ignore_ascii_case("host")) {
            out.extend_from_slice(b"Host: ");
            out.extend_from_slice(host.as_bytes());
            out.extend_from_slice(b"\r\n");
        }

        // 3. Connection Header
        if !self.headers.iter().any(|(k, _)| k.eq_ignore_ascii_case("connection")) {
            if keep_alive {
                out.extend_from_slice(b"Connection: keep-alive\r\n");
            } else {
                out.extend_from_slice(b"Connection: close\r\n");
            }
        }

        // 4. Body Content-Length
        if let Some(b) = self.body {
            if !self.headers.iter().any(|(k, _)| k.eq_ignore_ascii_case("content-length")) {
                let cl = format!("Content-Length: {}\r\n", b.len());
                out.extend_from_slice(cl.as_bytes());
            }
        }

        // 5. User custom headers in exact insertion order
        for (k, v) in self.headers.drain(..) {
            out.extend_from_slice(k.as_bytes());
            out.extend_from_slice(b": ");
            out.extend_from_slice(v.as_bytes());
            out.extend_from_slice(b"\r\n");
        }

        out.extend_from_slice(b"\r\n");

        // 6. Append body payload if present
        if let Some(b) = self.body {
            out.extend_from_slice(b);
        }

        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_serialize_get_request() {
        let req = Http1RequestBuilder::new("GET", "/index.html")
            .header("User-Agent", "Zawra/1.0")
            .serialize("example.com", true);

        let req_str = String::from_utf8(req).unwrap();
        assert!(req_str.starts_with("GET /index.html HTTP/1.1\r\n"));
        assert!(req_str.contains("Host: example.com\r\n"));
        assert!(req_str.contains("Connection: keep-alive\r\n"));
        assert!(req_str.contains("User-Agent: Zawra/1.0\r\n"));
        assert!(req_str.ends_with("\r\n\r\n"));
    }

    #[test]
    fn test_h1_request_builder_preserves_header_order() {
        let req = Http1RequestBuilder::new("GET", "/fingerprint")
            .header("Host", "example.com")
            .header("Connection", "keep-alive")
            .header("sec-ch-ua", "\"Chromium\";v=\"131\"")
            .header("sec-ch-ua-mobile", "?0")
            .header("User-Agent", "Mozilla/5.0")
            .header("Accept", "text/html,*/*;q=0.8")
            .header("Accept-Language", "en-US,en;q=0.9")
            .serialize("example.com", true);

        let req_str = String::from_utf8(req).unwrap();
        let expected = concat!(
            "GET /fingerprint HTTP/1.1\r\n",
            "Host: example.com\r\n",
            "Connection: keep-alive\r\n",
            "sec-ch-ua: \"Chromium\";v=\"131\"\r\n",
            "sec-ch-ua-mobile: ?0\r\n",
            "User-Agent: Mozilla/5.0\r\n",
            "Accept: text/html,*/*;q=0.8\r\n",
            "Accept-Language: en-US,en;q=0.9\r\n",
            "\r\n"
        );
        assert_eq!(req_str, expected);
    }

    #[test]
    fn test_serialize_post_request_with_body() {
        let payload = b"{\"key\":\"value\"}";
        let req = Http1RequestBuilder::new("POST", "/api/submit")
            .header("Content-Type", "application/json")
            .body(payload)
            .serialize("api.example.com", false);

        let req_str = String::from_utf8(req).unwrap();
        assert!(req_str.starts_with("POST /api/submit HTTP/1.1\r\n"));
        assert!(req_str.contains("Host: api.example.com\r\n"));
        assert!(req_str.contains("Connection: close\r\n"));
        assert!(req_str.contains("Content-Length: 15\r\n"));
        assert!(req_str.ends_with("\r\n{\"key\":\"value\"}"));
    }

    #[test]
    fn test_parse_fixed_content_length_response() {
        let mut parser = Http1ResponseParser::new();
        let raw = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 11\r\n\r\nHello World";

        let events = parser.feed(raw).expect("parse response");
        assert_eq!(events.len(), 3);

        match &events[0] {
            Http1FeedResult::HeadersParsed { status_code, content_length, .. } => {
                assert_eq!(*status_code, 200);
                assert_eq!(*content_length, Some(11));
            }
            _ => panic!("Expected HeadersParsed"),
        }

        assert_eq!(events[1], Http1FeedResult::BodyData(b"Hello World".to_vec()));
        assert_eq!(events[2], Http1FeedResult::Complete { keep_alive: true });
    }

    #[test]
    fn test_parse_chunked_transfer_encoding_response() {
        let mut parser = Http1ResponseParser::new();
        let raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nWiki\r\n6\r\npedia \r\nE\r\nin \r\n\r\nchunks.\r\n0\r\n\r\n";

        let events = parser.feed(raw).expect("parse chunked");

        let mut combined_body = Vec::new();
        let mut completed = false;

        for event in events {
            match event {
                Http1FeedResult::HeadersParsed { is_chunked, .. } => {
                    assert!(is_chunked);
                }
                Http1FeedResult::BodyData(chunk) => {
                    combined_body.extend_from_slice(&chunk);
                }
                Http1FeedResult::Complete { keep_alive } => {
                    assert!(keep_alive);
                    completed = true;
                }
                Http1FeedResult::NeedMoreData => {}
            }
        }

        assert!(completed, "chunked stream must complete");
        assert_eq!(
            String::from_utf8(combined_body).unwrap(),
            "Wikipedia in \r\n\r\nchunks."
        );
    }

    #[test]
    fn test_parse_chunked_with_extensions_and_trailers() {
        let mut parser = Http1ResponseParser::new();
        let raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5;ext=foo\r\nhello\r\n0\r\nTrailer-Key: Value\r\n\r\n";

        let events = parser.feed(raw).expect("parse chunked with ext");
        let mut combined = Vec::new();
        for ev in events {
            if let Http1FeedResult::BodyData(d) = ev {
                combined.extend_from_slice(&d);
            }
        }
        assert_eq!(combined, b"hello");
    }

    #[test]
    fn test_chunked_streaming_across_network_packets() {
        let mut parser = Http1ResponseParser::new();

        // Packet 1: Partial headers
        let ev1 = parser.feed(b"HTTP/1.1 200 OK\r\nTransfer-").unwrap();
        assert_eq!(ev1, vec![Http1FeedResult::NeedMoreData]);

        // Packet 2: Rest of headers + part of first chunk size
        let ev2 = parser.feed(b"Encoding: chunked\r\n\r\n4").unwrap();
        assert!(matches!(ev2[0], Http1FeedResult::HeadersParsed { .. }));

        // Packet 3: Rest of chunk size + chunk data
        let ev3 = parser.feed(b"\r\nTest\r\n0\r\n\r\n").unwrap();
        assert_eq!(ev3[0], Http1FeedResult::BodyData(b"Test".to_vec()));
        assert_eq!(ev3[1], Http1FeedResult::Complete { keep_alive: true });
    }
}
