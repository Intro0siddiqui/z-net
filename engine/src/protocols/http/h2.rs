use std::collections::HashMap;
use bytes::Bytes;
use http::{HeaderMap, HeaderName, HeaderValue, Method, Request, Uri};

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
        let uri = uri_str.parse::<Uri>()
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

    /// Build the standard `http::Request` containing pseudo-headers (:method, :scheme, :authority, :path).
    pub fn build(mut self) -> Result<(Request<()>, Option<Bytes>), String> {
        let mut builder = Request::builder()
            .method(self.method)
            .uri(self.uri);

        if let Some(headers_mut) = builder.headers_mut() {
            for (k, v) in self.headers.drain() {
                if let Some(name) = k {
                    headers_mut.insert(name, v);
                }
            }
        }

        let request = builder.body(()).map_err(|e| format!("Failed to build request: {}", e))?;
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

#[cfg(test)]
mod tests {
    use super::*;

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
}
