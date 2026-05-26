use url::Url;
use std::fs::File;
use std::io::Read;
use flate2::read::GzDecoder;
use brotli::Decompressor;



pub struct SmartMiddleware {
    max_redirects: u32,
}

impl SmartMiddleware {
    pub fn new() -> Self {
        Self {
            max_redirects: 5,
        }
    }

    /// Handles file:// URLs by reading from the local filesystem
    pub fn handle_file_url(&self, url: &Url) -> Result<Vec<u8>, std::io::Error> {
        let path = url.to_file_path().map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, "Invalid file URL path")
        })?;
        let mut file = File::open(path)?;
        let mut buffer = Vec::new();
        file.read_to_end(&mut buffer)?;
        Ok(buffer)
    }

    /// Decompresses content based on the encoding type
    pub fn decompress(&self, data: &[u8], encoding: &str) -> Result<Vec<u8>, std::io::Error> {
        let mut decompressed = Vec::new();
        // Limit decompressed size to 10MB to prevent zip bomb OOM crashes
        let max_size = 10 * 1024 * 1024;
        match encoding {
            "gzip" => {
                let mut decoder = GzDecoder::new(data).take(max_size);
                decoder.read_to_end(&mut decompressed)?;
            }
            "br" | "brotli" => {
                let mut decoder = Decompressor::new(data, 4096).take(max_size);
                decoder.read_to_end(&mut decompressed)?;
            }
            _ => {
                decompressed.extend_from_slice(data);
            }
        }
        Ok(decompressed)
    }

    /// Handles automatic redirection logic
    pub fn handle_redirect(&self, status_code: u16, location: Option<&str>, redirect_count: &mut u32, base_url: &Url) -> Option<Url> {
        if (300..400).contains(&status_code) {
            if *redirect_count < self.max_redirects {
                if let Some(loc) = location {
                    if let Ok(new_url) = base_url.join(loc) {
                        *redirect_count += 1;
                        return Some(new_url);
                    }
                }
            }
        }
        None
    }

    /// Prepares SNI (Server Name Indication) logic for HTTPS requests
    pub fn get_sni_hostname<'a>(&self, url: &'a Url) -> Option<&'a str> {
        if url.scheme() == "https" {
            url.host_str()
        } else {
            None
        }
    }

    /// Cookie injection placeholder
    pub fn inject_cookies(&self, _url: &Url) -> String {
        // Here we'd integrate with the `cookie` crate and our cookie jar
        String::new()
    }
}

pub struct FetchEngine {
    pub middleware: SmartMiddleware,
    pub response_data: Option<Vec<u8>>,
    pub response_status: u16,
    pub is_done: bool,
}

impl FetchEngine {
    pub fn new() -> Self {
        Self {
            middleware: SmartMiddleware::new(),
            response_data: None,
            response_status: 0,
            is_done: false,
        }
    }

    pub fn fetch(&mut self, mut url: Url) {
        let mut redirect_count = 0;

        loop {
            // 1. Protocol Awareness
            if url.scheme() == "file" {
                match self.middleware.handle_file_url(&url) {
                    Ok(data) => {
                        self.response_data = Some(data);
                        self.response_status = 200;
                        self.is_done = true;
                        break;
                    }
                    Err(_) => {
                        self.response_status = 404;
                        self.is_done = true;
                        break;
                    }
                }
            }

            // 2. Network Fetch Setup (Simulated for this implementation)
            let _sni = self.middleware.get_sni_hostname(&url);
            let _cookies = self.middleware.inject_cookies(&url);

            // In a complete implementation, this would integrate with the actual NetEngine polling loop
            // to connect via TCP/TLS using the extracted `sni`.

            // Simulating a network request...
            let status_code = 200;
            let content_encoding = "gzip";
            let location_header: Option<&str> = None;
            // Simulated gzip response body for testing
            let raw_body = if content_encoding == "gzip" {
                use std::io::Write;
                let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
                encoder.write_all(b"Hello from simulated network response").unwrap();
                encoder.finish().unwrap()
            } else {
                b"Hello from simulated network response".to_vec()
            };

            // 3. Automatic Redirection
            if let Some(new_url) = self.middleware.handle_redirect(status_code, location_header, &mut redirect_count, &url) {
                url = new_url;
                continue;
            }

            // 4. Content-Encoding Decompression
            let decompressed_body = match self.middleware.decompress(&raw_body, content_encoding) {
                Ok(data) => data,
                Err(_) => raw_body, // Fallback to raw on error
            };

            // Store response in engine state
            self.response_data = Some(decompressed_body);
            self.response_status = status_code;
            self.is_done = true;
            break;
        }
    }

    pub fn read_response(&self, buffer: &mut [u8]) -> usize {
        if let Some(data) = &self.response_data {
            let len = std::cmp::min(buffer.len(), data.len());
            buffer[..len].copy_from_slice(&data[..len]);
            len
        } else {
            0
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use url::Url;

    #[test]
    fn test_middleware_creation() {
        let middleware = SmartMiddleware::new();
        assert_eq!(middleware.max_redirects, 5);
    }

    #[test]
    fn test_sni_hostname() {
        let middleware = SmartMiddleware::new();
        let https_url = Url::parse("https://example.com").unwrap();
        assert_eq!(middleware.get_sni_hostname(&https_url), Some("example.com"));

        let http_url = Url::parse("http://example.com").unwrap();
        assert_eq!(middleware.get_sni_hostname(&http_url), None);
    }

    #[test]
    fn test_handle_redirect() {
        let middleware = SmartMiddleware::new();
        let mut redirect_count = 0;

        let new_url = middleware.handle_redirect(301, Some("https://example.com/new"), &mut redirect_count);
        assert!(new_url.is_some());
        assert_eq!(new_url.unwrap().as_str(), "https://example.com/new");
        assert_eq!(redirect_count, 1);

        // Exceed redirects
        redirect_count = 5;
        let no_url = middleware.handle_redirect(301, Some("https://example.com/new2"), &mut redirect_count);
        assert!(no_url.is_none());
        assert_eq!(redirect_count, 5);
    }
    
    #[test]
    fn test_fetch_engine_mock_network() {
        let mut engine = FetchEngine::new();
        let url = Url::parse("https://example.com").unwrap();
        engine.fetch(url);

        assert!(engine.is_done);
        assert_eq!(engine.response_status, 200);
        let data = engine.response_data.unwrap();
        assert_eq!(data, b"Hello from simulated network response");
    }
}
