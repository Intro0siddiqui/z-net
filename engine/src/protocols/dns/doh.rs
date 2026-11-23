//! DNS-over-HTTPS (DoH) client per RFC 8484.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::time::Duration;

use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, StreamOwned};
use url::Url;

use super::wire::{DnsRecord, DnsRecordType, DnsWireCodec};

pub struct DohClient {
    tls_config: Arc<ClientConfig>,
    endpoint_url: String, // e.g. "https://cloudflare-dns.com/dns-query"
    timeout: Duration,
}

impl DohClient {
    pub fn new(tls_config: Arc<ClientConfig>, endpoint_url: &str) -> Self {
        Self {
            tls_config,
            endpoint_url: endpoint_url.to_string(),
            timeout: Duration::from_secs(4),
        }
    }

    /// Query the DoH server using RFC 8484 wireformat POST request.
    pub fn resolve(&self, hostname: &str, record_type: DnsRecordType) -> Result<Vec<DnsRecord>, String> {
        let parsed = Url::parse(&self.endpoint_url)
            .map_err(|e| format!("Invalid DoH URL: {}", e))?;

        let host = parsed.host_str().ok_or("DoH URL missing host")?;
        let port = parsed.port_or_known_default().unwrap_or(443);
        let path = parsed.path();

        let addr_str = format!("{}:{}", host, port);
        let addrs: Vec<SocketAddr> = addr_str
            .to_socket_addrs()
            .map_err(|e| format!("DoH endpoint DNS resolution failed: {}", e))?
            .collect();

        let mut tcp = None;
        for addr in addrs {
            if let Ok(s) = TcpStream::connect_timeout(&addr, self.timeout) {
                let _ = s.set_nodelay(true);
                let _ = s.set_read_timeout(Some(self.timeout));
                let _ = s.set_write_timeout(Some(self.timeout));
                tcp = Some(s);
                break;
            }
        }
        let tcp = tcp.ok_or(format!("Could not connect to DoH server {}", addr_str))?;

        let server_name = ServerName::try_from(host)
            .map_err(|e| format!("Invalid DoH TLS server name: {}", e))?
            .to_owned();

        let tls_conn = ClientConnection::new(self.tls_config.clone(), server_name)
            .map_err(|e| format!("DoH TLS handshake init failed: {}", e))?;

        let mut stream = StreamOwned::new(tls_conn, tcp);

        // Encode RFC 1035 query
        let query_id = 0u16; // DoH recommends ID=0 for HTTP/2 and HTTP/3 caching
        let query_bytes = DnsWireCodec::encode_query(query_id, hostname, record_type);

        // Send HTTP/1.1 POST per RFC 8484
        let request = format!(
            "POST {} HTTP/1.1\r\n\
             Host: {}\r\n\
             Content-Type: application/dns-message\r\n\
             Accept: application/dns-message\r\n\
             Content-Length: {}\r\n\
             Connection: close\r\n\r\n",
            path, host, query_bytes.len()
        );

        stream.write_all(request.as_bytes())
            .map_err(|e| format!("DoH request write failed: {}", e))?;
        stream.write_all(&query_bytes)
            .map_err(|e| format!("DoH body write failed: {}", e))?;
        stream.flush()
            .map_err(|e| format!("DoH flush failed: {}", e))?;

        // Read HTTP response
        let mut resp_bytes = Vec::new();
        let mut read_buf = [0u8; 2048];
        loop {
            match stream.read(&mut read_buf) {
                Ok(0) => break,
                Ok(n) => resp_bytes.extend_from_slice(&read_buf[..n]),
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(e) => return Err(format!("DoH read error: {}", e)),
            }
        }

        // Split HTTP headers from body
        let header_end = resp_bytes
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .ok_or("Invalid DoH HTTP response (no header boundary)")?;

        let header_str = String::from_utf8_lossy(&resp_bytes[..header_end]);
        if !header_str.contains(" 200 ") {
            return Err(format!("DoH server returned non-200 response: {}", header_str.lines().next().unwrap_or("")));
        }

        let body = &resp_bytes[header_end + 4..];
        DnsWireCodec::decode_response(body)
    }
}
