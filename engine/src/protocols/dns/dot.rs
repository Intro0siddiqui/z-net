//! DNS-over-TLS (DoT) client per RFC 7858.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::time::Duration;

use crate::protocols::tls::BoringTlsConfig;

use super::wire::{DnsRecord, DnsRecordType, DnsWireCodec};

pub struct DotClient {
    tls_config: Arc<BoringTlsConfig>,
    server_addr: String, // e.g. "1.1.1.1:853"
    server_name: String, // e.g. "cloudflare-dns.com" or "1.1.1.1"
    timeout: Duration,
}

impl DotClient {
    pub fn new(tls_config: Arc<BoringTlsConfig>, server_addr: &str, server_name: &str) -> Self {
        Self {
            tls_config,
            server_addr: server_addr.to_string(),
            server_name: server_name.to_string(),
            timeout: Duration::from_secs(4),
        }
    }

    /// Query the DoT server for records matching the hostname and record type.
    pub fn resolve(&self, hostname: &str, record_type: DnsRecordType) -> Result<Vec<DnsRecord>, String> {
        let addrs: Vec<SocketAddr> = self.server_addr
            .to_socket_addrs()
            .map_err(|e| format!("DoT server DNS resolution failed: {}", e))?
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
        let tcp = tcp.ok_or(format!("Could not connect to DoT server {}", self.server_addr))?;

        let mut stream = self
            .tls_config
            .connect_blocking(&self.server_name, tcp, Some(b"\x08http/1.1"))
            .map_err(|e| format!("DoT TLS handshake failed: {}", e))?;

        // Encode RFC 1035 query
        let query_id = (std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .subsec_nanos() & 0xFFFF) as u16;
        let query_bytes = DnsWireCodec::encode_query(query_id, hostname, record_type);

        // RFC 7858: 2-byte length prefix
        let len_prefix = (query_bytes.len() as u16).to_be_bytes();
        stream.write_all(&len_prefix)
            .map_err(|e| format!("DoT write len failed: {}", e))?;
        stream.write_all(&query_bytes)
            .map_err(|e| format!("DoT write query failed: {}", e))?;
        stream.flush()
            .map_err(|e| format!("DoT flush failed: {}", e))?;

        // Read 2-byte length prefix response
        let mut resp_len_buf = [0u8; 2];
        stream.read_exact(&mut resp_len_buf)
            .map_err(|e| format!("DoT read response len failed: {}", e))?;
        let resp_len = u16::from_be_bytes(resp_len_buf) as usize;

        if resp_len > 4096 {
            return Err("DoT response exceeds maximum safe buffer size".to_string());
        }

        let mut resp_buf = vec![0u8; resp_len];
        stream.read_exact(&mut resp_buf)
            .map_err(|e| format!("DoT read response body failed: {}", e))?;

        DnsWireCodec::decode_response(&resp_buf)
    }
}
