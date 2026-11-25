//! Native UDP DNS client with parallel A/AAAA queries, EDNS0, failover, and TCP fallback.

use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicU16, Ordering};
use std::time::Duration;

use super::wire::{DecodeOutcome, DnsRecord, DnsRecordType, DnsWireCodec};

static TXID_COUNTER: AtomicU16 = AtomicU16::new(0x3141);

fn next_txid() -> u16 {
    let nanos = (std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() & 0xFFFF) as u16;
    nanos ^ TXID_COUNTER.fetch_add(0x405b, Ordering::Relaxed)
}

/// Parse nameservers from /etc/resolv.conf, falling back to public DNS if empty.
pub fn parse_nameservers() -> Vec<SocketAddr> {
    parse_nameservers_from_file("/etc/resolv.conf")
}

pub fn parse_nameservers_from_file(path: &str) -> Vec<SocketAddr> {
    let mut servers = Vec::new();
    if let Ok(content) = std::fs::read_to_string(path) {
        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with("nameserver") {
                let mut parts = trimmed.split_whitespace();
                parts.next(); // skip "nameserver"
                if let Some(ip_str) = parts.next() {
                    if let Ok(ip) = ip_str.parse::<IpAddr>() {
                        servers.push(SocketAddr::new(ip, 53));
                    }
                }
            }
        }
    }

    if servers.is_empty() {
        servers.push(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 53));
        servers.push(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 53));
        servers.push(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 0, 0, 1)), 53));
    }

    servers
}

/// Query a single record type across nameservers using an ephemeral UDP socket.
/// Falls back to TCP:53 if the TC (truncation) bit is set.
pub fn resolve_query(
    hostname: &str,
    record_type: DnsRecordType,
    nameservers: &[SocketAddr],
    timeout: Duration,
) -> Result<Vec<DnsRecord>, String> {
    let txid = next_txid();
    // EDNS0 payload size: 1232 bytes (DNS Flag Day standard)
    let query_bytes = DnsWireCodec::encode_query_with_edns(txid, hostname, record_type, 1232);

    let mut last_err = String::from("No nameservers available");

    for ns in nameservers {
        // Bind a dedicated ephemeral socket for this attempt to avoid port/NAT collisions
        let sock = match UdpSocket::bind("0.0.0.0:0") {
            Ok(s) => s,
            Err(e) => {
                last_err = format!("Failed to bind ephemeral UDP socket: {}", e);
                continue;
            }
        };

        if let Err(e) = sock.set_read_timeout(Some(timeout)) {
            last_err = format!("Failed to set read timeout on UDP socket: {}", e);
            continue;
        }
        if let Err(e) = sock.set_write_timeout(Some(timeout)) {
            last_err = format!("Failed to set write timeout on UDP socket: {}", e);
            continue;
        }

        if let Err(e) = sock.send_to(&query_bytes, ns) {
            last_err = format!("Failed to send DNS query to {}: {}", ns, e);
            continue;
        }

        let mut buf = [0u8; 2048];
        match sock.recv_from(&mut buf) {
            Ok((n, _src)) => {
                match DnsWireCodec::decode_response_checked(&buf[..n], txid) {
                    Ok(DecodeOutcome::Success(records)) => {
                        return Ok(records);
                    }
                    Ok(DecodeOutcome::Truncated) => {
                        // Response was truncated: fall back to TCP:53
                        match resolve_tcp(ns, &query_bytes, txid, timeout) {
                            Ok(records) => return Ok(records),
                            Err(e) => {
                                last_err = format!("TCP fallback to {} failed: {}", ns, e);
                                continue;
                            }
                        }
                    }
                    Err(e) => {
                        last_err = format!("DNS decode error from {}: {}", ns, e);
                        continue;
                    }
                }
            }
            Err(e) => {
                last_err = format!("DNS UDP recv error from {}: {}", ns, e);
                continue;
            }
        }
    }

    Err(last_err)
}

/// Fallback to DNS over TCP (RFC 1035 §4.2.2) when truncated.
pub fn resolve_tcp(
    ns: &SocketAddr,
    query: &[u8],
    expected_id: u16,
    timeout: Duration,
) -> Result<Vec<DnsRecord>, String> {
    use std::io::{Read, Write};
    use std::net::TcpStream;

    let mut stream = TcpStream::connect_timeout(ns, timeout)
        .map_err(|e| format!("TCP connect to {} failed: {}", ns, e))?;
    stream.set_read_timeout(Some(timeout)).ok();
    stream.set_write_timeout(Some(timeout)).ok();

    // 2-byte length prefix
    let mut send_buf = Vec::with_capacity(2 + query.len());
    send_buf.extend_from_slice(&(query.len() as u16).to_be_bytes());
    send_buf.extend_from_slice(query);

    stream
        .write_all(&send_buf)
        .map_err(|e| format!("TCP write to {} failed: {}", ns, e))?;

    let mut len_buf = [0u8; 2];
    stream
        .read_exact(&mut len_buf)
        .map_err(|e| format!("TCP read length from {} failed: {}", ns, e))?;
    let resp_len = u16::from_be_bytes(len_buf) as usize;

    if resp_len < 12 || resp_len > 65535 {
        return Err(format!("Invalid TCP DNS response length: {}", resp_len));
    }

    let mut resp_buf = vec![0u8; resp_len];
    stream
        .read_exact(&mut resp_buf)
        .map_err(|e| format!("TCP read body from {} failed: {}", ns, e))?;

    match DnsWireCodec::decode_response_checked(&resp_buf, expected_id)? {
        DecodeOutcome::Success(records) => Ok(records),
        DecodeOutcome::Truncated => Err("DNS response truncated even over TCP".to_string()),
    }
}

/// Resolve both A and AAAA in parallel using two separate ephemeral UDP sockets.
/// Each query runs concurrently on its own socket (distinct local ports),
/// preventing router/NAT conntrack collisions.
pub fn resolve_both_parallel(
    hostname: &str,
    nameservers: &[SocketAddr],
    timeout: Duration,
) -> (Result<Vec<DnsRecord>, String>, Result<Vec<DnsRecord>, String>) {
    let mut res_a = Err("Query not executed".to_string());
    let mut res_aaaa = Err("Query not executed".to_string());

    std::thread::scope(|s| {
        let handle_a = s.spawn(|| resolve_query(hostname, DnsRecordType::A, nameservers, timeout));
        let handle_aaaa =
            s.spawn(|| resolve_query(hostname, DnsRecordType::AAAA, nameservers, timeout));

        res_a = handle_a
            .join()
            .unwrap_or_else(|_| Err("Thread A panicked".to_string()));
        res_aaaa = handle_aaaa
            .join()
            .unwrap_or_else(|_| Err("Thread AAAA panicked".to_string()));
    });

    (res_a, res_aaaa)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_nameservers_fallback() {
        let ns = parse_nameservers_from_file("/nonexistent/resolv.conf");
        assert!(!ns.is_empty());
        assert_eq!(ns[0].port(), 53);
    }

    #[test]
    fn test_txid_uniqueness() {
        let id1 = next_txid();
        let id2 = next_txid();
        assert_ne!(id1, id2);
    }
}
