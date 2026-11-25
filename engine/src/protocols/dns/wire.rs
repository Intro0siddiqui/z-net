//! RFC 1035 DNS Message wireformat encoder and decoder.

use std::net::{Ipv4Addr, Ipv6Addr, IpAddr};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DnsRecordType {
    A = 1,
    AAAA = 28,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsRecord {
    pub name: String,
    pub record_type: DnsRecordType,
    pub ttl: u32,
    pub addr: IpAddr,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodeOutcome {
    Success(Vec<DnsRecord>),
    Truncated,
}

pub struct DnsWireCodec;

impl DnsWireCodec {
    /// Encode a standard DNS query for a hostname and record type.
    pub fn encode_query(id: u16, hostname: &str, record_type: DnsRecordType) -> Vec<u8> {
        let mut buf = Vec::with_capacity(64);

        // Header (12 bytes)
        buf.extend_from_slice(&id.to_be_bytes()); // ID
        buf.extend_from_slice(&0x0100u16.to_be_bytes()); // Flags: RD (Recursion Desired)
        buf.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT: 1
        buf.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT: 0
        buf.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT: 0
        buf.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT: 0

        // Question: QNAME
        for label in hostname.split('.') {
            if label.is_empty() {
                continue;
            }
            buf.push(label.len() as u8);
            buf.extend_from_slice(label.as_bytes());
        }
        buf.push(0x00); // Root label null terminator

        // QTYPE and QCLASS
        buf.extend_from_slice(&(record_type as u16).to_be_bytes());
        buf.extend_from_slice(&1u16.to_be_bytes()); // QCLASS: IN (1)

        buf
    }

    /// Encode a DNS query with EDNS0 OPT RR for larger UDP payloads (RFC 6891).
    pub fn encode_query_with_edns(
        id: u16,
        hostname: &str,
        record_type: DnsRecordType,
        buf_size: u16,
    ) -> Vec<u8> {
        let mut buf = Vec::with_capacity(80);

        // Header (12 bytes)
        buf.extend_from_slice(&id.to_be_bytes()); // ID
        buf.extend_from_slice(&0x0100u16.to_be_bytes()); // Flags: RD (Recursion Desired)
        buf.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT: 1
        buf.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT: 0
        buf.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT: 0
        buf.extend_from_slice(&1u16.to_be_bytes()); // ARCOUNT: 1 (EDNS0 OPT RR)

        // Question: QNAME
        for label in hostname.split('.') {
            if label.is_empty() {
                continue;
            }
            buf.push(label.len() as u8);
            buf.extend_from_slice(label.as_bytes());
        }
        buf.push(0x00); // Root label null terminator

        // QTYPE and QCLASS
        buf.extend_from_slice(&(record_type as u16).to_be_bytes());
        buf.extend_from_slice(&1u16.to_be_bytes()); // QCLASS: IN (1)

        // EDNS0 OPT Pseudo-RR (11 bytes)
        buf.push(0x00); // NAME: root
        buf.extend_from_slice(&41u16.to_be_bytes()); // TYPE: OPT (41)
        buf.extend_from_slice(&buf_size.to_be_bytes()); // CLASS: UDP payload size (e.g. 1232)
        buf.extend_from_slice(&0u32.to_be_bytes()); // Extended RCODE (0) + Version (0) + Flags (0)
        buf.extend_from_slice(&0u16.to_be_bytes()); // RDLENGTH: 0

        buf
    }

    /// Decode DNS response wireformat data with transaction ID and truncation checks.
    pub fn decode_response_checked(
        data: &[u8],
        expected_id: u16,
    ) -> Result<DecodeOutcome, String> {
        if data.len() < 12 {
            return Err("DNS response too short for header".to_string());
        }

        let resp_id = u16::from_be_bytes([data[0], data[1]]);
        if resp_id != expected_id {
            return Err(format!("DNS TXID mismatch: expected {}, got {}", expected_id, resp_id));
        }

        let flags = u16::from_be_bytes([data[2], data[3]]);
        let rcode = flags & 0x000F;
        if rcode != 0 {
            return Err(format!("DNS server returned error code RCODE: {}", rcode));
        }

        // TC (Truncation) flag is bit 9 (0x0200)
        if (flags & 0x0200) != 0 {
            return Ok(DecodeOutcome::Truncated);
        }

        let records = Self::decode_answers(data)?;
        Ok(DecodeOutcome::Success(records))
    }

    /// Decode DNS response wireformat data and extract resolved IP addresses.
    pub fn decode_response(data: &[u8]) -> Result<Vec<DnsRecord>, String> {
        if data.len() < 12 {
            return Err("DNS response too short for header".to_string());
        }

        let flags = u16::from_be_bytes([data[2], data[3]]);
        let rcode = flags & 0x000F;
        if rcode != 0 {
            return Err(format!("DNS server returned error code RCODE: {}", rcode));
        }

        Self::decode_answers(data)
    }

    fn decode_answers(data: &[u8]) -> Result<Vec<DnsRecord>, String> {
        let qdcount = u16::from_be_bytes([data[4], data[5]]) as usize;
        let ancount = u16::from_be_bytes([data[6], data[7]]) as usize;

        let mut offset = 12;

        // Skip Question Section
        for _ in 0..qdcount {
            offset = Self::skip_name(data, offset)?;
            if offset + 4 > data.len() {
                return Err("DNS response truncated in question".to_string());
            }
            offset += 4; // Skip QTYPE (2) + QCLASS (2)
        }

        // Parse Answer Section
        let mut records = Vec::with_capacity(ancount);
        for _ in 0..ancount {
            if offset >= data.len() {
                break;
            }
            let (name, next_off) = Self::read_name(data, offset)?;
            offset = next_off;

            if offset + 10 > data.len() {
                return Err("DNS response truncated in answer header".to_string());
            }

            let rtype = u16::from_be_bytes([data[offset], data[offset + 1]]);
            let _rclass = u16::from_be_bytes([data[offset + 2], data[offset + 3]]);
            let ttl = u32::from_be_bytes([
                data[offset + 4],
                data[offset + 5],
                data[offset + 6],
                data[offset + 7],
            ]);
            let rdlength = u16::from_be_bytes([data[offset + 8], data[offset + 9]]) as usize;
            offset += 10;

            if offset + rdlength > data.len() {
                return Err("DNS response truncated in RDATA".to_string());
            }

            if rtype == DnsRecordType::A as u16 && rdlength == 4 {
                let ip = Ipv4Addr::new(
                    data[offset],
                    data[offset + 1],
                    data[offset + 2],
                    data[offset + 3],
                );
                records.push(DnsRecord {
                    name,
                    record_type: DnsRecordType::A,
                    ttl,
                    addr: IpAddr::V4(ip),
                });
            } else if rtype == DnsRecordType::AAAA as u16 && rdlength == 16 {
                let mut octets = [0u8; 16];
                octets.copy_from_slice(&data[offset..offset + 16]);
                let ip = Ipv6Addr::from(octets);
                records.push(DnsRecord {
                    name,
                    record_type: DnsRecordType::AAAA,
                    ttl,
                    addr: IpAddr::V6(ip),
                });
            }

            offset += rdlength;
        }

        Ok(records)
    }

    fn skip_name(data: &[u8], mut offset: usize) -> Result<usize, String> {
        let mut jumps = 0;
        while offset < data.len() {
            let len = data[offset];
            if len == 0 {
                return Ok(offset + 1);
            }
            if (len & 0xC0) == 0xC0 {
                // Pointer (2 bytes)
                return Ok(offset + 2);
            }
            offset += 1 + len as usize;
            jumps += 1;
            if jumps > 128 {
                return Err("DNS QNAME loop detected".to_string());
            }
        }
        Err("DNS QNAME reached EOF".to_string())
    }

    fn read_name(data: &[u8], mut offset: usize) -> Result<(String, usize), String> {
        let mut labels = Vec::new();
        let mut next_offset = None;
        let mut jumps = 0;

        while offset < data.len() {
            let len = data[offset];
            if len == 0 {
                if next_offset.is_none() {
                    next_offset = Some(offset + 1);
                }
                break;
            }

            if (len & 0xC0) == 0xC0 {
                if offset + 1 >= data.len() {
                    return Err("Truncated DNS pointer".to_string());
                }
                if next_offset.is_none() {
                    next_offset = Some(offset + 2);
                }
                let ptr = (((len & 0x3F) as usize) << 8) | (data[offset + 1] as usize);
                offset = ptr;
                jumps += 1;
                if jumps > 128 {
                    return Err("DNS pointer loop detected".to_string());
                }
                continue;
            }

            offset += 1;
            let end = offset + len as usize;
            if end > data.len() {
                return Err("Truncated DNS label".to_string());
            }
            let label = String::from_utf8_lossy(&data[offset..end]).to_string();
            labels.push(label);
            offset = end;
        }

        let full_name = labels.join(".");
        Ok((full_name, next_offset.unwrap_or(offset)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_dns_query_a() {
        let encoded = DnsWireCodec::encode_query(0x1234, "example.com", DnsRecordType::A);
        assert_eq!(&encoded[0..2], &0x1234u16.to_be_bytes());
        assert_eq!(&encoded[2..4], &0x0100u16.to_be_bytes()); // Flags: RD
        assert_eq!(&encoded[4..6], &1u16.to_be_bytes()); // QDCOUNT: 1

        // Check QNAME: \x07example\x03com\x00
        assert_eq!(encoded[12], 7);
        assert_eq!(&encoded[13..20], b"example");
        assert_eq!(encoded[20], 3);
        assert_eq!(&encoded[21..24], b"com");
        assert_eq!(encoded[24], 0);

        // QTYPE: 1 (A), QCLASS: 1 (IN)
        assert_eq!(&encoded[25..27], &1u16.to_be_bytes());
        assert_eq!(&encoded[27..29], &1u16.to_be_bytes());
    }

    #[test]
    fn test_encode_dns_query_aaaa() {
        let encoded = DnsWireCodec::encode_query(0xabcd, "youtube.com", DnsRecordType::AAAA);
        assert_eq!(&encoded[25..27], &28u16.to_be_bytes()); // QTYPE: 28 (AAAA)
    }

    #[test]
    fn test_decode_dns_response_with_a_record() {
        // Build mock DNS response for example.com -> 93.184.216.34
        let mut res = Vec::new();
        // ID, Flags: 0x8180 (Response, NoError), QDCOUNT=1, ANCOUNT=1, NS=0, AR=0
        res.extend_from_slice(&0x1234u16.to_be_bytes());
        res.extend_from_slice(&0x8180u16.to_be_bytes());
        res.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT: 1
        res.extend_from_slice(&1u16.to_be_bytes()); // ANCOUNT: 1
        res.extend_from_slice(&0u16.to_be_bytes());
        res.extend_from_slice(&0u16.to_be_bytes());

        // Question: \x07example\x03com\x00, QTYPE=1, QCLASS=1
        res.push(7);
        res.extend_from_slice(b"example");
        res.push(3);
        res.extend_from_slice(b"com");
        res.push(0);
        res.extend_from_slice(&1u16.to_be_bytes());
        res.extend_from_slice(&1u16.to_be_bytes());

        // Answer: Pointer to offset 12 (0xC00C), TYPE=1, CLASS=1, TTL=300, RDLENGTH=4, IP=93.184.216.34
        res.extend_from_slice(&[0xC0, 12]);
        res.extend_from_slice(&1u16.to_be_bytes());
        res.extend_from_slice(&1u16.to_be_bytes());
        res.extend_from_slice(&300u32.to_be_bytes());
        res.extend_from_slice(&4u16.to_be_bytes());
        res.extend_from_slice(&[93, 184, 216, 34]);

        let records = DnsWireCodec::decode_response(&res).expect("decode response");
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].name, "example.com");
        assert_eq!(records[0].record_type, DnsRecordType::A);
        assert_eq!(records[0].ttl, 300);
        assert_eq!(records[0].addr, IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)));
    }

    #[test]
    fn test_encode_dns_query_with_edns() {
        let encoded = DnsWireCodec::encode_query_with_edns(0x5678, "doc.rust-lang.org", DnsRecordType::A, 1232);
        // ID: 0x5678
        assert_eq!(&encoded[0..2], &0x5678u16.to_be_bytes());
        // ARCOUNT: 1
        assert_eq!(&encoded[10..12], &1u16.to_be_bytes());
        // Ends with OPT record (11 bytes): 0x00, 0x0029, 0x04D0, 0x00000000, 0x0000
        let len = encoded.len();
        assert_eq!(encoded[len - 11], 0); // Root name
        assert_eq!(&encoded[len - 10..len - 8], &41u16.to_be_bytes()); // OPT
        assert_eq!(&encoded[len - 8..len - 6], &1232u16.to_be_bytes()); // 1232 bytes buffer
    }

    #[test]
    fn test_decode_response_checked_txid_and_truncation() {
        // 1. TXID mismatch test
        let mut res = vec![0x12, 0x34, 0x81, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let err = DnsWireCodec::decode_response_checked(&res, 0x9999);
        assert!(err.is_err());
        assert!(err.unwrap_err().contains("TXID mismatch"));

        // 2. Truncation (TC bit set: 0x8380 or 0x8200)
        res[0] = 0x99;
        res[1] = 0x99;
        res[2] = 0x83; // 0x8200 | ... (TC bit set)
        res[3] = 0x80;
        let outcome = DnsWireCodec::decode_response_checked(&res, 0x9999).expect("decode checked");
        assert_eq!(outcome, DecodeOutcome::Truncated);
    }
}
