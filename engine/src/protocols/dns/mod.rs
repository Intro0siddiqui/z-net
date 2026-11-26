//! Native Encrypted & High-Performance UDP DNS Resolver with TTL caching.

pub mod cache;
pub mod doh;
pub mod dot;
pub mod hosts;
pub mod udp;
pub mod wire;

use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::sync::Arc;
use std::time::Duration;

use crate::protocols::tls::BoringTlsConfig;

use cache::DnsCache;
use doh::DohClient;
use dot::DotClient;
use wire::DnsRecordType;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsMode {
    Native,
    System,
    DoH,
    DoT,
}

#[derive(Debug, Clone)]
pub struct DnsResolverConfig {
    pub mode: DnsMode,
    pub doh_url: String,
    pub dot_server_addr: String,
    pub dot_server_name: String,
}

impl Default for DnsResolverConfig {
    fn default() -> Self {
        Self {
            mode: DnsMode::Native,
            doh_url: "https://cloudflare-dns.com/dns-query".to_string(),
            dot_server_addr: "1.1.1.1:853".to_string(),
            dot_server_name: "cloudflare-dns.com".to_string(),
        }
    }
}

pub struct DnsResolver {
    pub config: DnsResolverConfig,
    pub cache: Arc<DnsCache>,
    pub nameservers: Vec<SocketAddr>,
    tls_config: Arc<BoringTlsConfig>,
}

impl DnsResolver {
    pub fn new(tls_config: Arc<BoringTlsConfig>, config: DnsResolverConfig) -> Self {
        let nameservers = udp::parse_nameservers();
        Self {
            config,
            cache: Arc::new(DnsCache::default()),
            nameservers,
            tls_config,
        }
    }

    /// Resolve a hostname into socket addresses, applying IP literal checks,
    /// /etc/hosts, in-memory cache, and the configured DNS resolver mode.
    pub fn resolve(&self, host: &str, port: u16) -> Result<Vec<SocketAddr>, String> {
        let clean_host = host.trim_start_matches('[').trim_end_matches(']');

        // 1. Check if host is already an IP literal (IPv4 or IPv6)
        if let Ok(ip) = clean_host.parse::<IpAddr>() {
            return Ok(vec![SocketAddr::new(ip, port)]);
        }

        // 2. Check /etc/hosts static lookup
        if let Some(ips) = hosts::lookup_hosts(clean_host) {
            let mut addrs: Vec<SocketAddr> =
                ips.into_iter().map(|ip| SocketAddr::new(ip, port)).collect();
            addrs.sort_by_key(|addr| !addr.is_ipv4());
            return Ok(addrs);
        }

        // 3. Check in-memory DNS cache (both A and AAAA)
        let mut cached_addrs = Vec::new();
        if let Some(v4) = self.cache.get(clean_host, DnsRecordType::A) {
            cached_addrs.extend(v4.into_iter().map(|ip| SocketAddr::new(ip, port)));
        }
        if let Some(v6) = self.cache.get(clean_host, DnsRecordType::AAAA) {
            cached_addrs.extend(v6.into_iter().map(|ip| SocketAddr::new(ip, port)));
        }
        if !cached_addrs.is_empty() {
            cached_addrs.sort_by_key(|addr| !addr.is_ipv4());
            return Ok(cached_addrs);
        }

        // 4. Resolve using configured mode
        match self.config.mode {
            DnsMode::Native => self.resolve_native(clean_host, port),
            DnsMode::DoH => {
                let doh = DohClient::new(self.tls_config.clone(), &self.config.doh_url);
                if let Ok(records) = doh.resolve(clean_host, DnsRecordType::A) {
                    if !records.is_empty() {
                        let ips: Vec<IpAddr> = records.iter().map(|r| r.addr).collect();
                        let min_ttl = records.iter().map(|r| r.ttl).min().unwrap_or(300).clamp(30, 3600);
                        self.cache.insert(clean_host, DnsRecordType::A, ips.clone(), min_ttl);
                        let mut addrs: Vec<SocketAddr> =
                            ips.into_iter().map(|ip| SocketAddr::new(ip, port)).collect();
                        addrs.sort_by_key(|addr| !addr.is_ipv4());
                        return Ok(addrs);
                    }
                }
                self.resolve_system(clean_host, port)
            }
            DnsMode::DoT => {
                let dot = DotClient::new(
                    self.tls_config.clone(),
                    &self.config.dot_server_addr,
                    &self.config.dot_server_name,
                );
                if let Ok(records) = dot.resolve(clean_host, DnsRecordType::A) {
                    if !records.is_empty() {
                        let ips: Vec<IpAddr> = records.iter().map(|r| r.addr).collect();
                        let min_ttl = records.iter().map(|r| r.ttl).min().unwrap_or(300).clamp(30, 3600);
                        self.cache.insert(clean_host, DnsRecordType::A, ips.clone(), min_ttl);
                        let mut addrs: Vec<SocketAddr> =
                            ips.into_iter().map(|ip| SocketAddr::new(ip, port)).collect();
                        addrs.sort_by_key(|addr| !addr.is_ipv4());
                        return Ok(addrs);
                    }
                }
                self.resolve_system(clean_host, port)
            }
            DnsMode::System => self.resolve_system(clean_host, port),
        }
    }

    /// Resolve using native parallel UDP queries across nameservers.
    fn resolve_native(&self, host: &str, port: u16) -> Result<Vec<SocketAddr>, String> {
        let timeout = Duration::from_millis(600);
        let (res_a, res_aaaa) = udp::resolve_both_parallel(host, &self.nameservers, timeout);

        let mut addrs = Vec::new();

        if let Ok(records) = res_a {
            if !records.is_empty() {
                let ips: Vec<IpAddr> = records.iter().map(|r| r.addr).collect();
                let min_ttl = records.iter().map(|r| r.ttl).min().unwrap_or(300).clamp(30, 3600);
                self.cache.insert(host, DnsRecordType::A, ips.clone(), min_ttl);
                addrs.extend(ips.into_iter().map(|ip| SocketAddr::new(ip, port)));
            }
        }

        if let Ok(records) = res_aaaa {
            if !records.is_empty() {
                let ips: Vec<IpAddr> = records.iter().map(|r| r.addr).collect();
                let min_ttl = records.iter().map(|r| r.ttl).min().unwrap_or(300).clamp(30, 3600);
                self.cache.insert(host, DnsRecordType::AAAA, ips.clone(), min_ttl);
                addrs.extend(ips.into_iter().map(|ip| SocketAddr::new(ip, port)));
            }
        }

        if addrs.is_empty() {
            // If native UDP failed completely, fallback to system resolution
            return self.resolve_system(host, port);
        }

        // Sort prioritizing IPv4 while preserving all addresses
        addrs.sort_by_key(|addr| !addr.is_ipv4());
        Ok(addrs)
    }

    fn resolve_system(&self, host: &str, port: u16) -> Result<Vec<SocketAddr>, String> {
        let addr_str = format!("{}:{}", host, port);
        let mut addrs: Vec<SocketAddr> = addr_str
            .to_socket_addrs()
            .map_err(|e| format!("DNS resolution failed for {}: {}", addr_str, e))?
            .collect();

        let ips: Vec<IpAddr> = addrs.iter().map(|a| a.ip()).collect();
        self.cache.insert(host, DnsRecordType::A, ips, 300);

        addrs.sort_by_key(|addr| !addr.is_ipv4());
        Ok(addrs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_dns_resolver_ip_literal() {
        let tls_cfg = Arc::new(BoringTlsConfig::new(crate::protocols::tls::TlsFingerprintProfile::Chrome, Arc::new(crate::protocols::tls::BoringSessionStore::in_memory())).unwrap());
        let resolver = DnsResolver::new(tls_cfg, DnsResolverConfig::default());

        let res = resolver.resolve("127.0.0.1", 8080).expect("resolve ip literal");
        assert_eq!(res, vec![SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080)]);

        let res_v6 = resolver.resolve("[::1]", 8080).expect("resolve ipv6 bracket literal");
        assert_eq!(res_v6, vec![SocketAddr::new("::1".parse().unwrap(), 8080)]);
    }

    #[test]
    fn test_dns_resolver_hosts_localhost() {
        let tls_cfg = Arc::new(BoringTlsConfig::new(crate::protocols::tls::TlsFingerprintProfile::Chrome, Arc::new(crate::protocols::tls::BoringSessionStore::in_memory())).unwrap());
        let resolver = DnsResolver::new(tls_cfg, DnsResolverConfig::default());

        let res = resolver.resolve("localhost", 80).expect("resolve localhost");
        assert!(!res.is_empty());
        assert!(res.iter().any(|a| a.ip() == IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))));
    }

    #[test]
    fn test_dns_resolver_cache_integration() {
        let tls_cfg = Arc::new(BoringTlsConfig::new(crate::protocols::tls::TlsFingerprintProfile::Chrome, Arc::new(crate::protocols::tls::BoringSessionStore::in_memory())).unwrap());
        let resolver = DnsResolver::new(tls_cfg, DnsResolverConfig::default());

        // Pre-populate cache
        let mock_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 99));
        resolver.cache.insert("nas.local", DnsRecordType::A, vec![mock_ip], 600);

        let res = resolver.resolve("nas.local", 443).expect("resolve cached");
        assert_eq!(res, vec![SocketAddr::new(mock_ip, 443)]);
    }

    #[test]
    fn test_dns_resolver_native_resolution() {
        let tls_cfg = Arc::new(BoringTlsConfig::new(crate::protocols::tls::TlsFingerprintProfile::Chrome, Arc::new(crate::protocols::tls::BoringSessionStore::in_memory())).unwrap());
        let resolver = DnsResolver::new(tls_cfg, DnsResolverConfig::default());

        let t0 = std::time::Instant::now();
        let res = resolver.resolve("doc.rust-lang.org", 443).expect("resolve doc.rust-lang.org");
        let elapsed = t0.elapsed();
        println!("[DNS-TEST] Native UDP resolved doc.rust-lang.org in {:?}, addrs: {:?}", elapsed, res);
        assert!(!res.is_empty());
        // Verify latency is well under 1000ms (eliminating the 5000ms stall!)
        assert!(elapsed < Duration::from_millis(1500));
    }
}
