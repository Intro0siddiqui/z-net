//! Native Encrypted DNS Resolver (DoH / DoT / System) with TTL caching.

pub mod cache;
pub mod doh;
pub mod dot;
pub mod wire;

use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::sync::Arc;

use rustls::ClientConfig;

use cache::DnsCache;
use doh::DohClient;
use dot::DotClient;
use wire::DnsRecordType;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsMode {
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
            mode: DnsMode::System,
            doh_url: "https://cloudflare-dns.com/dns-query".to_string(),
            dot_server_addr: "1.1.1.1:853".to_string(),
            dot_server_name: "cloudflare-dns.com".to_string(),
        }
    }
}

pub struct DnsResolver {
    pub config: DnsResolverConfig,
    pub cache: Arc<DnsCache>,
    tls_config: Arc<ClientConfig>,
}

impl DnsResolver {
    pub fn new(tls_config: Arc<ClientConfig>, config: DnsResolverConfig) -> Self {
        Self {
            config,
            cache: Arc::new(DnsCache::default()),
            tls_config,
        }
    }

    /// Resolve a hostname into socket addresses, applying cache, DoH, DoT, or system fallback.
    pub fn resolve(&self, host: &str, port: u16) -> Result<Vec<SocketAddr>, String> {
        // 1. Check if host is already an IP literal
        if let Ok(ip) = host.parse::<IpAddr>() {
            return Ok(vec![SocketAddr::new(ip, port)]);
        }

        // 2. Check in-memory DNS cache
        if let Some(cached_ips) = self.cache.get(host, DnsRecordType::A) {
            let mut addrs: Vec<SocketAddr> = cached_ips.into_iter().map(|ip| SocketAddr::new(ip, port)).collect();
            // Prioritize IPv4
            addrs.sort_by_key(|addr| !addr.is_ipv4());
            return Ok(addrs);
        }

        // 3. Resolve using configured mode
        match self.config.mode {
            DnsMode::DoH => {
                let doh = DohClient::new(self.tls_config.clone(), &self.config.doh_url);
                if let Ok(records) = doh.resolve(host, DnsRecordType::A) {
                    if !records.is_empty() {
                        let ips: Vec<IpAddr> = records.iter().map(|r| r.addr).collect();
                        let min_ttl = records.iter().map(|r| r.ttl).min().unwrap_or(300);
                        self.cache.insert(host, DnsRecordType::A, ips.clone(), min_ttl);
                        let mut addrs: Vec<SocketAddr> = ips.into_iter().map(|ip| SocketAddr::new(ip, port)).collect();
                        addrs.sort_by_key(|addr| !addr.is_ipv4());
                        return Ok(addrs);
                    }
                }
                // Fallback to system DNS if DoH query fails
                self.resolve_system(host, port)
            }
            DnsMode::DoT => {
                let dot = DotClient::new(
                    self.tls_config.clone(),
                    &self.config.dot_server_addr,
                    &self.config.dot_server_name,
                );
                if let Ok(records) = dot.resolve(host, DnsRecordType::A) {
                    if !records.is_empty() {
                        let ips: Vec<IpAddr> = records.iter().map(|r| r.addr).collect();
                        let min_ttl = records.iter().map(|r| r.ttl).min().unwrap_or(300);
                        self.cache.insert(host, DnsRecordType::A, ips.clone(), min_ttl);
                        let mut addrs: Vec<SocketAddr> = ips.into_iter().map(|ip| SocketAddr::new(ip, port)).collect();
                        addrs.sort_by_key(|addr| !addr.is_ipv4());
                        return Ok(addrs);
                    }
                }
                // Fallback to system DNS if DoT query fails
                self.resolve_system(host, port)
            }
            DnsMode::System => self.resolve_system(host, port),
        }
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
        let roots = rustls::RootCertStore::empty();
        let tls_cfg = Arc::new(ClientConfig::builder().with_root_certificates(roots).with_no_client_auth());
        let resolver = DnsResolver::new(tls_cfg, DnsResolverConfig::default());

        let res = resolver.resolve("127.0.0.1", 8080).expect("resolve ip literal");
        assert_eq!(res, vec![SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080)]);
    }

    #[test]
    fn test_dns_resolver_cache_integration() {
        let roots = rustls::RootCertStore::empty();
        let tls_cfg = Arc::new(ClientConfig::builder().with_root_certificates(roots).with_no_client_auth());
        let resolver = DnsResolver::new(tls_cfg, DnsResolverConfig::default());

        // Pre-populate cache
        let mock_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 99));
        resolver.cache.insert("nas.local", DnsRecordType::A, vec![mock_ip], 600);

        let res = resolver.resolve("nas.local", 443).expect("resolve cached");
        assert_eq!(res, vec![SocketAddr::new(mock_ip, 443)]);
    }
}
