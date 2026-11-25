//! Parser and lookup cache for /etc/hosts static mappings.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Mutex, OnceLock};

static HOSTS_CACHE: OnceLock<Mutex<HashMap<String, Vec<IpAddr>>>> = OnceLock::new();

fn get_cache() -> &'static Mutex<HashMap<String, Vec<IpAddr>>> {
    HOSTS_CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Look up a hostname in /etc/hosts.
pub fn lookup_hosts(hostname: &str) -> Option<Vec<IpAddr>> {
    let lower = hostname.to_ascii_lowercase();
    let cache = get_cache();

    // Check fast memory cache first
    if let Ok(guard) = cache.lock() {
        if let Some(ips) = guard.get(&lower) {
            return Some(ips.clone());
        }
    }

    // Parse /etc/hosts and populate cache
    if let Ok(content) = std::fs::read_to_string("/etc/hosts") {
        let parsed = parse_hosts_content(&content);
        if let Ok(mut guard) = cache.lock() {
            *guard = parsed;
            if let Some(ips) = guard.get(&lower) {
                return Some(ips.clone());
            }
        }
    }

    None
}

/// Parse content of a hosts file into a hostname-to-IPs map.
pub fn parse_hosts_content(content: &str) -> HashMap<String, Vec<IpAddr>> {
    let mut map: HashMap<String, Vec<IpAddr>> = HashMap::new();

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        // Strip inline comments
        let line_data = if let Some(idx) = trimmed.find('#') {
            &trimmed[..idx]
        } else {
            trimmed
        };

        let mut tokens = line_data.split_whitespace();
        let ip_str = match tokens.next() {
            Some(s) => s,
            None => continue,
        };

        let ip = match ip_str.parse::<IpAddr>() {
            Ok(ip) => ip,
            Err(_) => continue,
        };

        for host_token in tokens {
            let host_key = host_token.to_ascii_lowercase();
            map.entry(host_key).or_default().push(ip);
        }
    }

    map
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn test_parse_hosts_content() {
        let sample = r#"
        # System hosts file
        127.0.0.1   localhost.localdomain localhost
        ::1         localhost ip6-localhost
        192.168.1.50 nas.local # my NAS
        "#;

        let map = parse_hosts_content(sample);
        assert_eq!(
            map.get("localhost"),
            Some(&vec![
                IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
                IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1))
            ])
        );
        assert_eq!(
            map.get("nas.local"),
            Some(&vec![IpAddr::V4(Ipv4Addr::new(192, 168, 1, 50))])
        );
        assert_eq!(map.get("unknown.domain"), None);
    }
}
