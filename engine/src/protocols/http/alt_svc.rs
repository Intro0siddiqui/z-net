//! HTTP Alternative Services (Alt-Svc) registry per RFC 7838.
//!
//! Tracks advertised alternative endpoints (such as `h3=":443"`) with TTL expiration
//! and provides seamless discovery for HTTP/3 upgrades.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// A parsed Alt-Svc alternative endpoint entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AltSvcEntry {
    pub alpn: String,       // e.g. "h3", "h3-29"
    pub host: String,       // Alternative host (or origin host if omitted)
    pub port: u16,          // Alternative port
    pub expires_at: Instant,
    pub persist: bool,
}

/// Registry storing Alt-Svc records indexed by origin `host:port`.
pub struct AltSvcRegistry {
    entries: Mutex<HashMap<String, Vec<AltSvcEntry>>>,
}

impl Default for AltSvcRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl AltSvcRegistry {
    pub fn new() -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
        }
    }

    /// Clear all cached alternative services.
    pub fn clear(&self) {
        if let Ok(mut lock) = self.entries.lock() {
            lock.clear();
        }
    }

    /// Insert or update Alt-Svc directives parsed from an `Alt-Svc` response header.
    ///
    /// Supports RFC 7838 format:
    /// - `clear`: clears all alternative services for this origin.
    /// - `h3=":443"; ma=86400; persist=1`
    /// - Comma-separated alternatives: `h3=":443"; ma=86400, h3-29=":443"; ma=3600`
    pub fn insert(&self, origin_host: &str, origin_port: u16, header_val: &str) {
        let key = format!("{}:{}", origin_host.to_ascii_lowercase(), origin_port);
        let header_val = header_val.trim();

        if header_val.eq_ignore_ascii_case("clear") {
            if let Ok(mut lock) = self.entries.lock() {
                lock.remove(&key);
            }
            return;
        }

        let parsed_entries = Self::parse_header(origin_host, origin_port, header_val);
        if parsed_entries.is_empty() {
            return;
        }

        if let Ok(mut lock) = self.entries.lock() {
            let list = lock.entry(key).or_insert_with(Vec::new);
            for new_entry in parsed_entries {
                // If an entry for the same ALPN already exists, update it, otherwise append.
                if let Some(existing) = list.iter_mut().find(|e| e.alpn == new_entry.alpn) {
                    *existing = new_entry;
                } else {
                    list.push(new_entry);
                }
            }
        }
    }

    /// Parse one or more comma-separated Alt-Svc directives.
    pub fn parse_header(origin_host: &str, origin_port: u16, header_val: &str) -> Vec<AltSvcEntry> {
        let mut results = Vec::new();
        let now = Instant::now();

        for directive in header_val.split(',') {
            let part = directive.trim();
            if part.is_empty() || part.eq_ignore_ascii_case("clear") {
                continue;
            }

            // Syntax: <protocol-id>="<alt-authority>" [; <param-name>=<param-value>]*
            let eq_idx = match part.find('=') {
                Some(idx) => idx,
                None => continue,
            };

            let alpn = part[..eq_idx].trim().to_string();
            let remainder = part[eq_idx + 1..].trim();

            let (alt_authority, params_str) = if remainder.starts_with('"') {
                if let Some(close_quote) = remainder[1..].find('"') {
                    (&remainder[1..1 + close_quote], remainder[1 + close_quote + 1..].trim())
                } else {
                    (remainder.trim_matches('"'), "")
                }
            } else {
                let semi = remainder.find(';').unwrap_or(remainder.len());
                (remainder[..semi].trim(), remainder[semi..].trim())
            };

            // Parse alternative host & port
            let (target_host, target_port) = if alt_authority.starts_with(':') {
                let p: u16 = match alt_authority[1..].parse() {
                    Ok(p) => p,
                    Err(_) => origin_port,
                };
                (origin_host.to_string(), p)
            } else if let Some(colon) = alt_authority.rfind(':') {
                let h = alt_authority[..colon].to_string();
                let p: u16 = match alt_authority[colon + 1..].parse() {
                    Ok(p) => p,
                    Err(_) => origin_port,
                };
                (h, p)
            } else {
                (origin_host.to_string(), origin_port)
            };

            // Parse parameters: ma=<seconds>, persist=1
            let mut max_age_secs: u64 = 86400; // default 24h per RFC 7838
            let mut persist = false;

            for param in params_str.split(';') {
                let p = param.trim();
                if let Some(rest) = p.strip_prefix("ma=") {
                    if let Ok(secs) = rest.trim().parse::<u64>() {
                        max_age_secs = secs;
                    }
                } else if let Some(rest) = p.strip_prefix("persist=") {
                    if rest.trim() == "1" {
                        persist = true;
                    }
                }
            }

            let expires_at = now + Duration::from_secs(max_age_secs);

            results.push(AltSvcEntry {
                alpn,
                host: target_host,
                port: target_port,
                expires_at,
                persist,
            });
        }

        results
    }

    /// Retrieve the highest-priority HTTP/3 alternative service target if available and unexpired.
    pub fn get_h3_target(&self, origin_host: &str, origin_port: u16) -> Option<(String, u16)> {
        let key = format!("{}:{}", origin_host.to_ascii_lowercase(), origin_port);
        let now = Instant::now();

        let mut lock = self.entries.lock().ok()?;
        let list = lock.get_mut(&key)?;

        // Prune expired entries
        list.retain(|e| e.expires_at > now);

        // Find "h3" or "h3-29"
        for entry in list.iter() {
            if entry.alpn == "h3" || entry.alpn == "h3-29" {
                return Some((entry.host.clone(), entry.port));
            }
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_simple_h3_alt_svc() {
        let entries = AltSvcRegistry::parse_header("example.com", 443, "h3=\":443\"; ma=86400");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].alpn, "h3");
        assert_eq!(entries[0].host, "example.com");
        assert_eq!(entries[0].port, 443);
        assert!(!entries[0].persist);
    }

    #[test]
    fn test_parse_multiple_alt_svc_with_persist() {
        let header = "h3=\":443\"; ma=86400; persist=1, h3-29=\":443\"; ma=3600";
        let entries = AltSvcRegistry::parse_header("example.com", 443, header);
        assert_eq!(entries.len(), 2);

        assert_eq!(entries[0].alpn, "h3");
        assert_eq!(entries[0].port, 443);
        assert!(entries[0].persist);

        assert_eq!(entries[1].alpn, "h3-29");
        assert_eq!(entries[1].port, 443);
        assert!(!entries[1].persist);
    }

    #[test]
    fn test_parse_alt_svc_custom_host_and_port() {
        let header = "h3=\"alt.cloudflare.com:8443\"; ma=300";
        let entries = AltSvcRegistry::parse_header("example.com", 443, header);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].alpn, "h3");
        assert_eq!(entries[0].host, "alt.cloudflare.com");
        assert_eq!(entries[0].port, 8443);
    }

    #[test]
    fn test_registry_insert_and_lookup() {
        let registry = AltSvcRegistry::new();
        assert_eq!(registry.get_h3_target("youtube.com", 443), None);

        registry.insert("youtube.com", 443, "h3=\":443\"; ma=86400");
        assert_eq!(registry.get_h3_target("youtube.com", 443), Some(("youtube.com".to_string(), 443)));

        // Clear
        registry.insert("youtube.com", 443, "clear");
        assert_eq!(registry.get_h3_target("youtube.com", 443), None);
    }

    #[test]
    fn test_registry_expiration() {
        let registry = AltSvcRegistry::new();
        registry.insert("fast.com", 443, "h3=\":443\"; ma=0");
        std::thread::sleep(Duration::from_millis(10));
        assert_eq!(registry.get_h3_target("fast.com", 443), None);
    }
}
