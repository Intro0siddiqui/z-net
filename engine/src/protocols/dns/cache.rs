//! Thread-safe in-memory DNS cache with TTL expiration.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use super::wire::DnsRecordType;

#[derive(Debug, Clone)]
struct CacheEntry {
    addrs: Vec<IpAddr>,
    expires_at: Instant,
}

pub struct DnsCache {
    entries: Mutex<HashMap<(String, DnsRecordType), CacheEntry>>,
    min_ttl: Duration,
    max_ttl: Duration,
}

impl Default for DnsCache {
    fn default() -> Self {
        Self::new(Duration::from_secs(10), Duration::from_secs(86400))
    }
}

impl DnsCache {
    pub fn new(min_ttl: Duration, max_ttl: Duration) -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
            min_ttl,
            max_ttl,
        }
    }

    /// Retrieve unexpired cached IP addresses for a hostname and record type.
    pub fn get(&self, hostname: &str, record_type: DnsRecordType) -> Option<Vec<IpAddr>> {
        let key = (hostname.to_ascii_lowercase(), record_type);
        let mut lock = self.entries.lock().ok()?;

        if let Some(entry) = lock.get(&key) {
            if Instant::now() < entry.expires_at {
                return Some(entry.addrs.clone());
            } else {
                lock.remove(&key);
            }
        }
        None
    }

    /// Insert or update resolved IP addresses for a hostname with TTL clamping.
    pub fn insert(&self, hostname: &str, record_type: DnsRecordType, addrs: Vec<IpAddr>, ttl_secs: u32) {
        if addrs.is_empty() {
            return;
        }

        let mut ttl = Duration::from_secs(ttl_secs as u64);
        if ttl < self.min_ttl {
            ttl = self.min_ttl;
        } else if ttl > self.max_ttl {
            ttl = self.max_ttl;
        }

        let key = (hostname.to_ascii_lowercase(), record_type);
        let expires_at = Instant::now() + ttl;

        if let Ok(mut lock) = self.entries.lock() {
            lock.insert(key, CacheEntry { addrs, expires_at });
        }
    }

    /// Clear all cached DNS records.
    pub fn clear(&self) {
        if let Ok(mut lock) = self.entries.lock() {
            lock.clear();
        }
    }

    /// Prune all expired entries from memory.
    pub fn prune_expired(&self) {
        let now = Instant::now();
        if let Ok(mut lock) = self.entries.lock() {
            lock.retain(|_, entry| entry.expires_at > now);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_dns_cache_hit_and_expiry() {
        let cache = DnsCache::new(Duration::from_millis(50), Duration::from_secs(60));
        let ip = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1));

        cache.insert("cloudflare.com", DnsRecordType::A, vec![ip], 0);

        // Immediate lookup: hit
        let hit = cache.get("cloudflare.com", DnsRecordType::A);
        assert_eq!(hit, Some(vec![ip]));

        // Wait past min_ttl
        std::thread::sleep(Duration::from_millis(60));
        let expired = cache.get("cloudflare.com", DnsRecordType::A);
        assert_eq!(expired, None);
    }
}
