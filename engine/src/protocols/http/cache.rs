use std::collections::HashMap;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CacheKey {
    pub session_id: u64,
    pub url: String,
}

#[derive(Debug, Clone)]
pub struct CacheEntry {
    pub status: u16,
    pub reason: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    pub etag: Option<String>,
    pub last_modified: Option<String>,
    pub stored_at: Instant,
    pub max_age: Option<Duration>,
    pub no_cache: bool,
}

impl CacheEntry {
    pub fn is_fresh(&self) -> bool {
        if self.no_cache {
            return false;
        }
        match self.max_age {
            Some(ma) => self.stored_at.elapsed() < ma,
            None => false,
        }
    }
}

pub enum CacheLookup {
    Fresh(CacheEntry),
    Revalidate {
        etag: Option<String>,
        last_modified: Option<String>,
    },
    Miss,
}

#[derive(Debug, Default)]
struct CacheControlDirectives {
    no_store: bool,
    no_cache: bool,
    max_age: Option<Duration>,
}

fn parse_cache_control(headers: &[(String, String)]) -> CacheControlDirectives {
    let mut out = CacheControlDirectives::default();
    for (k, v) in headers {
        if !k.eq_ignore_ascii_case("cache-control") {
            continue;
        }
        for part in v.split(',') {
            let token = part.trim();
            if token.eq_ignore_ascii_case("no-store") {
                out.no_store = true;
            } else if token.eq_ignore_ascii_case("no-cache") {
                out.no_cache = true;
            } else if let Some((dk, dv)) = token.split_once('=') {
                if dk.trim().eq_ignore_ascii_case("max-age") {
                    let secs_str = dv.trim().trim_matches('"');
                    if let Ok(secs) = secs_str.parse::<u64>() {
                        out.max_age = Some(Duration::from_secs(secs));
                    }
                }
            }
        }
    }
    out
}

fn find_header(headers: &[(String, String)], name: &str) -> Option<String> {
    headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.clone())
}

pub struct HttpCache {
    entries: HashMap<CacheKey, CacheEntry>,
    max_entries: usize,
    max_entry_bytes: usize,
}

impl HttpCache {
    pub fn new(max_entries: usize, max_entry_bytes: usize) -> Self {
        Self {
            entries: HashMap::new(),
            max_entries,
            max_entry_bytes,
        }
    }

    pub fn lookup(
        &self,
        session_id: u64,
        method: &str,
        url: &str,
        req_headers: &[(String, String)],
    ) -> CacheLookup {
        if !method.eq_ignore_ascii_case("GET") {
            return CacheLookup::Miss;
        }
        if req_headers.iter().any(|(k, _)| k.eq_ignore_ascii_case("range")) {
            return CacheLookup::Miss;
        }
        let req_cc = parse_cache_control(req_headers);
        if req_cc.no_store {
            return CacheLookup::Miss;
        }

        let key = CacheKey {
            session_id,
            url: url.to_string(),
        };
        let entry = match self.entries.get(&key) {
            Some(e) => e,
            None => return CacheLookup::Miss,
        };

        let force_revalidate = req_cc.no_cache || req_cc.max_age == Some(Duration::ZERO);
        if !force_revalidate && entry.is_fresh() {
            return CacheLookup::Fresh(entry.clone());
        }

        if entry.etag.is_some() || entry.last_modified.is_some() {
            return CacheLookup::Revalidate {
                etag: entry.etag.clone(),
                last_modified: entry.last_modified.clone(),
            };
        }

        CacheLookup::Miss
    }

    pub fn store(
        &mut self,
        session_id: u64,
        method: &str,
        url: &str,
        status: u16,
        reason: &str,
        headers: &[(String, String)],
        body: Vec<u8>,
    ) {
        if !method.eq_ignore_ascii_case("GET") {
            return;
        }
        if !matches!(status, 200 | 203 | 204 | 300 | 301 | 404 | 410) {
            return;
        }
        if body.len() > self.max_entry_bytes {
            return;
        }

        let cc = parse_cache_control(headers);
        if cc.no_store {
            return;
        }

        let etag = find_header(headers, "etag");
        let last_modified = find_header(headers, "last-modified");

        // Only cache if there's an explicit freshness lifetime or validator
        if cc.max_age.is_none() && etag.is_none() && last_modified.is_none() && !cc.no_cache {
            return;
        }

        if self.entries.len() >= self.max_entries {
            // Evict oldest entry
            if let Some(oldest_key) = self
                .entries
                .iter()
                .min_by_key(|(_, e)| e.stored_at)
                .map(|(k, _)| k.clone())
            {
                self.entries.remove(&oldest_key);
            }
        }

        let key = CacheKey {
            session_id,
            url: url.to_string(),
        };
        self.entries.insert(
            key,
            CacheEntry {
                status,
                reason: reason.to_string(),
                headers: headers.to_vec(),
                body,
                etag,
                last_modified,
                stored_at: Instant::now(),
                max_age: cc.max_age,
                no_cache: cc.no_cache,
            },
        );
    }

    pub fn revalidate_304(
        &mut self,
        session_id: u64,
        url: &str,
        resp_304_headers: &[(String, String)],
    ) -> Option<CacheEntry> {
        let key = CacheKey {
            session_id,
            url: url.to_string(),
        };
        let entry = self.entries.get_mut(&key)?;
        let cc = parse_cache_control(resp_304_headers);
        entry.stored_at = Instant::now();
        if cc.max_age.is_some() {
            entry.max_age = cc.max_age;
        }
        entry.no_cache = cc.no_cache;
        if let Some(new_etag) = find_header(resp_304_headers, "etag") {
            entry.etag = Some(new_etag);
        }
        if let Some(new_lm) = find_header(resp_304_headers, "last-modified") {
            entry.last_modified = Some(new_lm);
        }
        // Merge updated headers from 304 into cached headers
        for (rk, rv) in resp_304_headers {
            if let Some(existing) = entry.headers.iter_mut().find(|(k, _)| k.eq_ignore_ascii_case(rk)) {
                existing.1 = rv.clone();
            } else {
                entry.headers.push((rk.clone(), rv.clone()));
            }
        }
        Some(entry.clone())
    }

    pub fn clear_session(&mut self, session_id: u64) {
        self.entries.retain(|k, _| k.session_id != session_id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_http_cache_fresh_hit_and_no_store() {
        let mut cache = HttpCache::new(16, 1024 * 1024);
        let headers = vec![
            ("cache-control".to_string(), "public, max-age=60".to_string()),
            ("content-type".to_string(), "text/css".to_string()),
        ];
        cache.store(0, "GET", "https://example.com/app.css", 200, "OK", &headers, b"body{}".to_vec());

        match cache.lookup(0, "GET", "https://example.com/app.css", &[]) {
            CacheLookup::Fresh(e) => {
                assert_eq!(e.status, 200);
                assert_eq!(e.body, b"body{}");
            }
            _ => panic!("expected Fresh cache hit"),
        }

        // Session isolation
        assert!(matches!(
            cache.lookup(1, "GET", "https://example.com/app.css", &[]),
            CacheLookup::Miss
        ));

        // no-store must not cache
        let no_store_headers = vec![("cache-control".to_string(), "no-store, max-age=60".to_string())];
        cache.store(0, "GET", "https://example.com/secret", 200, "OK", &no_store_headers, b"secret".to_vec());
        assert!(matches!(
            cache.lookup(0, "GET", "https://example.com/secret", &[]),
            CacheLookup::Miss
        ));
    }

    #[test]
    fn test_http_cache_etag_revalidation_304() {
        let mut cache = HttpCache::new(16, 1024 * 1024);
        let headers = vec![
            ("cache-control".to_string(), "no-cache".to_string()),
            ("etag".to_string(), "\"v1\"".to_string()),
        ];
        cache.store(0, "GET", "https://example.com/app.js", 200, "OK", &headers, b"console.log(1)".to_vec());

        match cache.lookup(0, "GET", "https://example.com/app.js", &[]) {
            CacheLookup::Revalidate { etag, last_modified } => {
                assert_eq!(etag.as_deref(), Some("\"v1\""));
                assert!(last_modified.is_none());
            }
            _ => panic!("expected Revalidate"),
        }

        let resp_304 = vec![
            ("cache-control".to_string(), "max-age=120".to_string()),
            ("etag".to_string(), "\"v2\"".to_string()),
        ];
        let refreshed = cache.revalidate_304(0, "https://example.com/app.js", &resp_304).unwrap();
        assert_eq!(refreshed.status, 200);
        assert_eq!(refreshed.body, b"console.log(1)");
        assert_eq!(refreshed.etag.as_deref(), Some("\"v2\""));
        assert!(refreshed.is_fresh());
    }
}
