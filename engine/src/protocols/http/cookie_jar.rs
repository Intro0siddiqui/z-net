use std::collections::HashMap;
use std::sync::RwLock;
use std::time::{Duration, SystemTime};
use url::Url;

/// An RFC 6265 HTTP cookie entry stored inside z-net.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredCookie {
    pub name: String,
    pub value: String,
    pub domain: String,
    pub host_only: bool,
    pub path: String,
    pub secure: bool,
    pub http_only: bool,
    pub expires_at: Option<SystemTime>,
    pub creation_time: SystemTime,
}

impl StoredCookie {
    /// Check whether this cookie matches the specified URL per RFC 6265.
    pub fn matches(&self, url: &Url, now: SystemTime) -> bool {
        // 1. Check expiration
        if let Some(exp) = self.expires_at {
            if now >= exp {
                return false;
            }
        }

        // 2. Check scheme / Secure flag
        if self.secure && url.scheme() != "https" && url.scheme() != "wss" {
            return false;
        }

        // 3. Check Domain
        let host = match url.host_str() {
            Some(h) => h.to_ascii_lowercase(),
            None => return false,
        };

        let cookie_domain = self.domain.to_ascii_lowercase();
        if self.host_only {
            if host != cookie_domain {
                return false;
            }
        } else {
            // Domain match per RFC 6265 section 5.1.3:
            // The domain string and the string are identical, or
            // the domain string is a suffix of the string AND the character
            // immediately preceding is '.'
            let trimmed_domain = cookie_domain.trim_start_matches('.');
            if host != trimmed_domain {
                if !host.ends_with(trimmed_domain) {
                    return false;
                }
                let prefix_len = host.len() - trimmed_domain.len();
                if prefix_len == 0 || !host[..prefix_len].ends_with('.') {
                    return false;
                }
            }
        }

        // 4. Check Path (RFC 6265 section 5.1.4)
        let req_path = url.path();
        if req_path != self.path {
            if !req_path.starts_with(&self.path) {
                return false;
            }
            if !self.path.ends_with('/') && !req_path[self.path.len()..].starts_with('/') {
                return false;
            }
        }

        true
    }
}

/// Thread-safe, multi-session RFC 6265 Cookie Jar.
pub struct CookieJar {
    /// Partitions cookies by session_id to isolate private browsing / distinct profiles.
    sessions: RwLock<HashMap<u64, Vec<StoredCookie>>>,
}

impl CookieJar {
    pub fn new() -> Self {
        Self {
            sessions: RwLock::new(HashMap::new()),
        }
    }

    /// Clear all cookies associated with a session ID.
    pub fn clear_session(&self, session_id: u64) {
        if let Ok(mut lock) = self.sessions.write() {
            lock.remove(&session_id);
        }
    }

    /// Parse and store a Set-Cookie header into the jar for the given session and request URL.
    pub fn process_set_cookie(&self, session_id: u64, url: &Url, set_cookie_str: &str) -> bool {
        let host = match url.host_str() {
            Some(h) => h.to_ascii_lowercase(),
            None => return false,
        };

        let parsed = match cookie::Cookie::parse(set_cookie_str) {
            Ok(c) => c,
            Err(_) => return false,
        };

        let name = parsed.name().to_string();
        let value = parsed.value().to_string();

        // Determine domain
        let (domain, host_only) = if let Some(d) = parsed.domain() {
            let d_clean = d.trim_start_matches('.').to_ascii_lowercase();
            // Verify domain attribute: host must end with domain attribute
            if host != d_clean && !host.ends_with(&format!(".{}", d_clean)) {
                // Reject invalid domain attribute trying to set cookie for different TLD/domain
                return false;
            }
            (d_clean, false)
        } else {
            (host.clone(), true)
        };

        // Determine path (RFC 6265 Section 5.1.4 default-path)
        let path = if let Some(p) = parsed.path() {
            p.to_string()
        } else {
            let uri_path = url.path();
            if uri_path.is_empty() || !uri_path.starts_with('/') {
                "/".to_string()
            } else if let Some(last_slash) = uri_path.rfind('/') {
                if last_slash == 0 {
                    "/".to_string()
                } else {
                    uri_path[..last_slash].to_string()
                }
            } else {
                "/".to_string()
            }
        };

        let secure = parsed.secure().unwrap_or(false);
        let http_only = parsed.http_only().unwrap_or(false);

        // Determine expiry
        let now = SystemTime::now();
        let expires_at = if let Some(max_age) = parsed.max_age() {
            let secs = max_age.whole_seconds();
            if secs <= 0 {
                Some(now.checked_sub(Duration::from_secs(1)).unwrap_or(now))
            } else {
                Some(now + Duration::from_secs(secs as u64))
            }
        } else if let Some(cookie::Expiration::DateTime(dt)) = parsed.expires() {
            let ts = dt.unix_timestamp();
            if ts <= 0 {
                Some(now.checked_sub(Duration::from_secs(1)).unwrap_or(now))
            } else {
                let dur = Duration::from_secs(ts as u64);
                Some(SystemTime::UNIX_EPOCH + dur)
            }
        } else {
            None // Session cookie
        };

        let cookie_entry = StoredCookie {
            name: name.clone(),
            value,
            domain: domain.clone(),
            host_only,
            path: path.clone(),
            secure,
            http_only,
            expires_at,
            creation_time: now,
        };

        // Insert or update in session store
        if let Ok(mut lock) = self.sessions.write() {
            let session_list = lock.entry(session_id).or_default();

            // If expired right away (Max-Age=0), delete existing matching cookie
            if let Some(exp) = expires_at {
                if now >= exp {
                    session_list.retain(|c| !(c.name == name && c.domain == domain && c.path == path));
                    return true;
                }
            }

            // Remove existing cookie with same name, domain, and path
            session_list.retain(|c| !(c.name == name && c.domain == domain && c.path == path));
            session_list.push(cookie_entry);
            true
        } else {
            false
        }
    }

    /// Retrieve formatted "name1=val1; name2=val2" Cookie header for a request URL.
    pub fn get_cookie_header(&self, session_id: u64, url: &Url) -> Option<String> {
        let now = SystemTime::now();
        let lock = self.sessions.read().ok()?;
        let session_list = lock.get(&session_id)?;

        let mut matching_cookies = Vec::new();
        for c in session_list {
            if c.matches(url, now) {
                matching_cookies.push(format!("{}={}", c.name, c.value));
            }
        }

        if matching_cookies.is_empty() {
            None
        } else {
            Some(matching_cookies.join("; "))
        }
    }

    /// Prune expired cookies across all sessions.
    pub fn prune_expired(&self) {
        let now = SystemTime::now();
        if let Ok(mut lock) = self.sessions.write() {
            for list in lock.values_mut() {
                list.retain(|c| {
                    if let Some(exp) = c.expires_at {
                        now < exp
                    } else {
                        true
                    }
                });
            }
        }
    }
}

impl Default for CookieJar {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cookie_jar_basic_storage_and_retrieval() {
        let jar = CookieJar::new();
        let url = Url::parse("https://example.com/api/v1/data").unwrap();

        assert!(jar.process_set_cookie(1, &url, "sid=abc123xyz; Path=/api; Secure; HttpOnly"));
        assert!(jar.process_set_cookie(1, &url, "theme=dark; Path=/"));

        let header = jar.get_cookie_header(1, &url).expect("Should have cookies");
        assert!(header.contains("sid=abc123xyz"));
        assert!(header.contains("theme=dark"));

        // Different session isolation check
        assert!(jar.get_cookie_header(2, &url).is_none());

        // Path filtering check: /other should have theme=dark but not sid=abc123xyz
        let other_url = Url::parse("https://example.com/other").unwrap();
        let other_header = jar.get_cookie_header(1, &other_url).expect("Should have theme");
        assert!(other_header.contains("theme=dark"));
        assert!(!other_header.contains("sid=abc123xyz"));
    }

    #[test]
    fn test_cookie_domain_matching() {
        let jar = CookieJar::new();
        let url = Url::parse("https://sub.example.com/").unwrap();

        // Domain cookie on example.com
        assert!(jar.process_set_cookie(1, &url, "account=main; Domain=example.com; Path=/"));

        // Should match subdomain
        let sub_header = jar.get_cookie_header(1, &url).unwrap();
        assert!(sub_header.contains("account=main"));

        // Should not match unrelated domain
        let evil_url = Url::parse("https://evilexample.com/").unwrap();
        assert!(jar.get_cookie_header(1, &evil_url).is_none());
    }

    #[test]
    fn test_cookie_secure_enforcement() {
        let jar = CookieJar::new();
        let https_url = Url::parse("https://secure.example.com/").unwrap();
        let http_url = Url::parse("http://secure.example.com/").unwrap();

        assert!(jar.process_set_cookie(1, &https_url, "secret=token; Secure; Path=/"));

        // HTTPS matches
        assert!(jar.get_cookie_header(1, &https_url).is_some());
        // Plaintext HTTP must NOT receive Secure cookies
        assert!(jar.get_cookie_header(1, &http_url).is_none());
    }

    #[test]
    fn test_cookie_max_age_zero_deletion() {
        let jar = CookieJar::new();
        let url = Url::parse("https://example.com/").unwrap();

        assert!(jar.process_set_cookie(1, &url, "user=john; Path=/"));
        assert!(jar.get_cookie_header(1, &url).is_some());

        // Delete with Max-Age=0
        assert!(jar.process_set_cookie(1, &url, "user=deleted; Max-Age=0; Path=/"));
        assert!(jar.get_cookie_header(1, &url).is_none());
    }
}
