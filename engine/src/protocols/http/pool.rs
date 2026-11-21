use std::collections::HashMap;
use std::time::{Duration, Instant};

/// Key used to partition idle keep-alive connections.
/// Incorporates `session_id` so private browsing sessions do not share pooled sockets.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PoolKey {
    pub session_id: u64,
    pub host: String,
    pub port: u16,
    pub is_tls: bool,
}

impl PoolKey {
    pub fn new(session_id: u64, host: &str, port: u16, is_tls: bool) -> Self {
        Self {
            session_id,
            host: host.to_ascii_lowercase(),
            port,
            is_tls,
        }
    }
}

/// Metadata and state for an idle pooled connection.
pub struct PooledSocket<T> {
    pub socket: T,
    pub inserted_at: Instant,
    pub is_h2: bool,
}

/// A unified, memory-efficient connection pool supporting partition isolation.
pub struct ConnectionPool<T> {
    idle: HashMap<PoolKey, Vec<PooledSocket<T>>>,
    max_idle_per_key: usize,
    idle_timeout: Duration,
}

impl<T> ConnectionPool<T> {
    pub fn new(max_idle_per_key: usize, idle_timeout: Duration) -> Self {
        Self {
            idle: HashMap::new(),
            max_idle_per_key,
            idle_timeout,
        }
    }

    /// Store an idle connection back into the pool for reuse.
    pub fn put(&mut self, key: PoolKey, socket: T, is_h2: bool) {
        let list = self.idle.entry(key).or_default();
        if list.len() < self.max_idle_per_key {
            list.push(PooledSocket {
                socket,
                inserted_at: Instant::now(),
                is_h2,
            });
        }
    }

    /// Retrieve an available idle connection for the given key, evicting expired sockets.
    pub fn get(&mut self, key: &PoolKey) -> Option<PooledSocket<T>> {
        let now = Instant::now();
        if let Some(list) = self.idle.get_mut(key) {
            while let Some(pooled) = list.pop() {
                if now.duration_since(pooled.inserted_at) <= self.idle_timeout {
                    return Some(pooled);
                }
            }
        }
        None
    }

    /// Remove all expired connections across all sessions and hosts.
    pub fn evict_expired(&mut self) -> usize {
        let now = Instant::now();
        let timeout = self.idle_timeout;
        let mut evicted = 0;

        self.idle.retain(|_, list| {
            let before = list.len();
            list.retain(|c| now.duration_since(c.inserted_at) <= timeout);
            evicted += before - list.len();
            !list.is_empty()
        });

        evicted
    }

    /// Total number of idle connections across the entire pool.
    pub fn total_idle(&self) -> usize {
        self.idle.values().map(|v| v.len()).sum()
    }

    /// Clear all pooled connections for a specific session (e.g. on private session close).
    pub fn clear_session(&mut self, session_id: u64) {
        self.idle.retain(|k, _| k.session_id != session_id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pool_put_and_get() {
        let mut pool = ConnectionPool::new(6, Duration::from_secs(60));
        let key = PoolKey::new(0, "example.com", 443, true);

        pool.put(key.clone(), 42, false);
        assert_eq!(pool.total_idle(), 1);

        let retrieved = pool.get(&key).expect("socket should be available");
        assert_eq!(retrieved.socket, 42);
        assert!(!retrieved.is_h2);
        assert_eq!(pool.total_idle(), 0);
    }

    #[test]
    fn test_pool_session_partition_isolation() {
        let mut pool = ConnectionPool::new(6, Duration::from_secs(60));
        let key_normal = PoolKey::new(0, "bank.com", 443, true);
        let key_private = PoolKey::new(1, "bank.com", 443, true);

        // Store socket in session 0
        pool.put(key_normal.clone(), 100, false);

        // Session 1 (private browsing) MUST NOT receive session 0's socket
        assert!(pool.get(&key_private).is_none());

        // Session 0 gets its socket
        let s0 = pool.get(&key_normal).expect("session 0 gets its socket");
        assert_eq!(s0.socket, 100);
    }

    #[test]
    fn test_pool_max_idle_limit() {
        let mut pool = ConnectionPool::new(2, Duration::from_secs(60));
        let key = PoolKey::new(0, "api.example.com", 80, false);

        pool.put(key.clone(), 1, false);
        pool.put(key.clone(), 2, false);
        pool.put(key.clone(), 3, false); // Exceeds limit 2

        assert_eq!(pool.total_idle(), 2);
    }

    #[test]
    fn test_pool_expiration_and_eviction() {
        let mut pool = ConnectionPool::new(6, Duration::from_millis(50));
        let key = PoolKey::new(0, "slow.com", 443, true);

        pool.put(key.clone(), 99, false);
        std::thread::sleep(Duration::from_millis(60));

        // Get should see it expired and return None
        assert!(pool.get(&key).is_none());
        assert_eq!(pool.total_idle(), 0);
    }

    #[test]
    fn test_pool_clear_session() {
        let mut pool = ConnectionPool::new(6, Duration::from_secs(60));
        let key1 = PoolKey::new(42, "example.com", 443, true);
        let key2 = PoolKey::new(42, "other.com", 443, true);
        let key_other_session = PoolKey::new(99, "example.com", 443, true);

        pool.put(key1, 1, false);
        pool.put(key2, 2, false);
        pool.put(key_other_session, 3, false);

        assert_eq!(pool.total_idle(), 3);
        pool.clear_session(42);
        assert_eq!(pool.total_idle(), 1);
    }
}
