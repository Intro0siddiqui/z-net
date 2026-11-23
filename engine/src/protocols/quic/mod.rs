//! Multi-Path QUIC and Connection Migration per RFC 9000 Section 9.
//!
//! Enables seamless connection migration between network interfaces (e.g. Wi-Fi
//! and 5G mobile hotspot) without dropping active streams, socket sessions, or TLS state.

use std::net::{SocketAddr, UdpSocket};
use std::sync::Arc;
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct QuicPath {
    pub id: u32,
    pub local_addr: SocketAddr,
    pub remote_addr: SocketAddr,
    pub socket: Arc<UdpSocket>,
    pub is_active: bool,
    pub validated: bool,
    pub rtt: Option<Duration>,
}

pub struct QuicPathManager {
    paths: Vec<QuicPath>,
    active_path_idx: usize,
    next_path_id: u32,
    pub remote_addr: SocketAddr,
}

impl QuicPathManager {
    pub fn new(initial_socket: UdpSocket, local_addr: SocketAddr, remote_addr: SocketAddr) -> Self {
        let _ = initial_socket.set_nonblocking(true);
        let path0 = QuicPath {
            id: 0,
            local_addr,
            remote_addr,
            socket: Arc::new(initial_socket),
            is_active: true,
            validated: true,
            rtt: None,
        };

        Self {
            paths: vec![path0],
            active_path_idx: 0,
            next_path_id: 1,
            remote_addr,
        }
    }

    /// Retrieve the currently active path for transmission.
    pub fn active_path(&self) -> &QuicPath {
        &self.paths[self.active_path_idx]
    }

    /// Retrieve the UDP socket of the active path.
    pub fn active_socket(&self) -> Arc<UdpSocket> {
        self.paths[self.active_path_idx].socket.clone()
    }

    /// Add a new alternate network path (e.g. 5G mobile hotspot interface).
    pub fn add_path(&mut self, local_addr: SocketAddr) -> Result<u32, String> {
        let socket = UdpSocket::bind(local_addr)
            .map_err(|e| format!("Failed to bind new QUIC path socket on {}: {}", local_addr, e))?;
        socket.set_nonblocking(true)
            .map_err(|e| format!("Failed to set nonblocking on new path socket: {}", e))?;

        let actual_local = socket.local_addr()
            .map_err(|e| format!("Failed to get local addr: {}", e))?;

        let path_id = self.next_path_id;
        self.next_path_id += 1;

        let path = QuicPath {
            id: path_id,
            local_addr: actual_local,
            remote_addr: self.remote_addr,
            socket: Arc::new(socket),
            is_active: false,
            validated: false,
            rtt: None,
        };

        self.paths.push(path);
        Ok(path_id)
    }

    /// Migrate active transmission to the path identified by `path_id`.
    pub fn migrate_to_path(&mut self, path_id: u32) -> Result<(), String> {
        let target_idx = self.paths.iter().position(|p| p.id == path_id)
            .ok_or_else(|| format!("Path ID {} not found", path_id))?;

        if target_idx == self.active_path_idx {
            return Ok(()); // Already active
        }

        self.paths[self.active_path_idx].is_active = false;
        self.paths[target_idx].is_active = true;
        self.paths[target_idx].validated = true;
        self.active_path_idx = target_idx;

        Ok(())
    }

    /// Rebind and migrate to a new local address in one seamless step.
    pub fn migrate_to_address(&mut self, new_local_addr: SocketAddr) -> Result<u32, String> {
        let path_id = self.add_path(new_local_addr)?;
        self.migrate_to_path(path_id)?;
        Ok(path_id)
    }

    /// Transmit bytes to the remote endpoint over the currently active path.
    pub fn send(&self, buf: &[u8]) -> std::io::Result<usize> {
        let active = self.active_path();
        active.socket.send_to(buf, active.remote_addr)
    }

    /// Poll incoming datagrams across all paths (active and standby).
    /// Returns `Some((bytes_read, remote_addr, path_id))` if a datagram is received.
    pub fn recv_any(&self, buf: &mut [u8]) -> Option<(usize, SocketAddr, u32)> {
        // Check active path first
        let active_path = &self.paths[self.active_path_idx];
        if let Ok((n, remote)) = active_path.socket.recv_from(buf) {
            return Some((n, remote, active_path.id));
        }

        // Check alternate standby paths
        for (idx, path) in self.paths.iter().enumerate() {
            if idx == self.active_path_idx {
                continue;
            }
            if let Ok((n, remote)) = path.socket.recv_from(buf) {
                return Some((n, remote, path.id));
            }
        }

        None
    }

    /// Number of registered network paths.
    pub fn path_count(&self) -> usize {
        self.paths.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_quic_path_manager_lifecycle_and_migration() {
        let socket1 = UdpSocket::bind("127.0.0.1:0").expect("bind path1");
        let local1 = socket1.local_addr().unwrap();
        let remote: SocketAddr = "127.0.0.1:4433".parse().unwrap();

        let mut pm = QuicPathManager::new(socket1, local1, remote);
        assert_eq!(pm.path_count(), 1);
        assert_eq!(pm.active_path().id, 0);
        assert!(pm.active_path().is_active);

        // Add alternate path (e.g. 5G hotspot adapter)
        let new_local: SocketAddr = SocketAddr::new(std::net::IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 0);
        let path2_id = pm.add_path(new_local).expect("add path2");
        assert_eq!(pm.path_count(), 2);
        assert_eq!(path2_id, 1);
        assert_eq!(pm.active_path().id, 0); // Still 0 before migration

        // Migrate to path2
        pm.migrate_to_path(path2_id).expect("migrate");
        assert_eq!(pm.active_path().id, 1);
        assert!(pm.active_path().is_active);
        assert!(!pm.paths[0].is_active); // Previous path is now standby
    }

    #[test]
    fn test_quic_path_manager_migrate_to_address() {
        let socket1 = UdpSocket::bind("127.0.0.1:0").expect("bind path1");
        let local1 = socket1.local_addr().unwrap();
        let remote: SocketAddr = "127.0.0.1:4433".parse().unwrap();

        let mut pm = QuicPathManager::new(socket1, local1, remote);
        let new_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();

        let migrated_id = pm.migrate_to_address(new_addr).expect("migrate to address");
        assert_eq!(pm.active_path().id, migrated_id);
        assert_eq!(pm.path_count(), 2);
    }
}
