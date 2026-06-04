# z-net Refactor — Execution Plan

**Branch:** `feat/refactor-zig-016-build-green-stubs-honest`
**Base:** `master` (active development)
**Zig:** 0.16.0 | **Rust:** stable (rustls 0.23, quinn-proto 0.11)
**Date:** 2026-06-04

---

## Current State
- `.gitignore` already updated: `rust_net/target/` → `engine/target/`
- `ci.yml` already updated: `cd rust_net` → `cd engine`; added FFI-linked build step
- `PLAN.md` exists with the full architecture decisions
- Directory `rust_net/` still needs renaming to `engine/`
- `build.zig` still references `rust_net/` and `liblean_net.a`
- `rust_net/Cargo.toml` still has `name = "lean-net"`

---

## Phase 1 — Rename `rust_net/` → `engine/`

### Steps
1. `git checkout -b feat/refactor-zig-016-build-green-stubs-honest`
2. `git mv rust_net engine`
3. `engine/Cargo.toml` line 2: `name = "lean-net"` → `name = "z-net-engine"`
4. `build.zig` line 12: `"rust_net/Cargo.toml"` → `"engine/Cargo.toml"`
5. `build.zig` line 15: `b.path("rust_net/target/release/liblean_net.a")` → `b.path("engine/target/release/libz_net_engine.a")`
6. `build.zig` line 79: comment references `lean-net` — update to `z-net-engine`
7. `build.zig` line 85: `"liblean_net.a"` in option description → `"libz_net_engine.a"`

### Verify
- `cargo build --release --manifest-path engine/Cargo.toml` → produces `libz_net_engine.a`

---

## Phase 2 — `std.net` → `std.Io.net`

### 2A: `src/z_monitoring/dashboard.zig` (FULL REWRITE)
**Current (broken):** Uses `std.net.Address`, `std.net.Server`, `std.http.Server` with old API.
**New API:** `std.Io.net` (IpAddress union), `std.http.Server(Reader, Writer)` takes reader/writer not connection.

Changes:
- Line 2: `const net = std.net;` → `const net = std.Io.net;`
- Line 55: `net.Address.parseIp(...)` → `net.IpAddress.parseIp(...)` or use string literal `"127.0.0.1"` with port
- Line 56: `address.listen(...)` — `std.Io.net.Server` API: create with `std.Io.net.Server.init()` + listen
- Lines 67-91: `handleConnection` — old `net.Server.Connection` type removed; new API uses `std.Io.net.Stream`
- Lines 71-76: `http.Server.init(conn, &read_buffer)` / `server.receiveHead()` — new API: `std.http.Server.init(.{ .reader = reader, .writer = writer })` then `server.receiveHead()`
- Lines 93-115: `handleRoot/handleMetrics/handleNotFound` — use new `request.respond()` API

**New dashboard.zig structure:**
```zig
const std = @import("std");
const net = std.Io.net;
const http = std.http;

pub fn start(allocator: std.mem.Allocator, io: *std.Io, port: u16) !void {
    const address = try net.IpAddress.parseIp4("127.0.0.1", port);
    var server = try net.Server.init(io, address, .{ .reuse_address = true });
    defer server.deinit();
    while (true) {
        const conn = try server.accept();
        _ = try std.Thread.spawn(.{}, handleConnection, .{ allocator, conn });
    }
}
```

### 2B: `src/z_monitoring/main.zig`
- Add `std.Io.Threaded` instantiation
- Pass `&threaded.io()` to `dashboard.start()`

### 2C: `src/z_socket/socket.zig`
- Line 5: `const net = std.net;` → `const net = std.Io.net;`
- Line 40: `net.Address.Family` → `net.IpAddress.Family`
- Line 48: `net.Address` → `net.IpAddress`
- Line 98: `net.Address` → `net.IpAddress`
- Line 166: `net.Address.parseIp4(host, port)` → `net.IpAddress.parseIp4(host, port)`

### 2D: `src/z_health/checker.zig`
- Line 2: `const net = std.net;` → `const net = std.Io.net;`
- Line 30: `net.Address.parseIp(host, port)` → `net.IpAddress.parseIp(host, port)`
- Line 42: `net.tcpConnectToAddress(address)` — this function doesn't exist in `std.Io.net`. Replace with `std.Io.net.Stream.connect(io_ctx, address)` retry loop.
- Add `io_ctx: *std.Io` parameter to `checkTcpConnection`

### 2E: `src/z_dns/dns.zig`
- Line 151: `std.net.Address.parseIp4(host, port)` → `std.Io.net.IpAddress.parseIp4(host, port)`
- Line 195: same

### 2F: `src/z_proxy/tunnel.zig`
- Line 13: `const net = std.net;` → `const net = std.Io.net;`
- Line 58: return type `net.Address` → `net.IpAddress`
- Line 61: `net.Address.parseIp4(host, port)` → `net.IpAddress.parseIp4(host, port)`

### 2G: `src/z_proxy/socks5.zig`
- Line 8: delete `const net = std.net;` (unused)

### Verify
- `zig build` green
- `zig build test` green

---

## Phase 3 — Wire rustls verification FFI

### Rust side: `rust_net/src/lib.rs` (→ `engine/src/lib.rs` after rename)

Add after existing FFI surface (~line 1180):

```rust
#[repr(C)]
pub enum TlsVerifyResult {
    Accepted = 0,
    Rejected = -1,
    NotEstablished = -2,
}

/// Returns rustls's WebPKI verification result after handshake.
#[no_mangle]
pub extern "C" fn net_tls_verify_result(
    engine_handle: NetEngineHandle,
    tls_handle: TlsHandle,
) -> TlsVerifyResult {
    // Look up the TlsState, check if handshake completed, read verifier result
    // If state is not Established, return NotEstablished
    // Otherwise check rustls::client::ServerCertVerified
}

/// Copies peer certificate DER into caller buffer. Returns bytes written or -1.
#[no_mangle]
pub extern "C" fn net_tls_peer_certificate(
    engine_handle: NetEngineHandle,
    tls_handle: TlsHandle,
    out: *mut u8,
    out_len: usize,
) -> i32 {
    // Read peer cert chain from rustls connection
    // Copy first cert DER to out buffer, capped at out_len
}
```

### Zig side: `src/z_tls/tls.zig`

Add FFI declarations:
```zig
extern fn net_tls_verify_result(engine: ?*anyopaque, tls: TlsHandle) i32;
extern fn net_tls_peer_certificate(engine: ?*anyopaque, tls: TlsHandle, out: [*]u8, out_len: usize) i32;
```

Replace `verifyCertificate()` (lines 215-218):
```zig
pub fn verifyCertificate(self: *Self) TlsError!bool {
    if (self.engine == null or self.handle == null) return error.LibraryNotLoaded;
    const result = net_tls_verify_result(self.engine, self.handle);
    return switch (result) {
        0 => true,   // Accepted
        -1 => false,  // Rejected
        else => error.NotImplemented, // NotEstablished or unknown
    };
}
```

Replace `getHandshakeInfo()` peer_certificate population (lines 195-208):
```zig
pub fn getHandshakeInfo(self: *Self) TlsError!TlsHandshakeInfo {
    if (self.state != .Established) return error.NotImplemented;
    var cert_buf: [4096]u8 = undefined;
    const cert_len = net_tls_peer_certificate(self.engine, self.handle, &cert_buf, cert_buf.len);
    const peer_cert = if (cert_len > 0) blk: {
        const owned = try self.allocator.alloc(u8, @intCast(cert_len));
        @memcpy(owned, cert_buf[0..@intCast(cert_len)]);
        break :blk owned;
    } else null;
    return TlsHandshakeInfo{
        .protocol = switch (self.version) { ... },
        .cipher_suite = ...,
        .peer_certificate = peer_cert,
        .handshake_time = 0,
    };
}
```

### Verify
- `zig build -Dznet-link-rust=true` green
- `cargo build --release` green

---

## Phase 4 — Silent stubs → explicit errors

| File:Line | Current | After |
|---|---|---|
| `src/z_tls/tls.zig:251-254` | `validateChain` returns `true` | `return error.NotImplemented;` |
| `src/z_tls/tls.zig:322-327` | `BACKEND = "rustls"` | Add `pub const WIRED = false;` with doc comment |
| `src/z_proxy/pac.zig:61` | `catch {}` | `catch @panic("OOM in PAC condition stack");` |
| `src/z_proxy/pac.zig:82-106` | `evalCond` returns `null` for unknown | Return `error.UnsupportedPacFunction`; `findProxyForURL` uses `try` on line 60 |
| `src/z_proxy/pac.zig:94-96` | `isInNet` returns `endsWith` stub | `@panic("isInNet: network/mask args not yet supported in PAC engine");` |
| `rust_net/src/protocols/proxy.rs:87` | `None => return 0` | `None => return -1` |
| `rust_net/src/protocols/proxy.rs:165-170` | `if`-branch missing `return None` | Add `return None;` if no `return` on next line |
| `rust_net/src/protocols/proxy.rs:60-63` | `znet_proxy_discover_env` truncates silently | `return -2` on truncation |

### Verify
- `zig build` green
- `cargo build --release` green

---

## Phase 5 — `unreachable` → propagated errors (10 sites)

| File:Line | Change |
|---|---|
| `tests/cicd_integration.zig:43` | `catch unreachable` → `try`, fn signature `!CICDIntegrationTests` already uses `!` |
| `examples/security_example.zig:221` | `catch unreachable` → propagate with `try` |
| `examples/dns_example.zig:291` | `catch unreachable` → `try` |
| `deployment/backup_recovery.zig:372` | `catch unreachable` → `try`, fn returns `!ArrayList(BackupJob)` |
| `deployment/backup_recovery.zig:379` | same |
| `deployment/backup_recovery.zig:478` | same pattern |
| `deployment/rolling_updates.zig:227` | `catch unreachable` → `try` |
| `deployment/rolling_updates.zig:458` | same |
| `deployment/rolling_updates.zig:530` | same |
| `deployment/automation_scripts.zig:204` | `catch unreachable` → `try` |

### Verify
- `zig build test` green

---

## Phase 6 — Trim unused Rust imports

| File | Issue | Fix |
|---|---|---|
| `rust_net/src/protocols/http/h2.rs:1` | `use h2;` unused | Add `#[allow(unused_imports)]` or remove (keep `h2` in Cargo.toml for future) |
| `rust_net/src/protocols/http3/mod.rs:2` | `use quinn_proto;` unused | Remove the line |
| `rust_net/src/protocols/fetch/mod.rs:3` | `use std::os::raw::c_int;` unused | Narrow to `use std::os::raw::c_char;` only |

### Verify
- `cargo build --release` → **0 warnings**

---

## Final Verification

```bash
zig build                                          # Phase 1-2
zig build test                                     # All tests pass
zig build -Dznet-link-rust=true                    # Phase 3 FFI path
cargo build --release --manifest-path engine/Cargo.toml  # Phase 6 zero warnings
```

---

## Git Workflow

1. `git checkout -b feat/refactor-zig-016-build-green-stubs-honest` from `master`
2. Stage files **explicitly** per phase (never `git add .`)
3. Commit per phase with descriptive messages
4. `git push -u origin HEAD`
5. `gh pr create --fill`
6. `gh pr checks --watch` — wait for CI green on all 3 OS matrix jobs
7. `gh pr merge --squash --delete-branch`

---

## Post-PR Follow-ups (not this PR)
- Migrate `z_quic` to FFI over `net_http3_*`
- Migrate `z_socket` raw TCP/UDP to FFI over `net_engine_create`/`net_connect`
- Migrate `z_monitoring` to FFI over `net_get_metrics`
- Migrate `z_body_ring.zig` to FFI over `net_body_ring_*`
- Flip `build.zig` `link_rust` default to `true`
