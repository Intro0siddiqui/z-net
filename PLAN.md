# z-net Refactor Plan & Status

> **Status:** **PHASES 1–6 COMPLETED (100% of Planned Work)**  
> **Test Results:** 63 / 63 Rust Engine Tests Passing, 21 / 21 Zig Network Tests Passing  
> **Toolchain:** Zig 0.16.0, Rust stable (rustls 0.23, mio 1.0, quinn-proto 0.11)

---

## 1. Goals & Completion Overview

1. [x] **Unblock `zig build`** — Migrated from removed `std.net` to `std.Io.net` across all modules.
2. [x] **Make silent stubs honest** — Replaced silent stubs and `catch {}` blocks with explicit `error.NotImplemented`, syntax errors, or `@panic`.
3. [x] **Wire rustls WebPKI verification** — Replaced dummy `return true` in `verifyCertificate()` with `net_tls_verify_result` FFI backed by rustls WebPKI.
4. [x] **Rename the Rust crate** — Renamed `rust_net/` to `engine/`, crate renamed to `z-net-engine`, static library configured as `libz_net_engine.a`.
5. [x] **Trim unused Rust imports** — Cleaned up compiler warnings; zero warnings on `cargo build --release`.
6. [x] **Pass test suites** — All 63 Rust engine tests and 21 Zig network tests pass cleanly.

---

## 2. Completed Phases (Phases 1–6)

### Phase 1 — Crate Rename (COMPLETED)
- Moved directory `z-net/rust_net/` → `z-net/engine/`.
- `engine/Cargo.toml`: Package renamed to `name = "z-net-engine"`.
- `build.zig`: Configured to build `--manifest-path "engine/Cargo.toml"` producing `libz_net_engine.a`.
- `.gitignore`: Excludes `engine/target/`.

### Phase 2 — `std.net` → `std.Io.net` Migration (COMPLETED)
Migrated all Zig networking code to Zig 0.16.0 `std.Io.net`:
- `src/z_monitoring/dashboard.zig`: Rewritten for `std.Io.net.Server` and `std.http.Server(Reader, Writer)`.
- `src/z_socket/socket.zig`: Switched `std.net` → `std.Io.net.IpAddress` unions (`.ip4` / `.ip6`).
- `src/z_health/checker.zig`: Switched to `Stream.connect`-based connection loops with `io_ctx`.
- `src/z_dns/dns.zig`: Switched to `std.Io.net.IpAddress.parseIp4`.
- `src/z_proxy/tunnel.zig`: Switched `resolveHost` return types to `std.Io.net.IpAddress`.
- `src/z_proxy/socks5.zig`: Removed stale `std.net` imports.

### Phase 3 — Rustls WebPKI Verification via FFI (COMPLETED)
- Added `net_tls_verify_result` and `net_tls_peer_certificate` to `engine/src/lib.rs:1612`.
- Consumed in `src/z_tls/tls.zig:226`.
- `verifyCertificate()` returns `true` only when rustls verification evaluates to `.Accepted`.

### Phase 4 — Honest Error Propagation (COMPLETED)
- `src/z_tls/tls.zig`: `validateChain()` returns `error.NotImplemented`; `getHandshakeInfo()` returns `error.NotImplemented` when state is not `.Established`.
- `src/z_proxy/pac.zig`: Replaced silent `catch {}` with `catch @panic("OOM in PAC condition stack")`; `evalCond()` returns `error.UnsupportedPacFunction` for unhandled routines.
- `engine/src/protocols/proxy.rs`: Returns `-1` on missing proxy condition and `-2` on truncation in `znet_proxy_discover_env`.

### Phase 5 — Propagated Errors (`catch unreachable` Purged) (COMPLETED)
- Replaced `catch unreachable` across `tests/cicd_integration.zig`, `examples/security_example.zig`, `examples/dns_example.zig`, and `deployment/*.zig` with propagated `try` expressions.

### Phase 6 — Rust Compiler Hygiene (COMPLETED)
- Removed unused imports in `src/protocols/http/h2.rs`, `src/protocols/http3/mod.rs`, and `src/protocols/fetch/mod.rs`.
- Zero compiler warnings during `cargo build --release`.
- All 63 engine tests pass (`cargo test --manifest-path engine/Cargo.toml`).

---

## 3. Definition of Done (Verified)

- [x] `zig build` → exit code 0, no errors.
- [x] `zig build test` → all 21 tests pass.
- [x] `zig build -Dznet-link-rust=true` → exit code 0, no errors.
- [x] `cargo build --release --manifest-path engine/Cargo.toml` → exit code 0, 0 warnings.
- [x] All 63 Rust unit and integration tests passing.
- [x] CI matrix green on Linux, macOS, and Windows targets.
- [x] Zero `std.net` references remain (`std.Io.net` across all Zig modules).
- [x] No `return true` dummy stubs in certificate verification.
- [x] No silent `catch {}` allocation drops in `pac.zig`.
- [x] No `catch unreachable` in examples, tests, or deployment scripts.
- [x] `engine/Cargo.toml` specifies `name = "z-net-engine"`.
- [x] `build.zig` references `engine/` and links `libz_net_engine.a`.

---

## 4. Future / Follow-up Roadmap Items

- **Phase 7 (MP-QUIC)**: Multi-interface scheduling across cellular and Wi-Fi networks (connection migration and Alt-Svc registry already completed).
- **Phase 8 (RFC 9220)**: WebSockets over HTTP/3 extended CONNECT method.
