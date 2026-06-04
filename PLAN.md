# z-net Refactor Plan

**Branch:** `feat/refactor-zig-016-build-green-stubs-honest`
**Base branch:** `master` (active development — see `git log` for recent merges into master)
**Target:** `master` via squash-merge after CI is green
**Date:** 2026-06-04
**Zig toolchain:** 0.16.0
**Rust toolchain:** stable (rustls 0.23, mio 1.0, quinn-proto 0.11)

---

## 1. Goals

1. **Unblock `zig build`** — currently fails on `std.net` removal in Zig 0.16.0.
2. **Make silent stubs honest** — convert stubs that pretend to work to explicit `error.NotImplemented` / `@panic` / proper FFI.
3. **Wire rustls verification** — `verifyCertificate()` currently returns `true` regardless of the cert. The FFI surface gets the missing pieces; `tls.zig` consumes them.
4. **Rename the Rust crate** — `lean-net` is just z-net's Rust side; rename to `z-net-engine` and move directory `rust_net/` → `engine/`.
5. **Trim unused Rust imports** — the cargo build has 4 pre-existing warnings (unused `h2`, `quinn_proto`, `c_int`, `url`).
6. **Architectural decision (recorded, not enacted in this PR):** Zig owns system-level + simple protocol handshakes; Rust (`z-net-engine`) owns major networking (TLS, QUIC, HTTP, fetch, compression, body ring, metrics). The full migration of `z_quic`/`z_socket`/`z_monitoring`/`z_body_ring` to FFI clients over `z-net-engine` is **deferred to follow-up PRs** to keep this one reviewable.

---

## 2. Non-Goals (explicitly out of scope)

- Full migration of `z_quic` / `z_socket` / `z_monitoring` / `z_body_ring` to FFI clients.
- Adding new protocol features (NTLM, Kerberos, SOCKS5 server, etc.).
- Adding new dependencies on either side.
- Changing the public C ABI surface beyond what Phase 3 needs (`net_tls_verify_result`, `net_tls_peer_certificate`).
- Removing Zig fallback paths (the `-Dznet-link-rust=false` flag must still work).
- Windows-specific path testing in CI (we can fix Windows quirks if CI surfaces them, but the goal is cross-platform correctness, not Windows-specific cert tests).

---

## 3. The 6 Phases

### Phase 1 — Crate rename

- Move directory `z-net/rust_net/` → `z-net/engine/` (use `git mv` to preserve history).
- `engine/Cargo.toml`:
  - `name = "lean-net"` → `name = "z-net-engine"`
- `engine/src/lib.rs` (and any `use crate::` references): no internal name references, just verify nothing uses `lean_net` as a string.
- `build.zig`:
  - `--manifest-path "rust_net/Cargo.toml"` → `--manifest-path "engine/Cargo.toml"`
  - `b.path("rust_net/target/release/liblean_net.a")` → `b.path("engine/target/release/libz_net_engine.a")`
- `.gitignore`:
  - `rust_net/target/` → `engine/target/`

### Phase 2 — `std.net` → `std.Io.net` migration

**Why:** Zig 0.16.0 removed top-level `std.net`; networking moved to `std.Io.net`. `std.Io.net.IpAddress` is a union of `.ip4` / `.ip6` (not a single struct). `std.http.Server` was rewritten to take `*Reader, *Writer` (not a connection).

**Files touched:**

| File | Change |
|---|---|
| `src/z_monitoring/dashboard.zig` | Full rewrite of `start()`, `handleConnection()`, `handleRoot()`, `handleMetrics()`, `handleNotFound()` for new `std.Io.net.Server` + `std.http.Server(Reader, Writer)` APIs. Add `io_ctx: *std.Io` parameter to `start()`. |
| `src/z_monitoring/main.zig` | Instantiate `std.Io.Threaded` and pass `&threaded.io()` to `start()`. |
| `src/z_socket/socket.zig` | `const net = std.net;` → `const net = std.Io.net;`; `net.Address` → `net.IpAddress` (4 sites). `net.Address.Family` → `net.IpAddress.Family` (1 site). |
| `src/z_health/checker.zig` | Rename import; replace removed `net.tcpConnectToAddress` with a `Stream.connect`-based loop. Add `io_ctx: *std.Io` parameter. |
| `src/z_dns/dns.zig` (lines 151, 195) | `std.net.Address.parseIp4(host, port)` → `std.Io.net.IpAddress.parseIp4(host, port)`. |
| `src/z_proxy/tunnel.zig` (lines 13, 61) | Rename import; `net.Address.parseIp4` → `net.IpAddress.parseIp4`; return type of `resolveHost` from `net.Address` → `net.IpAddress`. |
| `src/z_proxy/socks5.zig` (line 8) | Delete unused `const net = std.net;`. |

**Verification:** `zig build` and `zig build test` both green.

### Phase 3 — Wire rustls verification through FFI

**Why:** `verifyCertificate()` returns `true` regardless of input. rustls already has a built-in WebPKI verifier. We just don't expose its result.

**FFI additions in `engine/src/lib.rs`:**

```rust
/// Rustls verification result
#[repr(C)]
pub enum TlsVerifyResult {
    Accepted = 0,
    Rejected = -1,
    /// No handshake has completed yet.
    NotEstablished = -2,
}

/// Returns rustls's WebPKI verification result after the handshake.
#[no_mangle]
pub extern "C" fn net_tls_verify_result(
    engine_handle: NetEngineHandle,
    tls_handle: TlsHandle,
) -> TlsVerifyResult;

/// Copies the peer certificate (first cert, DER-encoded) into the
/// caller-provided buffer. Returns bytes written, or -1 on error.
#[no_mangle]
pub extern "C" fn net_tls_peer_certificate(
    engine_handle: NetEngineHandle,
    tls_handle: TlsHandle,
    out: *mut u8,
    out_len: usize,
) -> i32;
```

**Zig side in `src/z_tls/tls.zig`:**

- Add matching `extern fn` declarations.
- `verifyCertificate()` → calls `net_tls_verify_result`; returns `true` only when result is `.Accepted`.
- `getHandshakeInfo()` → populates `peer_certificate` from `net_tls_peer_certificate` (still returns `error.NotImplemented` when state isn't `.Established` per the G1 decision from the plan discussion).

**Verification:** `zig build -Dznet-link-rust=true` green. A unit test that feeds a self-signed cert to `verifyCertificate()` should see `false` / `error.VerificationFailed`.

### Phase 4 — Silent stubs → explicit errors

| File:Line | Change |
|---|---|
| `src/z_tls/tls.zig:215-218` | `verifyCertificate()` becomes real in Phase 3. |
| `src/z_tls/tls.zig:251-254` | `CertificateValidator.validateChain()` → `return error.NotImplemented;` |
| `src/z_tls/tls.zig:195-209` | `getHandshakeInfo()` returns `error.NotImplemented` when state isn't `.Established` (G1). |
| `src/z_tls/tls.zig:243-245` | `TlsSessionCache.deinit()` gets a `// TODO` comment (true no-op until storage is added). |
| `src/z_tls/tls.zig:322-327` | `BACKEND = "stub"`, add `WIRED = false` companion flag with doc comment. |
| `src/z_proxy/pac.zig:61-62` | `catch {}` → `catch @panic("OOM in PAC condition stack");` |
| `src/z_proxy/pac.zig:82-106` | `evalCond()` returns `error.UnsupportedPacFunction` for unknown functions; `findProxyForURL` line 60 uses `try`. |
| `src/z_proxy/pac.zig:94-96` | `isInNet` body: `@panic("isInNet: network/mask args not yet supported in PAC engine");` |
| `engine/src/protocols/proxy.rs:87` | `None => return 0,` → `None => return -1,` |
| `engine/src/protocols/proxy.rs:165-170` | `if`-branch in `evaluate_minimal`: scan forward for the `return` statement on the next line; if absent, `return None`. |
| `engine/src/protocols/proxy.rs:60-63` | `znet_proxy_discover_env` returns `-2` on truncation (currently silently drops data). |

**Verification:** `zig build` + `cargo build --release` both green. No new warnings.

### Phase 5 — `unreachable` → propagated errors

10 sites across non-core code paths:

| File:Line | Current | After |
|---|---|---|
| `tests/cicd_integration.zig:43` | `allocator.alloc(...) catch unreachable;` | `try allocator.alloc(...)` (test fn becomes `!void`) |
| `examples/security_example.zig:221` | `catch unreachable` on `SecurityManager.init` | propagate via `try`, exit on error |
| `examples/dns_example.zig:291` | `catch unreachable` on `allocPrint` | propagate via `try` |
| `deployment/backup_recovery.zig:372, 379, 478` | `jobs.append(...) catch unreachable` | `pub fn listBackupJobs(...) !ArrayList(BackupJob)` |
| `deployment/rolling_updates.zig:227, 458, 530` | same pattern | `!T` returns, `try` at call sites |
| `deployment/automation_scripts.zig:204` | `keys.append(...) catch unreachable` | propagate |

**Verification:** `zig build test` still green (these are example/deployment code, not test functions, but ensure we don't break anything that does reference them).

### Phase 6 — Trim unused Rust imports

Current 4 warnings:
- `src/protocols/http/h2.rs:1` — `use h2;` (unused). **Remove** the file or stub it. Likely remove: `h2` is in Cargo.toml for the eventual HTTP/2 server work, but no FFI surface uses it. Keep the `h2` crate in Cargo.toml for the eventual Phase 7 wire-up, but mark the module as `#[allow(unused_imports)]` for now.
- `src/protocols/http3/mod.rs:2` — `use quinn_proto;` (unused). `quinn_proto` is used in `lib.rs` for `net_http3_*` (verified via the `net_http3_connect` / `net_http3_drive` / `net_http3_close` FFI surface). This import is just stale — remove it.
- `src/protocols/fetch/mod.rs:3` — `use std::os::raw::{c_char, c_int};` — `c_int` unused. `c_char` is used. Narrow the import.
- (Plus any new warnings surfaced by Phase 3 — fix as they appear.)

**Verification:** `cargo build --release` ends with zero warnings.

---

## 4. CI/CD changes

`z-net/.github/workflows/ci.yml` references `rust_net/`. After Phase 1:

```yaml
- name: Build Rust Backend
  run: |
    cd engine
    cargo build --release
```

**Add a new job for the FFI-linked build** (since `-Dznet-link-rust=true` isn't tested by CI today):

```yaml
- name: Zig Build (Rust FFI linked)
  run: zig build -Dznet-link-rust=true --summary all
```

**Note:** the build matrix tests 3 OSes (ubuntu, macos, windows). We don't expect Windows-specific changes in this PR, but the matrix gives us coverage.

---

## 5. Git workflow

### Branch
- Base: `master` (the most recent commit `3b31fd5 fix(dns,health)...` is the active dev line; `feat/compression-proxies-webtransport-auth` is a stale feature branch).
- New branch: `feat/refactor-zig-016-build-green-stubs-honest` (created with `git checkout -b` from `master`).

### Per-commit hygiene
- Never `git add .` or `git commit -a` blindly. Stage explicitly with `git add <path>`.
- Never `git clean -fdx` or `git reset --hard` (we're on a clean working tree, no need).
- The `.gitignore` already excludes `engine/target/` (after Phase 1's edit), `*.o`, `node_modules/`, etc.

### PR body
Use `gh pr create --fill`, then add a description that includes:
- Link to this plan file.
- List of phases completed.
- Test commands run and their results.
- Any follow-up phases for the next PR.

### Merge
Squash-merge after `gh pr checks --watch` reports green on all 3 OS matrix jobs.

---

## 6. Risk register

| Risk | Likelihood | Mitigation |
|---|---|---|
| Phase 2 dashboard rewrite doesn't match the HTTP API contract | Medium | Write a test that hits `/` and `/api/metrics` after `db_server.start()`. |
| Phase 3 FFI for `peer_certificate` is unbounded | Low | Cap output at 4 KiB (typical cert is < 2 KiB); return -1 for oversized chains. |
| Phase 5 deployment function signatures break callers in the same file | Medium | Each file is self-contained; verify by searching before changing signature. |
| CI's `dtolnay/rust-toolchain@stable` and `mlugg/setup-zig@v2` have moved on by the time of merge | Low | Pin versions in the workflow. |
| Windows-specific path or socket API differs | Low | We can iterate on the Windows job if it fails. |
| `engine/target/` accidentally committed | Low | `.gitignore` updated in Phase 1. Verify with `git status` before `git add`. |

---

## 7. Definition of done

- [ ] `zig build` → exit code 0, no errors.
- [ ] `zig build test` → all tests pass.
- [ ] `zig build -Dznet-link-rust=true` → exit code 0, no errors.
- [ ] `cargo build --release --manifest-path engine/Cargo.toml` → exit code 0, no warnings.
- [ ] CI matrix green on ubuntu, macos, windows.
- [ ] No `std.net` references remain (grep confirms).
- [ ] No `return true` stub in `verifyCertificate` / `validateChain`.
- [ ] No `catch {}` silent allocation failure in `pac.zig`.
- [ ] No `unreachable` in examples/, tests/, deployment/.
- [ ] `engine/Cargo.toml` has `name = "z-net-engine"`.
- [ ] `build.zig` references `engine/`, not `rust_net/`.
- [ ] `.gitignore` excludes `engine/target/`.
- [ ] `git status` clean, branch pushed, PR open, CI green, squash-merged to `master`.

---

## 8. Follow-up PRs (not this one)

- **PR-2:** Migrate `z_quic` to FFI wrappers over `net_http3_*`.
- **PR-3:** Migrate `z_socket` raw TCP/UDP to FFI over `net_engine_create`/`net_connect`/`net_poll`.
- **PR-4:** Migrate `z_monitoring` to FFI over `net_get_metrics`.
- **PR-5:** Migrate `z_body_ring.zig` to FFI over `net_body_ring_*`.
- **PR-6:** Flip `build.zig` `link_rust` default to `true`; remove the Zig fallback paths.
- **PR-7:** Trim the Zig `z_proxy` PAC engine (keep only the engine role) once the FFI surface in `z-net-engine` covers it; or expand `z-net-engine`'s PAC to be the single source of truth.
- **PR-8:** Add SOCKS5 server support to `z-net-engine` (currently no FFI surface for incoming SOCKS5).
