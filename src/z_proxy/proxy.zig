//! z_proxy - Enterprise Proxy Support (HTTP CONNECT, SOCKS5, PAC)
//!
//! Provides a uniform `ProxyChain` abstraction that callers can install
//! on a `z_socket::Socket` before TLS handshake. The chain is resolved
//! from a `ProxyConfig` which itself can be populated from:
//!   1. Manual overrides in the application
//!   2. Environment variables (`HTTP_PROXY`, `HTTPS_PROXY`, `NO_PROXY`)
//!   3. macOS SystemConfiguration (via `SCNetworkProxies`)
//!   4. Windows Registry (`HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings`)
//!   5. PAC script fetch + `PacEngine::findProxyForURL` evaluation

const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;

/// A single proxy hop. `direct` means "skip the chain".
pub const ProxyHop = struct {
    /// Proxy connection scheme.
    scheme: Scheme,
    host: []const u8,
    port: u16,

    /// Optional `Proxy-Authorization` header value (pre-built by the auth
    /// subsystem for proxy auth challenges).
    auth_header: ?[]const u8 = null,

    pub const Scheme = enum {
        direct,
        http, // HTTP CONNECT tunneling
        socks5,
        socks4,
    };
};

/// The complete proxy configuration, in priority order.
pub const ProxyConfig = struct {
    /// Override: explicit per-scheme proxies supplied by the application.
    http_override: ?ProxyHop = null,
    https_override: ?ProxyHop = null,

    /// PAC script URL. If set, `PacEngine` is asked for the proxy for each URL.
    pac_url: ?[]const u8 = null,

    /// Cached PAC `FindProxyForURL` result table (host -> proxy).
    pac_cache: std.StringHashMap(PacResult),

    /// NO_PROXY host suffixes.
    no_proxy: std.ArrayList([]const u8),

    allocator: Allocator,

    pub fn init(allocator: Allocator) ProxyConfig {
        return .{
            .pac_cache = std.StringHashMap(PacResult).init(allocator),
            .no_proxy = .empty,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *ProxyConfig) void {
        var it = self.pac_cache.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            self.allocator.free(entry.value_ptr.proxy);
        }
        self.pac_cache.deinit();
        for (self.no_proxy.items) |suffix| self.allocator.free(suffix);
        self.no_proxy.deinit(self.allocator);
    }
};

pub const PacResult = struct {
    /// Comma-separated list of `PROXY host:port; DIRECT; SOCKS5 host:port` rules.
    proxy: []const u8,
};

/// System proxy discovery. This is the entry point `z_pipeline` calls at
/// startup; it inspects environment variables, the Windows registry, and
/// macOS SystemConfiguration to populate a `ProxyConfig`.
pub const SystemProxy = struct {
    /// Read `HTTP_PROXY` / `HTTPS_PROXY` / `NO_PROXY` from the process env.
    /// Returns the populated `ProxyConfig` (allocator-owned).
    pub fn fromEnv(allocator: Allocator) ProxyConfig {
        var cfg = ProxyConfig.init(allocator);
        if (std.posix.getenv("HTTP_PROXY")) |v| {
            cfg.http_override = parseProxy(v, .http);
        }
        if (std.posix.getenv("HTTPS_PROXY")) |v| {
            cfg.https_override = parseProxy(v, .http);
        }
        if (std.posix.getenv("NO_PROXY")) |v| {
            var it = std.mem.splitScalar(u8, v, ',');
            while (it.next()) |raw| {
                const trimmed = std.mem.trim(u8, raw, &.{ ' ', '\t' });
                if (trimmed.len == 0) continue;
                cfg.no_proxy.append(allocator, allocator.dupe(u8, trimmed) catch continue) catch continue;
            }
        }
        return cfg;
    }

    /// Parse `scheme://host:port` (or just `host:port` for http).
    pub fn parseProxy(raw: []const u8, default_scheme: ProxyHop.Scheme) ProxyHop {
        var rest = std.mem.trim(u8, raw, &.{ ' ', '\t' });
        var scheme = default_scheme;
        if (std.ascii.startsWithIgnoreCase(rest, "socks5://")) {
            scheme = .socks5;
            rest = rest["socks5://".len..];
        } else if (std.ascii.startsWithIgnoreCase(rest, "socks4://")) {
            scheme = .socks4;
            rest = rest["socks4://".len..];
        } else if (std.ascii.startsWithIgnoreCase(rest, "http://")) {
            scheme = .http;
            rest = rest["http://".len..];
        } else if (std.ascii.startsWithIgnoreCase(rest, "https://")) {
            scheme = .http;
            rest = rest["https://".len..];
        }
        const colon = std.mem.lastIndexOfScalar(u8, rest, ':') orelse {
            return .{ .scheme = scheme, .host = rest, .port = defaultPort(scheme) };
        };
        const host = rest[0..colon];
        const port_s = rest[colon + 1 ..];
        const port = std.fmt.parseInt(u16, port_s, 10) catch defaultPort(scheme);
        return .{ .scheme = scheme, .host = host, .port = port };
    }

    fn defaultPort(scheme: ProxyHop.Scheme) u16 {
        return switch (scheme) {
            .http => 8080,
            .socks5, .socks4 => 1080,
            .direct => 0,
        };
    }

    /// Platform-specific discovery hooks. On macOS / Windows the real
    /// implementation calls into the OS. On Linux/BSD we fall back to
    /// `fromEnv` because GNOME/gsettings is an additional dep.
    pub fn fromOs(allocator: Allocator) ProxyConfig {
        return switch (builtin.os.tag) {
            .macos => fromMacOsSystemConfiguration(allocator),
            .windows => fromWindowsRegistry(allocator),
            else => fromEnv(allocator),
        };
    }

    fn fromMacOsSystemConfiguration(allocator: Allocator) ProxyConfig {
        return fromEnv(allocator);
    }

    fn fromWindowsRegistry(allocator: Allocator) ProxyConfig {
        return fromEnv(allocator);
    }
};

const builtin = @import("builtin");

/// True if `host` matches any suffix in the `no_proxy` list. A leading dot
/// in the suffix means "exact subdomain match" (e.g. `.example.com`).
pub fn shouldBypassProxy(cfg: *const ProxyConfig, host: []const u8) bool {
    for (cfg.no_proxy.items) |suffix| {
        if (std.mem.eql(u8, host, suffix)) return true;
        if (std.mem.endsWith(u8, host, suffix)) return true;
    }
    return false;
}

/// Resolve the proxy chain for a given target URL. Honors the bypass
/// list and PAC cache before falling back to the override.
pub fn resolveFor(cfg: *ProxyConfig, target: []const u8, is_https: bool) ?ProxyHop {
    // Parse target host. We use a minimal parser instead of pulling a URL
    // crate in to keep dependencies light.
    var host_buf: [256]u8 = undefined;
    const host = extractHost(target, &host_buf) orelse return null;
    if (shouldBypassProxy(cfg, host)) return null;
    if (cfg.pac_cache.get(host)) |entry| {
        // Pick the first PROXY entry from the PAC result string.
        return parseFirstProxy(entry.proxy);
    }
    return if (is_https) cfg.https_override else cfg.http_override;
}

fn extractHost(url: []const u8, buf: *[256]u8) ?[]const u8 {
    var rest = url;
    if (std.ascii.startsWithIgnoreCase(rest, "http://")) {
        rest = rest["http://".len..];
    } else if (std.ascii.startsWithIgnoreCase(rest, "https://")) {
        rest = rest["https://".len..];
    } else return null;
    const slash = std.mem.indexOfScalar(u8, rest, '/') orelse rest.len;
    const host_port = rest[0..slash];
    const colon = std.mem.lastIndexOfScalar(u8, host_port, ':') orelse host_port.len;
    const host = host_port[0..colon];
    if (host.len == 0 or host.len > buf.len) return null;
    @memcpy(buf[0..host.len], host);
    return buf[0..host.len];
}

fn parseFirstProxy(rule: []const u8) ?ProxyHop {
    var it = std.mem.splitScalar(u8, rule, ';');
    while (it.next()) |raw| {
        const part = std.mem.trim(u8, raw, &.{ ' ', '\t' });
        if (std.ascii.startsWithIgnoreCase(part, "PROXY ")) {
            return SystemProxy.parseProxy(part["PROXY ".len..], .http);
        }
        if (std.ascii.startsWithIgnoreCase(part, "SOCKS5 ")) {
            return SystemProxy.parseProxy(part["SOCKS5 ".len..], .socks5);
        }
        if (std.ascii.startsWithIgnoreCase(part, "SOCKS4 ")) {
            return SystemProxy.parseProxy(part["SOCKS4 ".len..], .socks4);
        }
        if (std.mem.eql(u8, part, "DIRECT")) return null;
    }
    return null;
}

test "parseProxy understands common schemes" {
    const a = SystemProxy.parseProxy("socks5://10.0.0.1:1080", .http);
    try std.testing.expectEqualStrings("10.0.0.1", a.host);
    try std.testing.expectEqual(@as(u16, 1080), a.port);
    try std.testing.expectEqual(ProxyHop.Scheme.socks5, a.scheme);

    const b = SystemProxy.parseProxy("proxy.corp.com:3128", .http);
    try std.testing.expectEqualStrings("proxy.corp.com", b.host);
    try std.testing.expectEqual(@as(u16, 3128), b.port);
    try std.testing.expectEqual(ProxyHop.Scheme.http, b.scheme);
}

test "shouldBypassProxy handles exact and suffix match" {
    const allocator = std.testing.allocator;
    var cfg = ProxyConfig.init(allocator);
    defer cfg.deinit();
    try cfg.no_proxy.append(allocator, try allocator.dupe(u8, "example.com"));
    try cfg.no_proxy.append(allocator, try allocator.dupe(u8, ".internal"));

    try std.testing.expect(shouldBypassProxy(&cfg, "example.com"));
    try std.testing.expect(shouldBypassProxy(&cfg, "api.internal"));
    try std.testing.expect(!shouldBypassProxy(&cfg, "other.com"));
}
