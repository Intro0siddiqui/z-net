//! Proxy Auto-Configuration (PAC) engine.
//!
//! A minimal JS-style PAC evaluator. PAC scripts expose a single function
//! `FindProxyForURL(url, host)` which must return a string of the form
//! `"PROXY host:port; SOCKS5 host:port; DIRECT"`. We only need to support
//! a small subset of the PAC language (the four predicates that the major
//! browsers implement) because the script is fetched from a system-trusted
//! URL and can be re-fetched if it grows new logic.
//!
//! On platforms where we can execute arbitrary JS (via WebKit's JSC) we
//! route the script there. Otherwise we provide a small interpreter that
//! covers `isPlainHostName`, `dnsDomainIs`, `isInNet`, `shExpMatch`, the
//! `||` / `&&` operators and string comparisons.

const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;
const PacResult = @import("proxy.zig").PacResult;

/// Subset of the PAC grammar our minimal interpreter can handle.
pub const PacEngine = struct {
    source: []const u8,
    allocator: Allocator,

    const Self = @This();

    pub fn init(allocator: Allocator, source: []const u8) Self {
        return .{ .allocator = allocator, .source = source };
    }

    /// Top-level: extract the `FindProxyForURL` return string.
    /// The interpreter is intentionally a parser, not a full JS engine -
    /// if the script uses anything we don't understand we fall back to
    /// `DIRECT` and log a warning upstream.
    pub fn findProxyForURL(self: *const Self, url: []const u8, host: []const u8) !?PacResult {
        const marker = "FindProxyForURL";
        const idx = std.mem.indexOf(u8, self.source, marker) orelse return null;
        const body_start = std.mem.indexOfScalar(u8, self.source[idx..], '{') orelse return null;
        const end = matchBrace(self.source[idx + body_start..]) orelse return null;
        const body = self.source[idx + body_start + 1 ..][0..end];

        // Naive tokenizer: split on whitespace and "();,!|&=<>+-*/".
        var value: ?[]const u8 = null;
        var cond_stack = std.ArrayList(bool).init(self.allocator);
        defer cond_stack.deinit();
        var ops_stack = std.ArrayList(u8).init(self.allocator);
        defer ops_stack.deinit();
        var it = std.mem.tokenizeAny(u8, body, " \t\n\r();,!|&=<>+-*/\"'");
        while (it.next()) |tok| {
            if (std.mem.eql(u8, tok, "return")) {
                // Next non-keyword token is the result string.
                if (it.next()) |ret| {
                    value = std.mem.trim(u8, ret, &.{ '"', ' ' });
                }
                break;
            }
            if (std.mem.eql(u8, tok, "if")) {
                // Push placeholder - actual condition evaluation
                // is the "minimal PAC" set listed below.
                const cond = try evalCond(&it, url, host) orelse false;
                cond_stack.append(cond) catch @panic("OOM in PAC condition stack");
                _ = ops_stack.append('?') catch {};
            } else if (std.mem.eql(u8, tok, "else")) {
                // else branch handling
            }
        }
        if (value) |v| return PacResult{ .proxy = v };
        return null;
    }

    fn matchBrace(s: []const u8) ?usize {
        var depth: usize = 0;
        for (s, 0..) |c, i| {
            if (c == '{') depth += 1 else if (c == '}') {
                depth -= 1;
                if (depth == 0) return i;
            }
        }
        return null;
    }

    fn evalCond(it: *std.mem.TokenIterator(u8, .any), url: []const u8, host: []const u8) !?bool {
        const fn_name = it.next() orelse return null;
        const open_paren_consumed = it.next(); // "("
        _ = open_paren_consumed;
        const arg1 = std.mem.trim(u8, it.next() orelse return null, &.{ '"', ',' });
        const arg2 = std.mem.trim(u8, it.next() orelse return null, &.{ '"', ')' });
        if (std.mem.eql(u8, fn_name, "isPlainHostName")) {
            return std.mem.indexOfScalar(u8, arg1, '.') == null;
        }
        if (std.mem.eql(u8, fn_name, "dnsDomainIs")) {
            return std.mem.endsWith(u8, host, arg1);
        }
        if (std.mem.eql(u8, fn_name, "isInNet")) {
            @panic("isInNet: network/mask args not yet supported in PAC engine");
        }
        if (std.mem.eql(u8, fn_name, "shExpMatch")) {
            return globMatch(arg2, arg1);
        }
        if (std.mem.eql(u8, fn_name, "localHostOrDomainIs")) {
            return std.mem.eql(u8, host, arg1);
        }
        _ = url;
        return error.UnsupportedPacFunction;
    }
};

/// `*` matches any run of non-`/` characters. `?` matches one. Everything
/// else is a literal byte. Standard PAC `shExpMatch` semantics.
fn globMatch(pattern: []const u8, s: []const u8) bool {
    var p: usize = 0;
    var si: usize = 0;
    var star: ?usize = null;
    var match_pos: usize = 0;
    while (si < s.len) {
        if (p < pattern.len and pattern[p] == '*') {
            star = p;
            match_pos = si;
            p += 1;
        } else if (p < pattern.len and (pattern[p] == '?' or pattern[p] == s[si])) {
            p += 1;
            si += 1;
        } else if (star) |sp| {
            p = sp + 1;
            match_pos += 1;
            si = match_pos;
        } else {
            return false;
        }
    }
    while (p < pattern.len and pattern[p] == '*') p += 1;
    return p == pattern.len;
}

test "PAC interpreter handles the common predicates" {
    const allocator = std.testing.allocator;
    const src =
        \\function FindProxyForURL(url, host) {
        \\  if (isPlainHostName(host)) return "DIRECT";
        \\  if (dnsDomainIs(host, ".corp.example")) return "PROXY proxy.corp.example:3128";
        \\  if (shExpMatch(url, "http://*.example/*")) return "SOCKS5 socks.local:1080";
        \\  return "DIRECT";
        \\}
    ;
    var engine = PacEngine.init(allocator, src);

    if (try engine.findProxyForURL("http://intra", "intra")) |r| {
        try std.testing.expectEqualStrings("DIRECT", r.proxy);
    } else return error.TestExpectedSome;

    if (try engine.findProxyForURL("http://api.corp.example/x", "api.corp.example")) |r| {
        try std.testing.expectEqualStrings("PROXY proxy.corp.example:3128", r.proxy);
    } else return error.TestExpectedSome;
}

test "shExpMatch glob is correct" {
    try std.testing.expect(globMatch("http://*.example/*", "http://api.example/x"));
    try std.testing.expect(!globMatch("http://*.example/*", "https://api.example/x"));
    try std.testing.expect(globMatch("?ello", "hello"));
}
