//! Proxy Auto-Configuration (PAC) engine.
//!
//! Evaluates the subset of JavaScript that PAC scripts use in practice: a
//! `FindProxyForURL(url, host)` function containing `if`/`else` statements,
//! `var` bindings, boolean expressions and string comparisons.
//!
//! Supported PAC predicates are `isPlainHostName`, `dnsDomainIs`,
//! `localHostOrDomainIs`, `dnsDomainLevels`, `isInNet` (IPv4 literals only)
//! and `shExpMatch`. Comments and nested blocks are handled correctly.
//!
//! Unsupported functions (for example `dnsResolve`, `dateRange` or
//! `myIpAddress`) return `error.UnsupportedPacFunction` when they are
//! actually evaluated, so callers can fall back to `DIRECT`. Branches that
//! are not taken are parsed but never evaluated. Returned strings are slices
//! into `source` and remain valid for the lifetime of the engine.

const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;
const PacResult = @import("proxy.zig").PacResult;

const Tag = enum {
    ident,
    string,
    number,
    lparen,
    rparen,
    lbrace,
    rbrace,
    comma,
    semicolon,
    assign,
    eq,
    neq,
    bang,
    and_and,
    or_or,
    eof,
};

const Token = struct {
    tag: Tag,
    text: []const u8,
};

pub const PacError = error{
    SyntaxError,
    TypeError,
    UnsupportedPacFunction,
    UnknownIdentifier,
} || Allocator.Error;

const Value = union(enum) {
    string: []const u8,
    number: i64,
    boolean: bool,
    null_value,
};

const FunctionDef = struct {
    params_start: usize,
    params_end: usize,
    body_start: usize,
    body_end: usize,
};

pub const PacEngine = struct {
    source: []const u8,
    allocator: Allocator,

    const Self = @This();

    pub fn init(allocator: Allocator, source: []const u8) Self {
        return .{ .allocator = allocator, .source = source };
    }

    pub fn findProxyForURL(self: *const Self, url: []const u8, host: []const u8) PacError!?PacResult {
        var tokens: std.ArrayList(Token) = .empty;
        defer tokens.deinit(self.allocator);
        try tokenize(self.allocator, self.source, &tokens);

        var interp = Interpreter{
            .tokens = tokens.items,
            .env = std.StringHashMap(Value).init(self.allocator),
        };
        defer interp.deinit();

        const function_def = findFunction(tokens.items) orelse return null;
        try interp.bindParameters(function_def, url, host);
        interp.pos = function_def.body_start;

        const returned = try interp.execStatements(function_def.body_end, true);
        if (returned) |proxy| return PacResult{ .proxy = proxy };
        return null;
    }
};

const Interpreter = struct {
    tokens: []const Token,
    pos: usize = 0,
    env: std.StringHashMap(Value),

    fn deinit(self: *Interpreter) void {
        self.env.deinit();
    }

    fn bindParameters(self: *Interpreter, def: FunctionDef, url: []const u8, host: []const u8) PacError!void {
        var arg_index: usize = 0;
        var i = def.params_start;
        while (i < def.params_end) : (i += 1) {
            if (self.tokens[i].tag != .ident) continue;
            const value: Value = switch (arg_index) {
                0 => .{ .string = url },
                1 => .{ .string = host },
                else => .null_value,
            };
            try self.env.put(self.tokens[i].text, value);
            arg_index += 1;
        }
    }

    fn execStatements(self: *Interpreter, end: usize, live: bool) PacError!?[]const u8 {
        while (self.pos < end) {
            if (self.acceptTag(.semicolon)) continue;
            if (self.peek().tag == .rbrace) break;
            if (try self.execStatement(live)) |ret| return ret;
        }
        return null;
    }

    fn execStatementsUntilBrace(self: *Interpreter, live: bool) PacError!?[]const u8 {
        while (self.peek().tag != .rbrace) {
            if (self.peek().tag == .eof) return error.SyntaxError;
            if (self.acceptTag(.semicolon)) continue;
            if (try self.execStatement(live)) |ret| return ret;
        }
        return null;
    }

    fn execStatement(self: *Interpreter, live: bool) PacError!?[]const u8 {
        const tok = self.peek();
        if (tok.tag == .lbrace) {
            _ = self.advance();
            const returned = try self.execStatementsUntilBrace(live);
            if (!self.acceptTag(.rbrace)) return error.SyntaxError;
            return returned;
        }

        if (tok.tag == .ident) {
            if (mem.eql(u8, tok.text, "if")) return self.execIf(live);
            if (mem.eql(u8, tok.text, "return")) return self.execReturn(live);
            if (mem.eql(u8, tok.text, "var")) return self.execVar(live);
            if (mem.eql(u8, tok.text, "else")) return error.SyntaxError;
            if (mem.eql(u8, tok.text, "function")) {
                try self.skipFunction();
                return null;
            }
            if (self.peekAt(1).tag == .assign) {
                const name = tok.text;
                _ = self.advance();
                _ = self.advance();
                const value = try self.evalExpr(live);
                try self.optionalSemicolon();
                if (live) try self.env.put(name, value);
                return null;
            }
        }

        _ = try self.evalExpr(live);
        try self.optionalSemicolon();
        return null;
    }

    fn execIf(self: *Interpreter, live: bool) PacError!?[]const u8 {
        _ = self.advance(); // if
        try self.expectTag(.lparen);
        const condition = try self.evalExpr(live);
        try self.expectTag(.rparen);

        const branch = truthy(condition);
        const then_result = try self.execStatement(live and branch);

        var else_result: ?[]const u8 = null;
        if (self.acceptKeyword("else")) {
            else_result = try self.execStatement(live and !branch);
        }

        if (then_result) |ret| return ret;
        return else_result;
    }

    fn execReturn(self: *Interpreter, live: bool) PacError!?[]const u8 {
        _ = self.advance(); // return
        const value = try self.evalExpr(live);
        try self.optionalSemicolon();
        if (!live) return null;
        return switch (value) {
            .string => |s| s,
            else => error.TypeError,
        };
    }

    fn execVar(self: *Interpreter, live: bool) PacError!?[]const u8 {
        _ = self.advance(); // var
        const name = self.advance();
        if (name.tag != .ident) return error.SyntaxError;

        var value: Value = .null_value;
        if (self.acceptTag(.assign)) value = try self.evalExpr(live);
        try self.optionalSemicolon();

        if (live) try self.env.put(name.text, value);
        return null;
    }

    fn skipFunction(self: *Interpreter) PacError!void {
        _ = self.advance(); // function
        if (self.peek().tag == .ident) _ = self.advance();

        if (self.acceptTag(.lparen)) {
            var parens: usize = 1;
            while (parens > 0) {
                const tok = self.advance();
                if (tok.tag == .eof) return error.SyntaxError;
                if (tok.tag == .lparen) parens += 1;
                if (tok.tag == .rparen) parens -= 1;
            }
        }

        if (self.acceptTag(.lbrace)) {
            var braces: usize = 1;
            while (braces > 0) {
                const tok = self.advance();
                if (tok.tag == .eof) return error.SyntaxError;
                if (tok.tag == .lbrace) braces += 1;
                if (tok.tag == .rbrace) braces -= 1;
            }
        }
    }

    fn evalExpr(self: *Interpreter, live: bool) PacError!Value {
        return self.evalOr(live);
    }

    fn evalOr(self: *Interpreter, live: bool) PacError!Value {
        var lhs = try self.evalAnd(live);
        while (self.acceptTag(.or_or)) {
            const rhs = try self.evalAnd(live and !truthy(lhs));
            if (!truthy(lhs)) lhs = rhs;
        }
        return lhs;
    }

    fn evalAnd(self: *Interpreter, live: bool) PacError!Value {
        var lhs = try self.evalEquality(live);
        while (self.acceptTag(.and_and)) {
            const rhs = try self.evalEquality(live and truthy(lhs));
            if (truthy(lhs)) lhs = rhs;
        }
        return lhs;
    }

    fn evalEquality(self: *Interpreter, live: bool) PacError!Value {
        var lhs = try self.evalUnary(live);
        while (true) {
            const tag = self.peek().tag;
            if (tag != .eq and tag != .neq) break;
            _ = self.advance();
            const rhs = try self.evalUnary(live);
            const equal = valueEquals(lhs, rhs);
            lhs = .{ .boolean = if (tag == .eq) equal else !equal };
        }
        return lhs;
    }

    fn evalUnary(self: *Interpreter, live: bool) PacError!Value {
        if (self.acceptTag(.bang)) {
            const value = try self.evalUnary(live);
            return .{ .boolean = !truthy(value) };
        }
        return self.evalPrimary(live);
    }

    fn evalPrimary(self: *Interpreter, live: bool) PacError!Value {
        const tok = self.advance();
        switch (tok.tag) {
            .string => return .{ .string = tok.text },
            .number => return .{
                .number = std.fmt.parseInt(i64, tok.text, 10) catch return error.SyntaxError,
            },
            .lparen => {
                const value = try self.evalExpr(live);
                try self.expectTag(.rparen);
                return value;
            },
            .ident => {
                if (mem.eql(u8, tok.text, "true")) return .{ .boolean = true };
                if (mem.eql(u8, tok.text, "false")) return .{ .boolean = false };
                if (mem.eql(u8, tok.text, "null")) return .null_value;

                if (self.acceptTag(.lparen)) {
                    var args: [8]Value = undefined;
                    var argc: usize = 0;
                    if (!self.acceptTag(.rparen)) {
                        while (true) {
                            if (argc == args.len) return error.SyntaxError;
                            args[argc] = try self.evalExpr(live);
                            argc += 1;
                            if (self.acceptTag(.comma)) continue;
                            try self.expectTag(.rparen);
                            break;
                        }
                    }
                    if (!live) return .null_value;
                    return callBuiltin(tok.text, args[0..argc]);
                }

                if (!live) return .null_value;
                if (self.env.get(tok.text)) |value| return value;
                return error.UnknownIdentifier;
            },
            else => return error.SyntaxError,
        }
    }

    fn peek(self: *const Interpreter) Token {
        return self.peekAt(0);
    }

    fn peekAt(self: *const Interpreter, offset: usize) Token {
        const index = self.pos + offset;
        if (index >= self.tokens.len) return .{ .tag = .eof, .text = "" };
        return self.tokens[index];
    }

    fn advance(self: *Interpreter) Token {
        const tok = self.peek();
        if (self.pos < self.tokens.len) self.pos += 1;
        return tok;
    }

    fn acceptTag(self: *Interpreter, tag: Tag) bool {
        if (self.peek().tag != tag) return false;
        _ = self.advance();
        return true;
    }

    fn acceptKeyword(self: *Interpreter, word: []const u8) bool {
        if (!isIdent(self.peek(), word)) return false;
        _ = self.advance();
        return true;
    }

    fn expectTag(self: *Interpreter, tag: Tag) PacError!void {
        if (!self.acceptTag(tag)) return error.SyntaxError;
    }

    fn optionalSemicolon(self: *Interpreter) PacError!void {
        if (self.acceptTag(.semicolon)) return;
        if (self.peek().tag == .rbrace or self.peek().tag == .eof) return;
        return error.SyntaxError;
    }
};

fn tokenize(allocator: Allocator, source: []const u8, out: *std.ArrayList(Token)) PacError!void {
    var i: usize = 0;
    while (i < source.len) {
        const c = source[i];

        if (std.ascii.isWhitespace(c)) {
            i += 1;
            continue;
        }

        if (c == '/' and i + 1 < source.len) {
            if (source[i + 1] == '/') {
                i += 2;
                while (i < source.len and source[i] != '\n') i += 1;
                continue;
            }
            if (source[i + 1] == '*') {
                i += 2;
                while (i + 1 < source.len and !(source[i] == '*' and source[i + 1] == '/')) i += 1;
                if (i + 1 >= source.len) return error.SyntaxError;
                i += 2;
                continue;
            }
        }

        if (c == '"' or c == '\'') {
            const start = i + 1;
            i += 1;
            while (i < source.len and source[i] != c) {
                if (source[i] == '\\' and i + 1 < source.len) i += 1;
                i += 1;
            }
            if (i >= source.len) return error.SyntaxError;
            try out.append(allocator, .{ .tag = .string, .text = source[start..i] });
            i += 1;
            continue;
        }

        if (std.ascii.isAlphabetic(c) or c == '_' or c == '$') {
            const start = i;
            i += 1;
            while (i < source.len and
                (std.ascii.isAlphanumeric(source[i]) or source[i] == '_' or source[i] == '$'))
            {
                i += 1;
            }
            try out.append(allocator, .{ .tag = .ident, .text = source[start..i] });
            continue;
        }

        if (std.ascii.isDigit(c)) {
            const start = i;
            i += 1;
            while (i < source.len and std.ascii.isDigit(source[i])) i += 1;
            try out.append(allocator, .{ .tag = .number, .text = source[start..i] });
            continue;
        }

        if (i + 1 < source.len) {
            const two = source[i .. i + 2];
            const two_tag: ?Tag = if (mem.eql(u8, two, "||"))
                .or_or
            else if (mem.eql(u8, two, "&&"))
                .and_and
            else if (mem.eql(u8, two, "=="))
                .eq
            else if (mem.eql(u8, two, "!="))
                .neq
            else
                null;
            if (two_tag) |tag| {
                try out.append(allocator, .{ .tag = tag, .text = two });
                i += 2;
                continue;
            }
        }

        const one_tag: ?Tag = switch (c) {
            '(' => .lparen,
            ')' => .rparen,
            '{' => .lbrace,
            '}' => .rbrace,
            ',' => .comma,
            ';' => .semicolon,
            '=' => .assign,
            '!' => .bang,
            else => null,
        };
        if (one_tag) |tag| {
            try out.append(allocator, .{ .tag = tag, .text = source[i .. i + 1] });
            i += 1;
            continue;
        }

        return error.SyntaxError;
    }

    try out.append(allocator, .{ .tag = .eof, .text = "" });
}

fn findFunction(tokens: []const Token) ?FunctionDef {
    var i: usize = 0;
    while (i + 2 < tokens.len) : (i += 1) {
        if (!isIdent(tokens[i], "function")) continue;
        if (!isIdent(tokens[i + 1], "FindProxyForURL")) continue;
        if (tokens[i + 2].tag != .lparen) continue;

        const params_start = i + 3;
        var j = params_start;
        var parens: usize = 1;
        while (j < tokens.len and parens > 0) : (j += 1) {
            switch (tokens[j].tag) {
                .lparen => parens += 1,
                .rparen => parens -= 1,
                else => {},
            }
        }
        if (parens != 0 or j >= tokens.len) return null;

        const params_end = j - 1;
        if (tokens[j].tag != .lbrace) return null;

        const body_start = j + 1;
        var k = body_start;
        var braces: usize = 1;
        while (k < tokens.len) : (k += 1) {
            switch (tokens[k].tag) {
                .lbrace => braces += 1,
                .rbrace => {
                    braces -= 1;
                    if (braces == 0) {
                        return .{
                            .params_start = params_start,
                            .params_end = params_end,
                            .body_start = body_start,
                            .body_end = k,
                        };
                    }
                },
                else => {},
            }
        }
        return null;
    }
    return null;
}

fn isIdent(token: Token, text: []const u8) bool {
    return token.tag == .ident and mem.eql(u8, token.text, text);
}

fn truthy(value: Value) bool {
    return switch (value) {
        .string => |s| s.len != 0,
        .number => |n| n != 0,
        .boolean => |b| b,
        .null_value => false,
    };
}

fn valueEquals(a: Value, b: Value) bool {
    return switch (a) {
        .string => |s| switch (b) {
            .string => |t| mem.eql(u8, s, t),
            else => false,
        },
        .number => |n| switch (b) {
            .number => |m| n == m,
            else => false,
        },
        .boolean => |x| switch (b) {
            .boolean => |y| x == y,
            else => false,
        },
        .null_value => switch (b) {
            .null_value => true,
            else => false,
        },
    };
}

fn stringArg(args: []const Value, index: usize) ?[]const u8 {
    if (index >= args.len) return null;
    return switch (args[index]) {
        .string => |s| s,
        else => null,
    };
}

fn callBuiltin(name: []const u8, args: []const Value) PacError!Value {
    if (mem.eql(u8, name, "isPlainHostName")) {
        const host = stringArg(args, 0) orelse return error.TypeError;
        return .{ .boolean = mem.indexOfScalar(u8, host, '.') == null };
    }

    if (mem.eql(u8, name, "dnsDomainIs")) {
        const host = stringArg(args, 0) orelse return error.TypeError;
        const domain = stringArg(args, 1) orelse return error.TypeError;
        return .{ .boolean = std.ascii.endsWithIgnoreCase(host, domain) };
    }

    if (mem.eql(u8, name, "localHostOrDomainIs")) {
        const host = stringArg(args, 0) orelse return error.TypeError;
        const hostdom = stringArg(args, 1) orelse return error.TypeError;
        if (std.ascii.eqlIgnoreCase(host, hostdom)) return .{ .boolean = true };
        if (mem.indexOfScalar(u8, host, '.') != null) return .{ .boolean = false };
        return .{ .boolean = hostdom.len > host.len and
            std.ascii.startsWithIgnoreCase(hostdom, host) and
            hostdom[host.len] == '.' };
    }

    if (mem.eql(u8, name, "dnsDomainLevels")) {
        const host = stringArg(args, 0) orelse return error.TypeError;
        var levels: i64 = 0;
        for (host) |c| {
            if (c == '.') levels += 1;
        }
        return .{ .number = levels };
    }

    if (mem.eql(u8, name, "isInNet")) {
        const host = stringArg(args, 0) orelse return error.TypeError;
        const pattern = stringArg(args, 1) orelse return error.TypeError;
        const mask = stringArg(args, 2) orelse return error.TypeError;

        const host_ip = parseIpv4(host) orelse return .{ .boolean = false };
        const net_ip = parseIpv4(pattern) orelse return .{ .boolean = false };
        const mask_ip = parseIpv4(mask) orelse return .{ .boolean = false };
        return .{ .boolean = (host_ip & mask_ip) == (net_ip & mask_ip) };
    }

    if (mem.eql(u8, name, "shExpMatch")) {
        const value = stringArg(args, 0) orelse return error.TypeError;
        const pattern = stringArg(args, 1) orelse return error.TypeError;
        return .{ .boolean = globMatch(pattern, value) };
    }

    return error.UnsupportedPacFunction;
}

fn parseIpv4(text: []const u8) ?u32 {
    var octets: [4]u8 = undefined;
    var index: usize = 0;

    var it = mem.splitScalar(u8, text, '.');
    while (it.next()) |part| {
        if (index == octets.len or part.len == 0) return null;
        octets[index] = std.fmt.parseInt(u8, part, 10) catch return null;
        index += 1;
    }
    if (index != octets.len) return null;

    return (@as(u32, octets[0]) << 24) |
        (@as(u32, octets[1]) << 16) |
        (@as(u32, octets[2]) << 8) |
        @as(u32, octets[3]);
}

/// `*` matches any run of characters. `?` matches one. Everything else is a
/// literal byte. Standard PAC `shExpMatch` semantics.
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

fn expectProxy(engine: *const PacEngine, url: []const u8, host: []const u8, expected: []const u8) !void {
    const result = try engine.findProxyForURL(url, host) orelse return error.TestExpectedSome;
    try std.testing.expectEqualStrings(expected, result.proxy);
}

test "PAC: core predicates and branch ordering" {
    var engine = PacEngine.init(std.testing.allocator,
        \\function FindProxyForURL(url, host) {
        \\  if (isPlainHostName(host)) return "DIRECT";
        \\  if (dnsDomainIs(host, ".corp.example")) return "PROXY proxy.corp.example:3128";
        \\  if (shExpMatch(url, "http://*.example/*")) return "SOCKS5 socks.local:1080";
        \\  return "DIRECT";
        \\}
    );

    try expectProxy(&engine, "http://intra/", "intra", "DIRECT");
    try expectProxy(&engine, "http://api.corp.example/x", "api.corp.example", "PROXY proxy.corp.example:3128");
    try expectProxy(&engine, "http://www.example/x", "www.example", "SOCKS5 socks.local:1080");
    try expectProxy(&engine, "https://www.example/x", "www.example", "DIRECT");
}

test "PAC: shExpMatch keeps full URLs and glob semantics" {
    var engine = PacEngine.init(std.testing.allocator,
        \\function FindProxyForURL(url, host) {
        \\  if (shExpMatch(url, "https://*.example.com/*")) return "PROXY proxy.example.com:8443; DIRECT";
        \\  if (shExpMatch(host, "db?.internal")) return "SOCKS5 socks.local:1080";
        \\  return "DIRECT";
        \\}
    );

    try expectProxy(
        &engine,
        "https://a.example.com/path?q=1&r=2;x=3",
        "a.example.com",
        "PROXY proxy.example.com:8443; DIRECT",
    );
    try expectProxy(&engine, "http://db1.internal/", "db1.internal", "SOCKS5 socks.local:1080");
    try expectProxy(&engine, "http://db12.internal/", "db12.internal", "DIRECT");
}

test "PAC: local host, domain suffix and domain-level predicates" {
    var engine = PacEngine.init(std.testing.allocator,
        \\function FindProxyForURL(url, host) {
        \\  if (localHostOrDomainIs(host, "www.example.com")) return "DIRECT";
        \\  if (dnsDomainIs(host, ".corp.example")) return "PROXY corp:8080";
        \\  if (dnsDomainLevels(host) == 2) return "PROXY two-levels:8080";
        \\  return "DIRECT";
        \\}
    );

    try expectProxy(&engine, "http://www/", "www", "DIRECT");
    try expectProxy(&engine, "http://www.example.com/", "www.example.com", "DIRECT");
    try expectProxy(&engine, "http://api.corp.example/", "api.corp.example", "PROXY corp:8080");
    try expectProxy(&engine, "http://a.example/", "a.example", "DIRECT");
    try expectProxy(&engine, "http://a.b.example/", "a.b.example", "PROXY two-levels:8080");
    try expectProxy(&engine, "http://localhost/", "localhost", "DIRECT");
}

test "PAC: isInNet matches IPv4 ranges" {
    var engine = PacEngine.init(std.testing.allocator,
        \\function FindProxyForURL(url, host) {
        \\  if (isInNet(host, "192.168.1.0", "255.255.255.0")) return "DIRECT";
        \\  if (isInNet(host, "10.0.0.0", "255.0.0.0")) return "PROXY ten:8080";
        \\  return "PROXY fallback:8080";
        \\}
    );

    try expectProxy(&engine, "http://192.168.1.55/", "192.168.1.55", "DIRECT");
    try expectProxy(&engine, "http://192.168.2.55/", "192.168.2.55", "PROXY fallback:8080");
    try expectProxy(&engine, "http://10.9.8.7/", "10.9.8.7", "PROXY ten:8080");
    try expectProxy(&engine, "http://example.com/", "example.com", "PROXY fallback:8080");
    try expectProxy(&engine, "http://999.1.1.1/", "999.1.1.1", "PROXY fallback:8080");
}

test "PAC: boolean operators, negation and parentheses" {
    var engine = PacEngine.init(std.testing.allocator,
        \\function FindProxyForURL(url, host) {
        \\  if (!isPlainHostName(host) && (dnsDomainIs(host, ".corp.example") || shExpMatch(host, "*.internal"))) {
        \\    return "PROXY secure:3128";
        \\  }
        \\  return "DIRECT";
        \\}
    );

    try expectProxy(&engine, "http://api.corp.example/", "api.corp.example", "PROXY secure:3128");
    try expectProxy(&engine, "http://db.internal/", "db.internal", "PROXY secure:3128");
    try expectProxy(&engine, "http://intra/", "intra", "DIRECT");
    try expectProxy(&engine, "http://other.example/", "other.example", "DIRECT");
}

test "PAC: string equality and inequality" {
    var engine = PacEngine.init(std.testing.allocator,
        \\function FindProxyForURL(url, host) {
        \\  if (host == "special") return "SOCKS5 special:1080";
        \\  if (host != "blocked") return "DIRECT";
        \\  return "PROXY blocked:8080";
        \\}
    );

    try expectProxy(&engine, "http://special/", "special", "SOCKS5 special:1080");
    try expectProxy(&engine, "http://other/", "other", "DIRECT");
    try expectProxy(&engine, "http://blocked/", "blocked", "PROXY blocked:8080");
}

test "PAC: nested if/else and single-statement branches" {
    var engine = PacEngine.init(std.testing.allocator,
        \\function FindProxyForURL(url, host) {
        \\  if (isPlainHostName(host))
        \\    if (host == "intra") return "DIRECT";
        \\    else return "PROXY plain:8080";
        \\  else if (dnsDomainIs(host, ".corp.example")) return "PROXY corp:8080";
        \\  return "DIRECT";
        \\}
    );

    try expectProxy(&engine, "http://intra/", "intra", "DIRECT");
    try expectProxy(&engine, "http://plain/", "plain", "PROXY plain:8080");
    try expectProxy(&engine, "http://a.corp.example/", "a.corp.example", "PROXY corp:8080");
    try expectProxy(&engine, "http://other.example/", "other.example", "DIRECT");
}

test "PAC: variables hold strings and booleans" {
    var engine = PacEngine.init(std.testing.allocator,
        \\function FindProxyForURL(url, host) {
        \\  var proxy = "DIRECT";
        \\  var isCorp = dnsDomainIs(host, ".corp.example");
        \\  if (isCorp) { proxy = "PROXY corp:8080"; }
        \\  return proxy;
        \\}
    );

    try expectProxy(&engine, "http://a.corp.example/", "a.corp.example", "PROXY corp:8080");
    try expectProxy(&engine, "http://other.example/", "other.example", "DIRECT");
}

test "PAC: function parameter names are honoured" {
    var engine = PacEngine.init(std.testing.allocator,
        \\function FindProxyForURL(u, h) {
        \\  if (dnsDomainIs(h, ".corp.example")) return u;
        \\  return "DIRECT";
        \\}
    );

    try expectProxy(&engine, "PROXY from-param:1", "api.corp.example", "PROXY from-param:1");
    try expectProxy(&engine, "PROXY unused:1", "other.example", "DIRECT");
}

test "PAC: comments are skipped and string payloads preserved" {
    var engine = PacEngine.init(std.testing.allocator,
        \\/*
        \\ * A comment with { braces } and "quotes".
        \\ */
        \\function FindProxyForURL(url, host) {
        \\  // return "BROKEN";
        \\  if (shExpMatch(url, "https://*.example.com/*")) {
        \\    return "PROXY proxy.example.com:8443; DIRECT"; // trailing comment
        \\  }
        \\  return "DIRECT";
        \\}
    );

    try expectProxy(
        &engine,
        "https://a.example.com/path?q=1&r=2;x=3",
        "a.example.com",
        "PROXY proxy.example.com:8443; DIRECT",
    );
    try expectProxy(&engine, "http://a.example.com/", "a.example.com", "DIRECT");
}

test "PAC: unsupported functions error only when evaluated" {
    var engine = PacEngine.init(std.testing.allocator,
        \\function FindProxyForURL(url, host) {
        \\  if (isPlainHostName(host) || dateRange("MON")) return "DIRECT";
        \\  if (dnsDomainIs(host, ".corp.example")) return "PROXY corp:8080";
        \\  return dateRange("MON");
        \\}
    );

    // RHS of `||` is short-circuited once the LHS is true.
    try expectProxy(&engine, "http://intra/", "intra", "DIRECT");
    // The unsupported call is evaluated for a non-corp host and must surface.
    try std.testing.expectError(
        error.UnsupportedPacFunction,
        engine.findProxyForURL("http://other.example/", "other.example"),
    );
}

test "PAC: missing entry point yields null" {
    var no_function = PacEngine.init(std.testing.allocator, "var x = 1;");
    try std.testing.expect((try no_function.findProxyForURL("http://a/", "a")) == null);

    var unclosed = PacEngine.init(std.testing.allocator,
        \\function FindProxyForURL(url, host) {
        \\  if (isPlainHostName(host)) return "DIRECT";
    );
    try std.testing.expect((try unclosed.findProxyForURL("http://a/", "a")) == null);
}

test "PAC: non-string return is rejected" {
    var engine = PacEngine.init(std.testing.allocator,
        \\function FindProxyForURL(url, host) {
        \\  return 42;
        \\}
    );
    try std.testing.expectError(
        error.TypeError,
        engine.findProxyForURL("http://a/", "a"),
    );
}

test "shExpMatch glob is correct" {
    try std.testing.expect(globMatch("http://*.example/*", "http://api.example/x"));
    try std.testing.expect(!globMatch("http://*.example/*", "https://api.example/x"));
    try std.testing.expect(globMatch("?ello", "hello"));
    try std.testing.expect(globMatch("*example*", "http://a.example/b"));
    try std.testing.expect(!globMatch("?ello", "hello!"));
}
