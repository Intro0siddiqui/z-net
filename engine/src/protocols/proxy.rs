//! Proxy support - Rust-side coordinator that reads system proxy
//! settings, executes PAC scripts, and handles HTTP CONNECT and SOCKS5 tunneling.

use std::env;
use std::ffi::{CStr, CString};
use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpStream, ToSocketAddrs};
use std::os::raw::{c_char, c_int};

/// A `ProxyRule` is the parsed form of a PAC `FindProxyForURL` result or manual proxy config.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxyRule {
    pub scheme: ProxyScheme,
    pub host: String,
    pub port: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProxyScheme {
    Direct,
    Http,
    Socks5,
    Socks4,
}

/// One hop in the chain. This is a 1:1 mirror of the Zig `ProxyHop` struct.
#[repr(C)]
pub struct CProxyHop {
    pub scheme: c_int, // 0=direct, 1=http, 2=socks5, 3=socks4
    pub host: *const c_char,
    pub port: u16,
    pub auth_header: *const c_char,
}

/// Complete proxy configuration supporting PAC scripts, environment overrides, and bypass lists.
#[derive(Debug, Clone, Default)]
pub struct ProxyConfig {
    pub http_proxy: Option<ProxyRule>,
    pub https_proxy: Option<ProxyRule>,
    pub no_proxy: Vec<String>,
    pub pac_script: Option<String>,
}

impl ProxyConfig {
    pub fn new() -> Self {
        Self::default()
    }

    /// Read system proxy settings from environment variables (`HTTP_PROXY`, `HTTPS_PROXY`, `NO_PROXY`).
    pub fn from_env() -> Self {
        let mut cfg = Self::default();
        if let Ok(v) = env::var("HTTPS_PROXY").or_else(|_| env::var("https_proxy")) {
            cfg.https_proxy = parse_proxy_str(&v, ProxyScheme::Http);
        }
        if let Ok(v) = env::var("HTTP_PROXY").or_else(|_| env::var("http_proxy")) {
            cfg.http_proxy = parse_proxy_str(&v, ProxyScheme::Http);
        }
        if let Ok(v) = env::var("NO_PROXY").or_else(|_| env::var("no_proxy")) {
            for part in v.split(',') {
                let s = part.trim();
                if !s.is_empty() {
                    cfg.no_proxy.push(s.to_string());
                }
            }
        }
        cfg
    }

    pub fn with_pac(mut self, pac_content: String) -> Self {
        self.pac_script = Some(pac_content);
        self
    }

    /// True if the specified host matches any entry in the `no_proxy` list.
    pub fn should_bypass(&self, host: &str) -> bool {
        let host_lower = host.to_ascii_lowercase();
        // Always bypass localhost/loopback
        if host_lower == "localhost" || host_lower == "127.0.0.1" || host_lower == "::1" {
            return true;
        }

        for pattern in &self.no_proxy {
            let p_lower = pattern.to_ascii_lowercase();
            if p_lower == "*" {
                return true;
            }
            if p_lower.starts_with('.') {
                if host_lower.ends_with(&p_lower) {
                    return true;
                }
            } else if host_lower == p_lower || host_lower.ends_with(&format!(".{}", p_lower)) {
                return true;
            }
        }
        false
    }

    /// Resolve the proxy to use for a given URL and host.
    pub fn resolve(&self, url: &str, host: &str, is_https: bool) -> ProxyRule {
        if self.should_bypass(host) {
            return ProxyRule {
                scheme: ProxyScheme::Direct,
                host: String::new(),
                port: 0,
            };
        }

        // 1. If PAC script is installed, evaluate FindProxyForURL
        if let Some(ref script) = self.pac_script {
            if let Some(pac_result) = evaluate_minimal(script, url, host) {
                if let Some(rule) = parse_pac_rule_first(&pac_result) {
                    return rule;
                }
            }
        }

        // 2. Fallback to explicit scheme proxy
        if is_https {
            if let Some(ref p) = self.https_proxy {
                return p.clone();
            }
        } else if let Some(ref p) = self.http_proxy {
            return p.clone();
        }

        ProxyRule {
            scheme: ProxyScheme::Direct,
            host: String::new(),
            port: 0,
        }
    }
}

/// Discover proxy config from environment variables.
#[no_mangle]
pub extern "C" fn znet_proxy_discover_env(out: *mut c_char, out_len: usize) -> c_int {
    if out.is_null() || out_len == 0 {
        return -1;
    }
    let mut buf = String::new();
    for var in &["HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "http_proxy", "https_proxy", "no_proxy"] {
        if let Ok(v) = env::var(var) {
            buf.push_str(var);
            buf.push('=');
            buf.push_str(&v);
            buf.push('\n');
        }
    }
    let bytes = buf.into_bytes();
    if bytes.len() >= out_len {
        return -2;
    }
    let n = bytes.len();
    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), out as *mut u8, n);
        *out.add(n) = 0;
    }
    n as c_int
}

/// Evaluate a PAC script body for a given (url, host) pair. Writes the
/// resulting rule string into `out` (caller-provided, null-terminated).
#[no_mangle]
pub extern "C" fn znet_pac_evaluate(
    source: *const c_char,
    url: *const c_char,
    host: *const c_char,
    out: *mut c_char,
    out_len: usize,
) -> c_int {
    if source.is_null() || url.is_null() || host.is_null() || out.is_null() || out_len == 0 {
        return -1;
    }
    let src = unsafe { CStr::from_ptr(source) }.to_string_lossy().into_owned();
    let url_str = unsafe { CStr::from_ptr(url) }.to_string_lossy().into_owned();
    let host_str = unsafe { CStr::from_ptr(host) }.to_string_lossy().into_owned();
    let result = match evaluate_minimal(&src, &url_str, &host_str) {
        Some(s) => s,
        None => return -1,
    };
    let bytes = result.into_bytes();
    let n = bytes.len().min(out_len - 1);
    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), out as *mut u8, n);
        *out.add(n) = 0;
    }
    n as c_int
}

/// Parse the first `PROXY` or `SOCKS5` rule from a PAC result string.
#[no_mangle]
pub extern "C" fn znet_proxy_parse_first(
    rule: *const c_char,
    out: *mut CProxyHop,
) -> c_int {
    if rule.is_null() || out.is_null() {
        return -1;
    }
    let rstr = unsafe { CStr::from_ptr(rule) }.to_string_lossy().into_owned();
    if let Some(rule) = parse_pac_rule_first(&rstr) {
        let host_c = CString::new(rule.host).unwrap_or_default();
        unsafe {
            (*out).scheme = match rule.scheme {
                ProxyScheme::Direct => 0,
                ProxyScheme::Http => 1,
                ProxyScheme::Socks5 => 2,
                ProxyScheme::Socks4 => 3,
            };
            (*out).host = host_c.into_raw();
            (*out).port = rule.port;
            (*out).auth_header = std::ptr::null();
        }
        0
    } else {
        -1
    }
}

pub fn parse_pac_rule_first(rstr: &str) -> Option<ProxyRule> {
    for part in rstr.split(';') {
        let p = part.trim();
        if let Some(rest) = p.strip_prefix("PROXY ") {
            if let Some(rule) = parse_host_port(rest, ProxyScheme::Http) {
                return Some(rule);
            }
        } else if let Some(rest) = p.strip_prefix("SOCKS5 ") {
            if let Some(rule) = parse_host_port(rest, ProxyScheme::Socks5) {
                return Some(rule);
            }
        } else if let Some(rest) = p.strip_prefix("SOCKS4 ") {
            if let Some(rule) = parse_host_port(rest, ProxyScheme::Socks4) {
                return Some(rule);
            }
        } else if p.eq_ignore_ascii_case("DIRECT") {
            return Some(ProxyRule {
                scheme: ProxyScheme::Direct,
                host: String::new(),
                port: 0,
            });
        }
    }
    None
}

fn parse_proxy_str(raw: &str, default_scheme: ProxyScheme) -> Option<ProxyRule> {
    let mut s = raw.trim();
    let scheme = if let Some(rest) = s.strip_prefix("socks5://") {
        s = rest;
        ProxyScheme::Socks5
    } else if let Some(rest) = s.strip_prefix("socks4://") {
        s = rest;
        ProxyScheme::Socks4
    } else if let Some(rest) = s.strip_prefix("http://") {
        s = rest;
        ProxyScheme::Http
    } else if let Some(rest) = s.strip_prefix("https://") {
        s = rest;
        ProxyScheme::Http
    } else {
        default_scheme
    };

    let colon = s.rfind(':')?;
    let host = s[..colon].to_string();
    let port: u16 = s[colon + 1..].parse().ok()?;
    Some(ProxyRule { scheme, host, port })
}

fn parse_host_port(s: &str, scheme: ProxyScheme) -> Option<ProxyRule> {
    let s = s.trim();
    let colon = s.rfind(':')?;
    let host = s[..colon].to_string();
    let port: u16 = s[colon + 1..].parse().ok()?;
    Some(ProxyRule { scheme, host, port })
}

// ─────────────────────────────────────────────────────────────────────────────
// PAC Evaluation Engine
// ─────────────────────────────────────────────────────────────────────────────

pub fn evaluate_minimal(src: &str, url: &str, host: &str) -> Option<String> {
    let marker = "FindProxyForURL";
    let idx = src.find(marker)?;
    let body_start = src[idx..].find('{')?;
    let body_with_brace = &src[idx + body_start..];
    let end = match_brace(body_with_brace)?;
    let body = &body_with_brace[1..end];

    let mut pos = 0;
    while pos < body.len() {
        let rest = &body[pos..];
        let s = rest.trim_start();
        let skipped = rest.len() - s.len();
        pos += skipped;

        if s.is_empty() {
            break;
        }

        if s.starts_with("return ") {
            let return_len = "return ".len();
            let value_offset = return_len + (s[return_len..].len() - s[return_len..].trim_start().len());
            let after_start = &s[value_offset..];
            let v = if after_start.starts_with('"') {
                if let Some(close_quote) = after_start[1..].find('"') {
                    &after_start[1..1 + close_quote]
                } else {
                    after_start.trim_matches('"')
                }
            } else {
                let line = after_start.split('\n').next().unwrap_or("");
                if let Some(semi) = line.find(';') {
                    line[..semi].trim()
                } else {
                    line.trim()
                }
            };
            return Some(v.to_string());
        } else if s.starts_with("if ") || s.starts_with("if(") {
            let cond_end = s.find('{')?;
            let cond = s["if".len()..cond_end].trim();
            let matched = eval_cond(cond, url, host);
            let block_with_brace = &s[cond_end..];
            let close = match_brace(block_with_brace)?;
            if matched {
                let block = &block_with_brace[1..close];
                if let Some(ret_off) = block.find("return ") {
                    let ret_stmt = &block[ret_off..];
                    let ret_after = ret_stmt["return ".len()..].trim();
                    let v = if ret_after.starts_with('"') {
                        if let Some(close_quote) = ret_after[1..].find('"') {
                            &ret_after[1..1 + close_quote]
                        } else {
                            ret_after.trim_matches('"')
                        }
                    } else {
                        let line = ret_after.split('\n').next().unwrap_or("");
                        if let Some(semi) = line.find(';') {
                            line[..semi].trim()
                        } else {
                            line.trim()
                        }
                    };
                    return Some(v.to_string());
                }
            }
            pos += cond_end + close + 1;
        } else {
            if let Some(semi) = body[pos..].find(';') {
                pos += semi + 1;
            } else {
                break;
            }
        }
    }
    None
}

fn split_top_level<'a>(s: &'a str, delim: &str) -> Option<Vec<&'a str>> {
    let mut parts = Vec::new();
    let mut depth: i32 = 0;
    let mut last = 0;
    let delim_bytes = delim.as_bytes();
    let s_bytes = s.as_bytes();
    let len = s_bytes.len();
    let dlen = delim_bytes.len();

    let mut i = 0;
    let mut found = false;
    while i < len {
        let b = s_bytes[i];
        if b == b'(' {
            depth += 1;
        } else if b == b')' {
            depth -= 1;
        } else if depth == 0 && i + dlen <= len && &s_bytes[i..i + dlen] == delim_bytes {
            parts.push(&s[last..i]);
            i += dlen;
            last = i;
            found = true;
            continue;
        }
        i += 1;
    }

    if !found {
        None
    } else {
        parts.push(&s[last..]);
        Some(parts)
    }
}

/// Evaluates compound boolean conditions with `&&`, `||`, and `!` support.
pub fn eval_cond(mut cond: &str, url: &str, host: &str) -> bool {
    cond = cond.trim().trim_end_matches('{').trim();

    // Strip outer parentheses if present
    while cond.starts_with('(') && cond.ends_with(')') {
        if match_parentheses(cond) == Some(cond.len() - 1) {
            cond = cond[1..cond.len() - 1].trim();
        } else {
            break;
        }
    }

    // 1. Disjunction (`||`) at top-level
    if let Some(parts) = split_top_level(cond, "||") {
        for part in parts {
            if eval_cond(part.trim(), url, host) {
                return true;
            }
        }
        return false;
    }

    // 2. Conjunction (`&&`) at top-level
    if let Some(parts) = split_top_level(cond, "&&") {
        for part in parts {
            if !eval_cond(part.trim(), url, host) {
                return false;
            }
        }
        return true;
    }

    // 3. Negation (`!`)
    if let Some(rest) = cond.strip_prefix('!') {
        return !eval_cond(rest.trim(), url, host);
    }

    eval_single_cond(cond, url, host)
}

fn eval_single_cond(cond: &str, url: &str, host: &str) -> bool {
    let cond = cond.trim();

    // Standard PAC: isPlainHostName(host)
    if let Some(rest) = cond.strip_prefix("isPlainHostName(") {
        let arg = rest.trim_end_matches(')').trim_matches('"');
        let target = if arg == "host" { host } else { arg };
        return !target.contains('.');
    }

    // Standard PAC: dnsDomainIs(host, domain)
    if let Some(rest) = cond.strip_prefix("dnsDomainIs(") {
        let inside = rest.trim_end_matches(')');
        let parts: Vec<&str> = inside.split(',').collect();
        if parts.len() >= 2 {
            let target_host = if parts[0].trim() == "host" { host } else { parts[0].trim().trim_matches('"') };
            let domain = parts[1].trim().trim_matches('"');
            return target_host.ends_with(domain);
        }
    }

    // Standard PAC: localHostOrDomainIs(host, hostdom)
    if let Some(rest) = cond.strip_prefix("localHostOrDomainIs(") {
        let inside = rest.trim_end_matches(')');
        let parts: Vec<&str> = inside.split(',').collect();
        if parts.len() >= 2 {
            let target_host = if parts[0].trim() == "host" { host } else { parts[0].trim().trim_matches('"') };
            let hostdom = parts[1].trim().trim_matches('"');
            if target_host == hostdom {
                return true;
            }
            if !target_host.contains('.') && hostdom.starts_with(target_host) {
                return true;
            }
        }
        return false;
    }

    // Standard PAC: isResolvable(host)
    if let Some(rest) = cond.strip_prefix("isResolvable(") {
        let arg = rest.trim_end_matches(')').trim_matches('"');
        let target = if arg == "host" { host } else { arg };
        return format!("{}:80", target).to_socket_addrs().is_ok();
    }

    // Standard PAC: isInNet(ip_or_host, pattern, mask)
    if let Some(rest) = cond.strip_prefix("isInNet(") {
        let inside = rest.trim_end_matches(')');
        let parts: Vec<&str> = inside.split(',').collect();
        if parts.len() >= 3 {
            let target = if parts[0].trim() == "host" { host } else { parts[0].trim().trim_matches('"') };
            let pattern_str = parts[1].trim().trim_matches('"');
            let mask_str = parts[2].trim().trim_matches('"');

            if let (Ok(pattern_ip), Ok(mask_ip)) = (pattern_str.parse::<Ipv4Addr>(), mask_str.parse::<Ipv4Addr>()) {
                let resolved_ip = target.parse::<Ipv4Addr>().ok().or_else(|| {
                    format!("{}:80", target)
                        .to_socket_addrs()
                        .ok()?
                        .find_map(|a| match a {
                            SocketAddr::V4(v4) => Some(*v4.ip()),
                            _ => None,
                        })
                });

                if let Some(ip) = resolved_ip {
                    let ip_u32 = u32::from(ip);
                    let pat_u32 = u32::from(pattern_ip);
                    let mask_u32 = u32::from(mask_ip);
                    return (ip_u32 & mask_u32) == (pat_u32 & mask_u32);
                }
            }
        }
        return false;
    }

    // Standard PAC: dnsDomainLevels(host)
    if let Some(rest) = cond.strip_prefix("dnsDomainLevels(") {
        let inside = rest.trim_end_matches(')');
        let target = if inside.trim() == "host" { host } else { inside.trim().trim_matches('"') };
        let levels = target.chars().filter(|&c| c == '.').count();
        // If compared like dnsDomainLevels(host) > 0 or == 0
        return levels > 0;
    }

    // Standard PAC: shExpMatch(str, shexp)
    if let Some(rest) = cond.strip_prefix("shExpMatch(") {
        let inside = rest.trim_end_matches(')');
        let parts: Vec<&str> = inside.split(',').collect();
        if parts.len() >= 2 {
            let candidate = if parts[0].trim() == "url" {
                url
            } else if parts[0].trim() == "host" {
                host
            } else {
                parts[0].trim().trim_matches('"')
            };
            let pattern = parts[1].trim().trim_matches('"');
            return glob_match(pattern, candidate);
        }
    }

    false
}

fn match_brace(s: &str) -> Option<usize> {
    let mut depth: i32 = 0;
    for (i, c) in s.char_indices() {
        if c == '{' {
            depth += 1;
        } else if c == '}' {
            depth -= 1;
            if depth == 0 {
                return Some(i);
            }
        }
    }
    None
}

fn match_parentheses(s: &str) -> Option<usize> {
    let mut depth: i32 = 0;
    for (i, c) in s.char_indices() {
        if c == '(' {
            depth += 1;
        } else if c == ')' {
            depth -= 1;
            if depth == 0 {
                return Some(i);
            }
        }
    }
    None
}

pub fn glob_match(pattern: &str, s: &str) -> bool {
    let pat: Vec<char> = pattern.chars().collect();
    let str: Vec<char> = s.chars().collect();
    let mut p = 0;
    let mut si = 0;
    let mut star: Option<usize> = None;
    let mut match_pos: usize = 0;
    while si < str.len() {
        if p < pat.len() && pat[p] == '*' {
            star = Some(p);
            match_pos = si;
            p += 1;
        } else if p < pat.len() && (pat[p] == '?' || pat[p].to_ascii_lowercase() == str[si].to_ascii_lowercase()) {
            p += 1;
            si += 1;
        } else if let Some(sp) = star {
            p = sp + 1;
            match_pos += 1;
            si = match_pos;
        } else {
            return false;
        }
    }
    while p < pat.len() && pat[p] == '*' {
        p += 1;
    }
    p == pat.len()
}

// ─────────────────────────────────────────────────────────────────────────────
// Tunneling Implementations: HTTP CONNECT & SOCKS5
// ─────────────────────────────────────────────────────────────────────────────

/// Establishes an HTTP CONNECT tunnel on an already connected TCP socket.
/// Format: `CONNECT target_host:target_port HTTP/1.1\r\nHost: target_host:target_port\r\n\r\n`
pub fn establish_http_connect_tunnel(
    stream: &mut TcpStream,
    target_host: &str,
    target_port: u16,
) -> Result<(), String> {
    let connect_req = format!(
        "CONNECT {}:{} HTTP/1.1\r\nHost: {}:{}\r\nProxy-Connection: keep-alive\r\nUser-Agent: Zawra/1.0\r\n\r\n",
        target_host, target_port, target_host, target_port
    );
    stream.write_all(connect_req.as_bytes())
        .map_err(|e| format!("Failed to send HTTP CONNECT: {}", e))?;
    stream.flush()
        .map_err(|e| format!("Failed to flush HTTP CONNECT: {}", e))?;

    let mut buf = [0u8; 1024];
    let mut total_read = 0;
    loop {
        let n = stream.read(&mut buf[total_read..])
            .map_err(|e| format!("Failed reading proxy response: {}", e))?;
        if n == 0 {
            return Err("Proxy closed connection prematurely during CONNECT".to_string());
        }
        total_read += n;

        let response_str = String::from_utf8_lossy(&buf[..total_read]);
        if let Some(header_end) = response_str.find("\r\n\r\n") {
            let first_line = response_str[..header_end].lines().next().unwrap_or("");
            if first_line.contains(" 200 ") || first_line.ends_with(" 200") {
                return Ok(());
            } else {
                return Err(format!("Proxy rejected CONNECT with status: {}", first_line));
            }
        }
        if total_read >= buf.len() {
            return Err("Proxy CONNECT response headers exceeded buffer limit".to_string());
        }
    }
}

/// Establishes an RFC 1928 SOCKS5 tunnel to target_host:target_port.
pub fn establish_socks5_tunnel(
    stream: &mut TcpStream,
    target_host: &str,
    target_port: u16,
) -> Result<(), String> {
    // 1. Client greeting: Version 5, 1 authentication method (No Auth: 0x00)
    let greeting = [0x05, 0x01, 0x00];
    stream.write_all(&greeting)
        .map_err(|e| format!("Failed to send SOCKS5 greeting: {}", e))?;
    stream.flush()
        .map_err(|e| format!("Failed to flush SOCKS5 greeting: {}", e))?;

    let mut response = [0u8; 2];
    stream.read_exact(&mut response)
        .map_err(|e| format!("Failed to read SOCKS5 auth method choice: {}", e))?;

    if response[0] != 0x05 || response[1] != 0x00 {
        return Err(format!("SOCKS5 server rejected unauthenticated connection (code: {:?})", response));
    }

    // 2. Connect request: VER=5, CMD=1 (CONNECT), RSV=0, ATYP=3 (Domain name)
    let host_bytes = target_host.as_bytes();
    if host_bytes.len() > 255 {
        return Err("Target hostname exceeds SOCKS5 255-byte length limit".to_string());
    }

    let mut request = Vec::with_capacity(4 + 1 + host_bytes.len() + 2);
    request.extend_from_slice(&[0x05, 0x01, 0x00, 0x03, host_bytes.len() as u8]);
    request.extend_from_slice(host_bytes);
    request.extend_from_slice(&target_port.to_be_bytes());

    stream.write_all(&request)
        .map_err(|e| format!("Failed to send SOCKS5 CONNECT command: {}", e))?;
    stream.flush()
        .map_err(|e| format!("Failed to flush SOCKS5 CONNECT command: {}", e))?;

    // 3. Response: [VER, REP, RSV, ATYP, BND.ADDR, BND.PORT]
    let mut resp_header = [0u8; 4];
    stream.read_exact(&mut resp_header)
        .map_err(|e| format!("Failed to read SOCKS5 CONNECT reply header: {}", e))?;

    if resp_header[0] != 0x05 {
        return Err("Invalid SOCKS5 version in reply".to_string());
    }
    if resp_header[1] != 0x00 {
        return Err(format!("SOCKS5 connect failed with reply code: 0x{:02x}", resp_header[1]));
    }

    // Consume bound address based on ATYP
    match resp_header[3] {
        0x01 => {
            // IPv4: 4 bytes + 2 bytes port
            let mut buf = [0u8; 6];
            stream.read_exact(&mut buf).map_err(|e| format!("Failed reading SOCKS5 IPv4 bound addr: {}", e))?;
        }
        0x03 => {
            // Domain name: 1 byte len + domain + 2 bytes port
            let mut len_buf = [0u8; 1];
            stream.read_exact(&mut len_buf).map_err(|e| format!("Failed reading SOCKS5 domain len: {}", e))?;
            let mut domain_buf = vec![0u8; len_buf[0] as usize + 2];
            stream.read_exact(&mut domain_buf).map_err(|e| format!("Failed reading SOCKS5 domain bound addr: {}", e))?;
        }
        0x04 => {
            // IPv6: 16 bytes + 2 bytes port
            let mut buf = [0u8; 18];
            stream.read_exact(&mut buf).map_err(|e| format!("Failed reading SOCKS5 IPv6 bound addr: {}", e))?;
        }
        other => return Err(format!("Unknown SOCKS5 address type: {}", other)),
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pac_eval_is_plain_host_name() {
        let script = r#"
            function FindProxyForURL(url, host) {
                if (isPlainHostName(host)) {
                    return "DIRECT";
                }
                return "PROXY proxy.corp.local:8080";
            }
        "#;
        assert_eq!(evaluate_minimal(script, "http://intranet/index", "intranet"), Some("DIRECT".to_string()));
        assert_eq!(evaluate_minimal(script, "https://example.com/", "example.com"), Some("PROXY proxy.corp.local:8080".to_string()));
    }

    #[test]
    fn test_pac_eval_dns_domain_is() {
        let script = r#"
            function FindProxyForURL(url, host) {
                if (dnsDomainIs(host, ".google.com")) {
                    return "PROXY gproxy:8080";
                }
                return "DIRECT";
            }
        "#;
        assert_eq!(evaluate_minimal(script, "https://mail.google.com/", "mail.google.com"), Some("PROXY gproxy:8080".to_string()));
        assert_eq!(evaluate_minimal(script, "https://youtube.com/", "youtube.com"), Some("DIRECT".to_string()));
    }

    #[test]
    fn test_pac_eval_local_host_or_domain_is() {
        let script = r#"
            function FindProxyForURL(url, host) {
                if (localHostOrDomainIs(host, "www.internal.net")) {
                    return "DIRECT";
                }
                return "PROXY corp.proxy:3128";
            }
        "#;
        assert_eq!(evaluate_minimal(script, "http://www.internal.net/", "www.internal.net"), Some("DIRECT".to_string()));
        assert_eq!(evaluate_minimal(script, "http://www/index", "www"), Some("DIRECT".to_string()));
        assert_eq!(evaluate_minimal(script, "https://external.org/", "external.org"), Some("PROXY corp.proxy:3128".to_string()));
    }

    #[test]
    fn test_pac_eval_is_in_net() {
        let script = r#"
            function FindProxyForURL(url, host) {
                if (isInNet(host, "10.0.0.0", "255.0.0.0")) {
                    return "DIRECT";
                }
                return "SOCKS5 10.0.0.1:1080";
            }
        "#;
        assert_eq!(evaluate_minimal(script, "http://10.5.1.2/", "10.5.1.2"), Some("DIRECT".to_string()));
        assert_eq!(evaluate_minimal(script, "http://192.168.1.1/", "192.168.1.1"), Some("SOCKS5 10.0.0.1:1080".to_string()));
    }

    #[test]
    fn test_pac_eval_compound_boolean_logic() {
        let script = r#"
            function FindProxyForURL(url, host) {
                if (isPlainHostName(host) || dnsDomainIs(host, ".local")) {
                    return "DIRECT";
                }
                if (!dnsDomainIs(host, ".internal") && shExpMatch(url, "*youtube*")) {
                    return "PROXY media-proxy:8080; DIRECT";
                }
                return "DIRECT";
            }
        "#;
        assert_eq!(evaluate_minimal(script, "http://nas/", "nas"), Some("DIRECT".to_string()));
        assert_eq!(evaluate_minimal(script, "http://router.local/", "router.local"), Some("DIRECT".to_string()));
        assert_eq!(evaluate_minimal(script, "https://www.youtube.com/watch?v=1", "www.youtube.com"), Some("PROXY media-proxy:8080; DIRECT".to_string()));
    }

    #[test]
    fn test_proxy_config_bypass_matching() {
        let mut cfg = ProxyConfig::new();
        cfg.no_proxy = vec!["example.com".to_string(), ".corp.net".to_string()];

        assert!(cfg.should_bypass("localhost"));
        assert!(cfg.should_bypass("127.0.0.1"));
        assert!(cfg.should_bypass("example.com"));
        assert!(cfg.should_bypass("sub.example.com"));
        assert!(cfg.should_bypass("host.corp.net"));
        assert!(!cfg.should_bypass("other.com"));
    }

    #[test]
    fn test_http_connect_tunnel_roundtrip() {
        use std::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock proxy");
        let port = listener.local_addr().unwrap().port();

        let server = std::thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut buf = [0u8; 1024];
                let n = stream.read(&mut buf).unwrap();
                let req = String::from_utf8_lossy(&buf[..n]);
                assert!(req.starts_with("CONNECT target.com:443 HTTP/1.1"));

                let response = b"HTTP/1.1 200 Connection established\r\n\r\n";
                stream.write_all(response).unwrap();
            }
        });

        let mut client_stream = TcpStream::connect(format!("127.0.0.1:{}", port)).expect("connect to proxy");
        assert!(establish_http_connect_tunnel(&mut client_stream, "target.com", 443).is_ok());

        server.join().unwrap();
    }

    #[test]
    fn test_socks5_tunnel_roundtrip() {
        use std::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock socks5");
        let port = listener.local_addr().unwrap().port();

        let server = std::thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                // 1. Read greeting [0x05, 0x01, 0x00]
                let mut greeting = [0u8; 3];
                stream.read_exact(&mut greeting).unwrap();
                assert_eq!(greeting, [0x05, 0x01, 0x00]);

                // Send choice [0x05, 0x00] (No Auth)
                stream.write_all(&[0x05, 0x00]).unwrap();

                // 2. Read connect request
                let mut req_header = [0u8; 5];
                stream.read_exact(&mut req_header).unwrap();
                assert_eq!(req_header[0..4], [0x05, 0x01, 0x00, 0x03]);
                let domain_len = req_header[4] as usize;
                let mut domain_buf = vec![0u8; domain_len + 2];
                stream.read_exact(&mut domain_buf).unwrap();
                let domain = String::from_utf8_lossy(&domain_buf[..domain_len]);
                assert_eq!(domain, "api.example.com");

                // Send success response
                stream.write_all(&[0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 1, 187]).unwrap();
            }
        });

        let mut client_stream = TcpStream::connect(format!("127.0.0.1:{}", port)).expect("connect to socks5");
        assert!(establish_socks5_tunnel(&mut client_stream, "api.example.com", 443).is_ok());

        server.join().unwrap();
    }
}
