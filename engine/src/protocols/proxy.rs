//! Proxy support - Rust-side coordinator that reads system proxy
//! settings, executes PAC scripts, and feeds the resolved `ProxyHop`
//! back to the Zig `z_proxy` module over C ABI.
//!
//! The actual TCP tunneling (SOCKS5 / HTTP CONNECT) is performed on the
//! Zig side because it has direct access to the `z_socket::Socket` we
//! are going to wrap. This module just provides the system discovery +
//! PAC evaluation in Rust where the ecosystem (system-configuration
//! crates, etc.) is more mature.

use std::collections::HashMap;
use std::env;
use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int};
use std::sync::Mutex;

/// A `ProxyRule` is the parsed form of a PAC `FindProxyForURL` result.
#[derive(Debug, Clone)]
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

/// Discover proxy config from environment variables. Returns a JSON
/// blob describing the configuration so the Zig side can rebuild a
/// `ProxyConfig` without a deep FFI struct.
#[no_mangle]
pub extern "C" fn znet_proxy_discover_env(out: *mut c_char, out_len: usize) -> c_int {
    if out.is_null() || out_len == 0 {
        return -1;
    }
    let mut buf = String::new();
    for var in &["HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "http_proxy", "https_proxy", "no_proxy"] {
        if let Some(v) = env::var(var).ok() {
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
/// Returns the number of bytes written, or -1 on error.
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
    let mut found: Option<ProxyRule> = None;
    for part in rstr.split(';') {
        let p = part.trim();
        if let Some(rest) = p.strip_prefix("PROXY ") {
            found = parse_host_port(rest, ProxyScheme::Http);
        } else if let Some(rest) = p.strip_prefix("SOCKS5 ") {
            found = parse_host_port(rest, ProxyScheme::Socks5);
        } else if let Some(rest) = p.strip_prefix("SOCKS4 ") {
            found = parse_host_port(rest, ProxyScheme::Socks4);
        } else if p == "DIRECT" {
            found = Some(ProxyRule { scheme: ProxyScheme::Direct, host: String::new(), port: 0 });
        }
    }
    match found {
        Some(rule) => {
            let host_c = CString::new(rule.host).unwrap();
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
        }
        None => -1,
    }
}

fn parse_host_port(s: &str, scheme: ProxyScheme) -> Option<ProxyRule> {
    let s = s.trim();
    let colon = s.rfind(':')?;
    let host = s[..colon].to_string();
    let port: u16 = s[colon + 1..].parse().ok()?;
    Some(ProxyRule { scheme, host, port })
}

/// Tiny PAC interpreter. Mirrors the Zig `PacEngine` so behavior stays
/// in sync if either side is extended.
fn evaluate_minimal(src: &str, url: &str, host: &str) -> Option<String> {
    let marker = "FindProxyForURL";
    let idx = src.find(marker)?;
    let body_start = src[idx..].find('{')?;
    let body_with_brace = &src[idx + body_start..];
    let end = match_brace(body_with_brace)?;
    let body = &body_with_brace[1..end];

    let mut last_return: Option<String> = None;
    let mut pos = 0;
    while pos < body.len() {
        let rest = &body[pos..];
        let s = rest.trim_start();
        let skipped = rest.len() - s.len();
        pos += skipped;

        if s.starts_with("return ") {
            let semi = body[pos..].find(';').unwrap_or(body[pos..].len());
            let stmt = &body[pos..pos + semi];
            let after = stmt["return ".len()..].trim();
            let v = after.trim_matches('"');
            last_return = Some(v.to_string());
            pos += semi + 1;
        } else if s.starts_with("if ") {
            let cond_end = s.find('{')?;
            let cond = s["if ".len()..cond_end].trim();
            let matched = eval_cond(cond, url, host);
            pos += skipped + cond_end;
            let block_with_brace = &body[pos..];
            let close = match_brace(block_with_brace)?;
            if matched {
                let block = &block_with_brace[1..close];
                if let Some(ret_off) = block.find("return ") {
                    let ret_stmt = &block[ret_off..];
                    let semi = ret_stmt.find(';').unwrap_or(ret_stmt.len());
                    let stmt = &ret_stmt[..semi];
                    let v = stmt["return ".len()..].trim().trim_matches('"');
                    last_return = Some(v.to_string());
                }
            }
            pos += close + 1;
        } else {
            if let Some(semi) = body[pos..].find(';') {
                pos += semi + 1;
            } else {
                break;
            }
        }
    }
    last_return
}

fn eval_cond(cond: &str, _url: &str, host: &str) -> bool {
    let cond = cond.trim().trim_end_matches('{').trim();
    if let Some(rest) = cond.strip_prefix("isPlainHostName(") {
        let arg = rest.trim_end_matches(')').trim_matches('"');
        return !arg.contains('.');
    }
    if let Some(rest) = cond.strip_prefix("dnsDomainIs(") {
        let inside = rest.trim_end_matches(')');
        let parts: Vec<&str> = inside.split(',').collect();
        if parts.len() >= 2 {
            return host.ends_with(parts[1].trim().trim_matches('"'));
        }
    }
    if let Some(rest) = cond.strip_prefix("shExpMatch(") {
        let inside = rest.trim_end_matches(')');
        let parts: Vec<&str> = inside.split(',').collect();
        if parts.len() >= 2 {
            return glob_match(parts[1].trim().trim_matches('"'), parts[0].trim().trim_matches('"'));
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

fn glob_match(pattern: &str, s: &str) -> bool {
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
        } else if p < pat.len() && (pat[p] == '?' || pat[p] == str[si]) {
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

// Suppress unused-import warning when building for non-test targets.
#[allow(dead_code)]
fn _suppress_unused() {
    let _ = Mutex::new(HashMap::<String, String>::new());
}
