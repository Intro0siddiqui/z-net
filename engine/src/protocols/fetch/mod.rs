use url::Url;
use std::ffi::{CString, CStr};
use std::os::raw::c_char;
use std::collections::HashMap;

extern "C" {
    fn Zawra_Hash_String(input: *const c_char, out_hi: *mut u64, out_lo: *mut u64);
    fn Zawra_Cookie_GetForDomain(hi: u64, lo: u64, out: *mut c_char, len: usize) -> i32;
    fn Zawra_Cookie_Put(hi: u64, lo: u64, name: *const c_char, value: *const c_char, expiry: u64, flags: u8) -> i32;
    fn Zawra_History_Put(hi: u64, lo: u64, url: *const c_char, title: *const c_char, ts: u64) -> i32;
}

pub struct SmartMiddleware;

impl SmartMiddleware {
    pub fn inject_cookies(&self, url: &Url) -> String {
        let host = match url.host_str() {
            Some(h) => h,
            None => return String::new(),
        };
        let host_c = match CString::new(host) {
            Ok(c) => c,
            Err(_) => return String::new(),
        };
        let mut hi: u64 = 0;
        let mut lo: u64 = 0;
        unsafe {
            Zawra_Hash_String(host_c.as_ptr(), &mut hi, &mut lo);
            let mut buf = vec![0u8; 4096];
            let ret = Zawra_Cookie_GetForDomain(hi, lo, buf.as_mut_ptr() as *mut c_char, buf.len());
            if ret == 0 {
                return CStr::from_ptr(buf.as_ptr() as *const c_char).to_string_lossy().into_owned();
            }
        }
        String::new()
    }

    pub fn store_cookie(&self, url: &Url, cookie_str: &str) {
        let host = match url.host_str() {
            Some(h) => h,
            None => return,
        };
        let host_c = match CString::new(host) {
            Ok(c) => c,
            Err(_) => return,
        };
        let mut hi: u64 = 0;
        let mut lo: u64 = 0;
        let parts: Vec<&str> = cookie_str.split(';').collect();
        if parts.is_empty() { return; }
        let kv: Vec<&str> = parts[0].split('=').collect();
        if kv.len() < 2 { return; }
        let name = match CString::new(kv[0].trim()) {
            Ok(c) => c,
            Err(_) => return,
        };
        let value = match CString::new(kv[1].trim()) {
            Ok(c) => c,
            Err(_) => return,
        };
        unsafe {
            Zawra_Hash_String(host_c.as_ptr(), &mut hi, &mut lo);
            Zawra_Cookie_Put(hi, lo, name.as_ptr(), value.as_ptr(), 0, 0);
        }
    }

    pub fn record_history(&self, url: &Url, title: &str) {
        let url_str = url.as_str();
        let url_c = match CString::new(url_str) {
            Ok(c) => c,
            Err(_) => return,
        };
        let title_c = match CString::new(title) {
            Ok(c) => c,
            Err(_) => return,
        };
        let mut hi: u64 = 0;
        let mut lo: u64 = 0;
        unsafe {
            Zawra_Hash_String(url_c.as_ptr(), &mut hi, &mut lo);
            let ts = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            Zawra_History_Put(hi, lo, url_c.as_ptr(), title_c.as_ptr(), ts);
        }
    }
}

pub struct FetchEngine {
    pub request_headers: HashMap<String, String>,
    pub middleware: SmartMiddleware,
}

impl FetchEngine {
    pub fn new() -> Self {
        Self {
            request_headers: HashMap::new(),
            middleware: SmartMiddleware,
        }
    }

    pub fn fetch(&mut self, url: Url) {
        self.request_headers.clear();

        let cookies = self.middleware.inject_cookies(&url);
        if !cookies.is_empty() {
            self.request_headers.insert("Cookie".to_string(), cookies);
        }

        // Cookie Storage from simulated response
        self.middleware.store_cookie(&url, "session_id=12345; Path=/; HttpOnly");

        // History Recording
        self.middleware.record_history(&url, "Zawra Browser Page");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[no_mangle]
    extern "C" fn Zawra_Hash_String(_input: *const c_char, out_hi: *mut u64, out_lo: *mut u64) {
        unsafe {
            *out_hi = 1;
            *out_lo = 2;
        }
    }

    #[no_mangle]
    extern "C" fn Zawra_Cookie_GetForDomain(_hi: u64, _lo: u64, _out: *mut c_char, _len: usize) -> i32 {
        -1
    }

    #[no_mangle]
    extern "C" fn Zawra_Cookie_Put(_hi: u64, _lo: u64, _name: *const c_char, _value: *const c_char, _expiry: u64, _flags: u8) -> i32 {
        0
    }

    #[no_mangle]
    extern "C" fn Zawra_History_Put(_hi: u64, _lo: u64, _url: *const c_char, _title: *const c_char, _ts: u64) -> i32 {
        0
    }

    #[test]
    fn test_store_cookie_with_nul_bytes_does_not_panic() {
        let mw = SmartMiddleware;
        let url = Url::parse("https://example.com/test").unwrap();
        // Embedded NUL in name
        mw.store_cookie(&url, "user\0name=alice; Path=/");
        // Embedded NUL in value
        mw.store_cookie(&url, "session=secret\0token; Path=/");
        // Empty or malformed parts
        mw.store_cookie(&url, "");
        mw.store_cookie(&url, "invalid_cookie_without_equals");
    }

    #[test]
    fn test_record_history_with_nul_bytes_does_not_panic() {
        let mw = SmartMiddleware;
        let url = Url::parse("https://example.com/page").unwrap();
        // Embedded NUL in title
        mw.record_history(&url, "Zawra\0Browser Page");
    }
}
