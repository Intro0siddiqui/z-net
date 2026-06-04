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
        let host_c = CString::new(host).unwrap();
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
        let host_c = CString::new(host).unwrap();
        let mut hi: u64 = 0;
        let mut lo: u64 = 0;
        let parts: Vec<&str> = cookie_str.split(';').collect();
        if parts.is_empty() { return; }
        let kv: Vec<&str> = parts[0].split('=').collect();
        if kv.len() < 2 { return; }
        let name = CString::new(kv[0].trim()).unwrap();
        let value = CString::new(kv[1].trim()).unwrap();
        unsafe {
            Zawra_Hash_String(host_c.as_ptr(), &mut hi, &mut lo);
            Zawra_Cookie_Put(hi, lo, name.as_ptr(), value.as_ptr(), 0, 0);
        }
    }

    pub fn record_history(&self, url: &Url, title: &str) {
        let url_str = url.as_str();
        let url_c = CString::new(url_str).unwrap();
        let title_c = CString::new(title).unwrap();
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
