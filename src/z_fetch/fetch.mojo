# z_fetch - Public API Layer
# High-level fetch interface for Zawra browser integration

from .z_socket import Socket
from .z_tls import TlsManager
from .z_dns import DnsResolver, DnsCache
from .z_http import Http1Client, Http2Client
from .z_cache import HttpCache, DnsCache, CookieCache
from .z_pipeline import Pipeline, PipelineConfig, RequestOptions
from collections import Dict
from typing import Optional, List
import time
import json

# Public API Types
alias Url = String
alias ByteArray = List[UInt8]

struct FetchOptions:
    var method: String
    var headers: Dict[String, String]
    var timeout: Optional[Float64] = None
    var cache_mode: CacheMode
    var follow_redirects: Bool = True
    var verify_ssl: Bool = True
    var max_redirects: Int64 = 5
    var body: Optional[ByteArray] = None
    var cookies: Optional[Dict[String, String]] = None
    var proxy: Optional[String] = None
    var allow_redirects: Bool = True
    var max_content_length: Optional[Int64] = None

    fn __init__(inout self):
        self.method = "GET"
        self.headers = Dict[String, String]()
        self.cache_mode = CacheMode.Default
        self.follow_redirects = True
        self.verify_ssl = True
        self.max_redirects = 5
        self.body = None
        self.cookies = None
        self.proxy = None
        self.allow_redirects = True
        self.max_content_length = None

    fn set_header(inout self, name: String, value: String):
        self.headers[name] = value

    fn set_body(inout self, body: ByteArray):
        self.body = body

    fn set_timeout(inout self, timeout_seconds: Float64):
        self.timeout = timeout_seconds

    fn enable_caching(inout self):
        self.cache_mode = CacheMode.Default

    fn disable_caching(inout self):
        self.cache_mode = CacheMode.NoCache

    fn set_cache_mode(inout self, mode: CacheMode):
        self.cache_mode = mode

struct FetchResult:
    var status: Int64
    var headers: Dict[String, String]
    var body: ByteArray
    var url: String
    var final_url: String
    var ok: Bool
    var redirected: Bool
    var history: List[String]
    var content_type: Optional[String] = None
    var content_length: Optional[Int64] = None
    var from_cache: Bool = False
    var cache_hit: Bool = False
    var timing: FetchTiming
    var error: Optional[String] = None

    fn __init__(inout self):
        self.status = 200
        self.headers = Dict[String, String]()
        self.body = ByteArray()
        self.url = ""
        self.final_url = ""
        self.ok = True
        self.redirected = False
        self.history = List[String]()
        self.content_type = None
        self.content_length = None
        self.from_cache = False
        self.cache_hit = False
        self.timing = FetchTiming()
        self.error = None

struct FetchTiming:
    var start_time: Float64
    var dns_time: Optional[Float64] = None
    var connect_time: Optional[Float64] = None
    var handshake_time: Optional[Float64] = None
    var transfer_time: Optional[Float64] = None
    var total_time: Float64

    fn __init__(inout self):
        self.start_time = time.time()
        self.total_time = 0.0

    fn mark_complete(inout self):
        self.total_time = time.time() - self.start_time

    fn set_dns_time(inout self, dns_time: Float64):
        self.dns_time = dns_time

    fn set_connect_time(inout self, connect_time: Float64):
        self.connect_time = connect_time

    fn set_handshake_time(inout self, handshake_time: Float64):
        self.handshake_time = handshake_time

    fn set_transfer_time(inout self, transfer_time: Float64):
        self.transfer_time = transfer_time

enum CacheMode:
    Default
    ForceCache
    NoCache
    Revalidate

# High-level Fetch Manager
class ZawraFetch:
    var config: FetchConfig
    var pipeline: Pipeline
    var http_cache: HttpCache
    var dns_cache: DnsCache
    var cookie_cache: CookieCache
    var session_cookies: Dict[String, String]
    var user_agent: String = "Zawra/1.0 (Browser)"
    var default_headers: Dict[String, String]
    var timeout_default: Float64 = 30.0

    def __init__(inout self, config: Optional[FetchConfig] = None):
        if config is None:
            config = FetchConfig()
        
        self.config = config
        self.pipeline = Pipeline(config.pipeline_config)
        self.http_cache = HttpCache()
        self.dns_cache = DnsCache()
        self.cookie_cache = CookieCache()
        self.session_cookies = Dict[String, String]()
        self.default_headers = Dict[String, String]()
        self._setup_default_headers()

    def _setup_default_headers(inout self):
        self.default_headers["User-Agent"] = self.user_agent
        self.default_headers["Accept"] = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
        self.default_headers["Accept-Language"] = "en-US,en;q=0.5"
        self.default_headers["Accept-Encoding"] = "gzip, deflate"
        self.default_headers["Connection"] = "keep-alive"
        self.default_headers["Upgrade-Insecure-Requests"] = "1"

    fn fetch(inout self, url: Url, options: Optional[FetchOptions] = None) -> FetchResult:
        var fetch_options = options if options is not None else FetchOptions()
        return self._fetch_with_options(url, fetch_options)

    fn get(inout self, url: Url, options: Optional[FetchOptions] = None) -> FetchResult:
        var fetch_options = options if options is not None else FetchOptions()
        fetch_options.method = "GET"
        return self._fetch_with_options(url, fetch_options)

    fn post(inout self, url: Url, body: ByteArray, options: Optional[FetchOptions] = None) -> FetchResult:
        var fetch_options = options if options is not None else FetchOptions()
        fetch_options.method = "POST"
        fetch_options.set_body(body)
        return self._fetch_with_options(url, fetch_options)

    fn put(inout self, url: Url, body: ByteArray, options: Optional[FetchOptions] = None) -> FetchResult:
        var fetch_options = options if options is not None else FetchOptions()
        fetch_options.method = "PUT"
        fetch_options.set_body(body)
        return self._fetch_with_options(url, fetch_options)

    fn delete(inout self, url: Url, options: Optional[FetchOptions] = None) -> FetchResult:
        var fetch_options = options if options is not None else FetchOptions()
        fetch_options.method = "DELETE"
        return self._fetch_with_options(url, fetch_options)

    fn head(inout self, url: Url, options: Optional[FetchOptions] = None) -> FetchResult:
        var fetch_options = options if options is not None else FetchOptions()
        fetch_options.method = "HEAD"
        return self._fetch_with_options(url, fetch_options)

    fn _fetch_with_options(inout self, url: Url, options: FetchOptions) -> FetchResult:
        var timing = FetchTiming()
        var result = FetchResult()
        
        try:
            # Validate URL
            if not self._is_valid_url(url):
                result.ok = False
                result.error = "Invalid URL: " + url
                result.status = 0
                timing.mark_complete()
                result.timing = timing
                return result

            result.url = url

            # Apply default headers
            for name, value in self.default_headers.items():
                if name not in options.headers:
                    options.headers[name] = value

            # Add session cookies
            if options.cookies is None:
                options.cookies = Dict[String, String]()
            
            for name, value in self.session_cookies.items():
                if name not in options.cookies:
                    options.cookies[name] = value

            # Convert cookies to header format
            if options.cookies is not None and len(options.cookies) > 0:
                cookie_str = ""
                for name, value in options.cookies.items():
                    if len(cookie_str) > 0:
                        cookie_str += "; "
                    cookie_str += name + "=" + value
                options.headers["Cookie"] = cookie_str

            # Set default timeout
            timeout_duration = options.timeout if options.timeout is not None else self.timeout_default
            options.timeout = timeout_duration

            # Execute request through pipeline
            pipeline_result = self.pipeline.fetch(url, self._convert_to_pipeline_options(options))
            
            if pipeline_result.is_ok():
                var response = pipeline_result.value()
                
                # Convert pipeline response to fetch result
                result.status = response.status_code
                result.headers = response.headers
                result.body = response.body
                result.final_url = response.final_url
                result.redirected = len(response.redirects) > 0
                result.history = response.redirects
                result.from_cache = response.from_cache
                result.cache_hit = response.cache_hit
                
                # Parse timing information
                if response.dns_time is not None:
                    timing.set_dns_time(response.dns_time.total_seconds())
                if response.connection_time is not None:
                    timing.set_connect_time(response.connection_time.total_seconds())
                if response.handshake_time is not None:
                    timing.set_handshake_time(response.handshake_time.total_seconds())
                if response.transfer_time is not None:
                    timing.set_transfer_time(response.transfer_time.total_seconds())
                
                # Extract useful headers
                if "Content-Type" in response.headers:
                    result.content_type = response.headers["Content-Type"]
                if "Content-Length" in response.headers:
                    try:
                        result.content_length = int(response.headers["Content-Length"])
                    except:
                        pass
                
                # Update session cookies
                self._update_session_cookies(response.headers, result.final_url)
                
            else:
                result.ok = False
                result.error = pipeline_result.error()
                result.status = 0

        except Exception as e:
            result.ok = False
            result.error = str(e)
            result.status = 0

        timing.mark_complete()
        result.timing = timing
        return result

    fn _convert_to_pipeline_options(inout self, options: FetchOptions) -> RequestOptions:
        var pipeline_options = RequestOptions()
        pipeline_options.method = options.method
        pipeline_options.headers = options.headers
        pipeline_options.timeout = options.timeout
        pipeline_options.cache_mode = self._convert_cache_mode(options.cache_mode)
        pipeline_options.follow_redirects = options.follow_redirects
        pipeline_options.verify_ssl = options.verify_ssl
        pipeline_options.max_redirects = options.max_redirects
        return pipeline_options

    fn _convert_cache_mode(inout self, cache_mode: CacheMode) -> CacheMode:
        match cache_mode:
            case CacheMode.Default:
                return CacheMode.Default
            case CacheMode.ForceCache:
                return CacheMode.ForceCache
            case CacheMode.NoCache:
                return CacheMode.NoCache
            case CacheMode.Revalidate:
                return CacheMode.Revalidate
            case _:
                return CacheMode.Default

    fn _is_valid_url(inout self, url: Url) -> Bool:
        # Basic URL validation
        if url.length() == 0:
            return False
        
        # Check for valid scheme
        if url.startswith("http://") or url.startswith("https://") or url.startswith("ftp://"):
            return True
        
        # Try to parse as URL
        try:
            parsed = url.parse()
            return parsed.is_ok()
        except:
            return False

    fn _update_session_cookies(inout self, headers: Dict[String, String], url: String):
        # Extract Set-Cookie headers
        if "Set-Cookie" in headers:
            cookie_header = headers["Set-Cookie"]
            
            # Simple cookie parsing
            var cookie_parts = cookie_header.split(";")
            if len(cookie_parts) > 0:
                var name_value = cookie_parts[0].split("=", 1)
                if len(name_value) == 2:
                    name = name_value[0].strip()
                    value = name_value[1].strip()
                    
                    # Check for cookie attributes
                    var secure = False
                    var http_only = False
                    
                    for part in cookie_parts[1:]:
                        if "Secure" in part:
                            secure = True
                        elif "HttpOnly" in part:
                            http_only = True
                    
                    # Only set session cookie if not secure (for HTTPS) or if URL is HTTPS
                    if not secure or url.startswith("https://"):
                        self.session_cookies[name] = value

    fn get_cookies(inout self, domain: String) -> Dict[String, String]:
        var domain_cookies = Dict[String, String]()
        
        for name, value in self.session_cookies.items():
            # Simple domain matching
            if domain.endswith(name) or name in domain:
                domain_cookies[name] = value
        
        return domain_cookies

    fn clear_cookies(inout self):
        self.session_cookies = Dict[String, String]()

    fn set_user_agent(inout self, user_agent: String):
        self.user_agent = user_agent
        self.default_headers["User-Agent"] = user_agent

    fn add_header(inout self, name: String, value: String):
        self.default_headers[name] = value

    fn remove_header(inout self, name: String):
        if name in self.default_headers:
            del self.default_headers[name]

    fn set_timeout(inout self, timeout_seconds: Float64):
        self.timeout_default = timeout_seconds

    fn enable_redirects(inout self):
        self.default_headers["Follow-Redirects"] = "true"

    fn disable_redirects(inout self):
        self.default_headers["Follow-Redirects"] = "false"

    fn get_timing(inout self, result: FetchResult) -> FetchTiming:
        return result.timing

    fn print_timing(inout self, result: FetchResult):
        var timing = result.timing
        print("Request timing for", result.url)
        print("  Total time: {:.3f}s".format(timing.total_time))
        
        if timing.dns_time is not None:
            print("  DNS resolution: {:.3f}s".format(timing.dns_time))
        
        if timing.connect_time is not None:
            print("  Connection: {:.3f}s".format(timing.connect_time))
        
        if timing.handshake_time is not None:
            print("  TLS handshake: {:.3f}s".format(timing.handshake_time))
        
        if timing.transfer_time is not None:
            print("  Data transfer: {:.3f}s".format(timing.transfer_time))
        
        if result.from_cache:
            print("  Served from cache")
        elif result.cache_hit:
            print("  Cache hit")
        else:
            print("  Fresh request")

    fn batch_fetch(inout self, urls: List[Url], options: Optional[FetchOptions] = None) -> List[FetchResult]:
        var results = List[FetchResult]()
        
        for url in urls:
            result = self.get(url, options)
            results.append(result)
        
        return results

    fn prefetch(inout self, urls: List[Url], options: Optional[FetchOptions] = None):
        # Prefetch URLs in background
        # This would be implemented as async in real usage
        for url in urls:
            self.get(url, options)

# Configuration structures
struct FetchConfig:
    var pipeline_config: PipelineConfig
    var enable_caching: Bool = True
    var cache_ttl: Int64 = 300
    var max_redirects: Int64 = 5
    var verify_ssl: Bool = True
    var follow_redirects: Bool = True
    var user_agent: String = "Zawra/1.0"
    var default_headers: Dict[String, String]
    var proxy: Optional[String] = None
    var timeout: Float64 = 30.0
    var max_content_length: Int64 = 50 * 1024 * 1024  # 50MB

    fn __init__(inout self):
        self.pipeline_config = PipelineConfig()
        self.default_headers = Dict[String, String]()
        self._setup_defaults()

    fn _setup_defaults(inout self):
        self.default_headers["User-Agent"] = self.user_agent
        self.default_headers["Accept"] = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
        self.default_headers["Accept-Language"] = "en-US,en;q=0.5"
        self.default_headers["Accept-Encoding"] = "gzip, deflate"
        self.default_headers["Connection"] = "keep-alive"

# Helper functions for common usage patterns
fn quick_fetch(url: Url) -> FetchResult:
    var fetch = ZawraFetch()
    return fetch.get(url)

fn fetch_json(url: Url, options: Optional[FetchOptions] = None) -> Dict[String, String]:
    var fetch_options = options if options is not None else FetchOptions()
    fetch_options.set_header("Accept", "application/json")
    
    var fetch = ZawraFetch()
    var result = fetch.get(url, fetch_options)
    
    if result.ok and result.content_type is not None and "json" in result.content_type:
        try:
            return json.loads("".join([chr(b) for b in result.body]))
        except:
            pass
    
    return Dict[String, String]()

fn fetch_text(url: Url, options: Optional[FetchOptions] = None) -> String:
    var fetch_options = options if options is not None else FetchOptions()
    fetch_options.set_header("Accept", "text/html,text/plain,*/*")
    
    var fetch = ZawraFetch()
    var result = fetch.get(url, fetch_options)
    
    if result.ok:
        return "".join([chr(b) for b in result.body])
    
    return ""

fn download_file(url: Url, local_path: String, options: Optional[FetchOptions] = None) -> Bool:
    var fetch_options = options if options is not None else FetchOptions()
    
    var fetch = ZawraFetch()
    var result = fetch.get(url, fetch_options)
    
    if result.ok:
        # Write to file (simplified)
        try:
            with open(local_path, "wb") as f:
                for byte in result.body:
                    f.write(byte)
            return True
        except:
            pass
    
    return False

# Usage examples
fn example_usage():
    # Basic usage
    var result = quick_fetch("https://example.com")
    print("Status:", result.status)
    print("OK:", result.ok)
    
    # With options
    var options = FetchOptions()
    options.set_timeout(10.0)
    options.set_header("Custom-Header", "value")
    
    var fetch = ZawraFetch()
    result = fetch.get("https://httpbin.org/headers", options)
    
    # JSON API
    var json_data = fetch_json("https://httpbin.org/json")
    print("JSON data:", json_data)
    
    # POST request
    var body = "Hello, Zawra!".encode("utf-8")
    result = fetch.post("https://httpbin.org/post", body)
    print("POST result status:", result.status)
    
    # Batch requests
    var urls = List[Url]("https://httpbin.org/delay/1", "https://httpbin.org/delay/2")
    var results = fetch.batch_fetch(urls)
    
    # Timing information
    if len(results) > 0:
        fetch.print_timing(results[0])