# z-net API Reference 📚

The primary interface for z-net is the `Fetch` API, implemented in Zig. This document describes the public classes, structures, and methods available for browser integration.

## 🚀 z-net Fetch Class

The main entry point for making network requests.

### `__init__(config: Optional[FetchConfig] = None)`
Initializes a new instance of the fetch manager.

### `get(url: Url, options: Optional[FetchOptions] = None) -> FetchResult`
Performs an asynchronous HTTP GET request.

### `post(url: Url, body: ByteArray, options: Optional[FetchOptions] = None) -> FetchResult`
Performs an asynchronous HTTP POST request.

### `put(url: Url, body: ByteArray, options: Optional[FetchOptions] = None) -> FetchResult`
Performs an asynchronous HTTP PUT request.

### `delete(url: Url, options: Optional[FetchOptions] = None) -> FetchResult`
Performs an asynchronous HTTP DELETE request.

### `head(url: Url, options: Optional[FetchOptions] = None) -> FetchResult`
Performs an asynchronous HTTP HEAD request.

### `set_user_agent(user_agent: String)`
Sets the default User-Agent for all subsequent requests.

### `clear_cookies()`
Clears all session cookies.

---

## 🛠️ FetchOptions Struct

Used to configure individual requests.

- `method: String`: HTTP method (default: "GET")
- `headers: Dict[String, String]`: Custom HTTP headers
- `timeout: Optional[Float64]`: Request timeout in seconds
- `cache_mode: CacheMode`: Caching strategy
- `follow_redirects: Bool`: Whether to follow HTTP redirects (default: True)
- `verify_ssl: Bool`: Whether to verify SSL certificates (default: True)
- `body: Optional[ByteArray]`: Request body data

### `set_header(name: String, value: String)`
Adds or updates a request header.

---

## 📄 FetchResult Struct

Contains the response data and metadata.

- `status: Int64`: HTTP status code
- `ok: Bool`: True if status is in the 200-299 range
- `headers: Dict[String, String]`: Response headers
- `body: ByteArray`: Response body data
- `url: String`: The requested URL
- `final_url: String`: The final URL after redirects
- `from_cache: Bool`: True if the response was served from cache
- `timing: FetchTiming`: Detailed timing information

---

## ⏱️ FetchTiming Struct

Provides granular performance metrics.

- `dns_time: Optional[Float64]`: Time spent on DNS resolution
- `connect_time: Optional[Float64]`: Time spent establishing connection
- `handshake_time: Optional[Float64]`: Time spent on TLS handshake
- `transfer_time: Optional[Float64]`: Time spent transferring data
- `total_time: Float64`: Total time from start to completion

---

## ⚙️ FetchConfig Struct

Global configuration for the `znetFetch` instance.

- `enable_caching: Bool`: Global cache toggle
- `cache_ttl: Int64`: Default cache time-to-live
- `max_redirects: Int64`: Maximum number of redirects to follow
- `timeout: Float64`: Default request timeout

---

## 🛠️ Helper Functions

- `quick_fetch(url: Url) -> FetchResult`: Convenience function for simple GET requests.
- `fetch_json(url: Url, options: Optional[FetchOptions] = None) -> Dict[String, String]`: Fetches and parses JSON data.
- `fetch_text(url: Url, options: Optional[FetchOptions] = None) -> String`: Fetches and returns the response as a string.
- `download_file(url: Url, local_path: String, options: Optional[FetchOptions] = None) -> Bool`: Downloads a file to the local disk.

---

## ⚠️ Error Handling

The `FetchResult.ok` property indicates success. If `ok` is `False`, the `error` property will contain a descriptive error message.

Common error scenarios:
- `Invalid URL`: The provided URL is malformed.
- `Connection Timeout`: The request exceeded the specified timeout.
- `DNS Resolution Failed`: Could not resolve the host name.
- `TLS Handshake Failed`: Secure connection could not be established.
