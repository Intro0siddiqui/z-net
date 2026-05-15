# Quick Start Guide 🚀

Get up and running with the Zawra Networking Stack in 5 minutes!

## Prerequisites

Make sure you have these installed:

```bash
# Check your versions
zig version      # Should be 0.11+
mojo --version   # Latest
rustc --version  # Latest
```

## 1. Clone & Build

```bash
git clone <repository-url>
cd zawra-netstack

# Build everything
./build.sh build

# Verify build by running tests
./build.sh test
```

## 2. Your First Request (Zig)

Create `hello_world.zig`:

```zig
const std = @import("std");
const zawra = @import("zawra_netstack");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    
    // Initialize the stack
    try zawra.init(allocator);
    
    // ZawraFetch is primarily a Mojo API,
    // for Zig usage we use the underlying modules or the bridge.
    var engine = try zawra.NetworkEngine.init(allocator);
    defer engine.deinit();
    
    const result = try engine.get("https://httpbin.org/get");
    std.log.info("Status: {d}", .{result.status});
}
```

## 3. Your First Request (Mojo)

Create `hello_world.mojo`:

```python
from zawra_netstack import ZawraFetch, FetchOptions

def main():
    # Initialize ZawraFetch
    var fetch = ZawraFetch()
    
    # Simple GET request
    var result = fetch.get("https://httpbin.org/get")
    
    if result.ok:
        print("Status Code: ", result.status)
        # Body is a ByteArray, convert to string for printing
        print("Response Body: ", "".join([chr(b) for b in result.body]))
    else:
        print("Error: ", result.error)
```

## 4. Advanced Mojo Usage (Headers & POST)

```python
from zawra_netstack import ZawraFetch, FetchOptions

def main():
    var fetch = ZawraFetch()
    
    # Configure options
    var options = FetchOptions()
    options.set_header("Content-Type", "application/json")
    options.set_timeout(10.0)
    
    # POST request with JSON body
    var body = '{"name": "Zawra", "version": "1.0"}'.encode("utf-8")
    var result = fetch.post("https://httpbin.org/post", body, options)
    
    if result.ok:
        print("POST Successful!")
        print("Final URL: ", result.final_url)
```

## 5. Caching & Performance

```python
from zawra_netstack import ZawraFetch, FetchOptions

def main():
    var fetch = ZawraFetch()
    var options = FetchOptions()
    
    # Enable caching for this request
    options.enable_caching()
    
    # First request - Fetch from network
    var result1 = fetch.get("https://httpbin.org/get", options)
    print("From Cache: ", result1.from_cache) # False
    
    # Second request - Served from local z_cache
    var result2 = fetch.get("https://httpbin.org/get", options)
    print("From Cache: ", result2.from_cache) # True
```

## 📚 Next Steps

- Read [DEVELOPER_GUIDE.md](DEVELOPER_GUIDE.md) for advanced usage.
- Check [API_REFERENCE.md](API_REFERENCE.md) for complete API documentation.
- See [ARCHITECTURE.md](ARCHITECTURE.md) for a deep dive into how Zawra works.

---

**Ready to build something amazing? 🎉**
