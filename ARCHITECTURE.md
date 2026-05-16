# z-net Architecture 🏗️

z-net is a modular, high-performance system designed for modern web browsers. It employs a multi-language approach to leverage the unique strengths of Zig and Rust.

## 📐 Conceptual Overview

z-net follows a layered architecture where each layer provides specific services to the layer above it.

```
┌─────────────────────────────────────────────────────────┐
│                    z_fetch Public API                   │ (Zig)
├─────────────────────────────────────────────────────────┤
│    z_service_worker  │  z_websocket  │  z_event_loop    │ (Zig)
├─────────────────────────────────────────────────────────┤
│    z_policy (SOP/CORS) │  z_storage (IDB/Cache)         │ (Zig)
├─────────────────────────────────────────────────────────┤
│         z_http3 (QUIC)       │      z_early_hints       │ (Zig)
├─────────────────────────────────────────────────────────┤
│    z_prioritization (H2)     │   z_performance (Opt)    │ (Zig)
├─────────────────────────────────────────────────────────┤
│                 z_pipeline Executor                     │ (Rust)
├─────────────────────────────────────────────────────────┤
│    z_cache (BrowserDB)       │   z_http (H1/H2)         │ (Zig)
├─────────────────────────────────────────────────────────┤
│    z_tls (TLS 1.3)           │   z_dns (DoH/DoT)        │ (Zig)
├─────────────────────────────────────────────────────────┤
│                 z_socket (TCP/UDP I/O)                  │ (Zig)
└─────────────────────────────────────────────────────────┘
```

## 🧩 Core Components

### 1. Foundation Layer (Zig)
- **z_socket**: Low-level TCP/UDP socket management.
- **z_tls**: Implementation of TLS 1.3 using mbedTLS.
- **z_dns**: Multi-protocol resolver supporting UDP, DoH, and DoT.

### ⚖️ Zig Engineering Rules
The foundation layer is built according to strict **Zig Engineering Rules**:
- **Unified I/O**: Centralized I/O management using dependency injection.
- **OS-Agnosticism**: Single public API with compile-time dispatch for Linux, macOS/BSD, and Windows (1 API, 3 Fast Code Paths).

### 2. Protocol Engine (Zig)
- **z_http**: Robust engine for HTTP/1.1 and HTTP/2.
- **z_quic**: Transport layer implementation for QUIC.
- **z_http3**: High-level HTTP/3 implementation over QUIC.

### 3. Orchestration & Execution (Rust)
- **z_pipeline**: The core engine that manages the lifecycle of a request, handling scheduling, retry logic, and concurrent execution.

### 4. Browser Integration (Zig)
- **z_event_loop**: Integrates with the browser's main event loop for non-blocking I/O.
- **z_policy**: Implements browser security models like Same-Origin Policy (SOP), CORS, and Content Security Policy (CSP).
- **z_storage**: Bridge to various browser storage mechanisms including LocalStorage, IndexedDB, and the Cache API.
- **z_service_worker**: Full implementation of the Service Worker lifecycle and interceptors.

### 5. Public Interface (Zig)
- **z_fetch**: Provides a developer-friendly API similar to the Web Fetch API for use within the browser.

## 🔄 Request Lifecycle

1. **API Call**: Developer calls `fetch.get()`.
2. **Policy Check**: `z_policy` validates the request against origin rules.
3. **Pipeline Entry**: Request is handed off to the `z_pipeline` (Rust).
4. **Resolution**: `z_dns` resolves the domain name.
5. **Connection**: `z_socket` and `z_tls` establish a secure connection.
6. **Execution**: The appropriate protocol engine (`z_http` or `z_http3`) sends the request and receives the response.
7. **Caching**: `z_cache` stores the response if applicable.
8. **Completion**: Result is returned to the user via the `z_fetch` interface.

## 🌉 Cross-Language Integration

- **Zig to Rust**: Accomplished through C FFI for performance.
- **Zig Interop**: Modules are linked together as a single library or binary using the Zig build system, ensuring minimal overhead.

## 🛡️ Security Architecture

- **Isolation**: Each module is designed to be as isolated as possible.
- **Validation**: Strict validation of all incoming network data.
- **Encapsulation**: Low-level details are hidden from the high-level API to prevent misuse.

---

*This architecture ensures that z-net is not only fast but also secure and extensible.*
