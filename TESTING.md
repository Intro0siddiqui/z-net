# Zawra Testing Framework 🧪

The Zawra Networking Stack employs a multi-tiered testing strategy to ensure reliability, performance, and security across all supported platforms and protocols.

## 📂 Test Organization

Tests are located in the `tests/` directory and within individual module directories.

- `tests/main_test_runner.zig`: The central orchestrator for all tests.
- `tests/protocol_compliance.zig`: Ensures adherence to RFC standards (HTTP/1.1, HTTP/2, QUIC, etc.).
- `tests/performance_benchmarks.zig`: Measures latency, throughput, and resource usage.
- `tests/security_validation.zig`: Tests for SOP, CORS, CSP enforcement, and TLS vulnerabilities.
- `tests/cross_platform.mojo`: Verifies functionality across Linux, macOS, and Windows.
- `tests/load_testing.zig`: Stress tests the stack with high volumes of concurrent requests.

## 🚀 Running Tests

### Full Test Suite
```bash
./build.sh test
```

### Module-Specific Tests
```bash
cd src/z_socket
zig test socket.zig
```

### Performance Benchmarks
```bash
./build.sh benchmark
```

## 🛠️ Testing Tools

- **Zig Test**: Native Zig testing framework for unit tests.
- **Cargo Test**: For testing Rust components in `z_pipeline`.
- **Mojo**: Used for high-level integration and cross-platform verification tests.

## 📈 Quality Gates

A contribution is considered ready for merge only if:
1. All unit tests pass.
2. All integration tests pass.
3. Protocol compliance is verified.
4. No performance regressions are detected (within 5% margin).
5. Security validation passes without warnings.

## 🔍 CI/CD Integration

The file `tests/cicd_integration.zig` contains the logic for running the Zawra test suite within various CI environments (GitHub Actions, GitLab CI, etc.).

---

*For more details on contributing tests, see the [Developer Guide](DEVELOPER_GUIDE.md).*
