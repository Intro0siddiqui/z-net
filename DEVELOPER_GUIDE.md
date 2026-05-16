# Zawra Developer Guide 🛠️

Welcome to the Zawra Networking Stack developer guide. This document provides comprehensive information for contributors and developers working with the Zawra codebase.

## 🏗️ Technical Stack

The Zawra Networking Stack is built using a high-performance native architecture:

- **Zig**: Core performance-critical components (Socket, TLS, DNS, Cache, Event Loop, etc.)
- **Rust**: High-performance protocol handling, async orchestration, and pipeline execution

## 📂 Repository Structure

- `src/`: Source code for all modules
- `tests/`: Comprehensive test suite
- `deployment/`: Production deployment and operations scripts
- `examples/`: Usage examples for various components
- `rust_net/`: Rust-specific networking components

## 🛠️ Development Environment Setup

### Prerequisites

- **Zig 0.12.0+**: [Installation Guide](https://ziglang.org/learn/getting-started/)
- **Rust (latest)**: [Installation Guide](https://www.rust-lang.org/tools/install)

### Initial Setup

```bash
git clone <repository-url>
cd zawra-netstack
./build.sh deps
```

## 🏗️ Build System

We use a custom `build.sh` script to orchestrate the Zig and Rust build process.

- `build.sh build`: Builds all components (Zig and Rust)
- `build.sh clean`: Removes build artifacts
- `build.sh test`: Runs the full test suite
- `build.sh example`: Builds and runs usage examples

## 🧪 Testing Guidelines

- **Unit Tests**: Every module should have comprehensive unit tests.
- **Integration Tests**: Test the interaction between different language components.
- **Performance Benchmarks**: Ensure no regressions in critical paths.

Run tests for a specific module:
```bash
cd src/z_socket
zig test socket.zig
```

## 🤝 Contributing Workflow

1. **Branching**: Use `feature/` or `fix/` prefixes for your branches.
2. **Coding Standards**:
   - **Zig**: Follow the standard Zig style guide (use `zig fmt`).
   - **Rust**: Follow standard Rust idioms (use `cargo fmt`).
3. **Commits**: Use descriptive commit messages.
4. **Pull Requests**: Provide a clear description of changes and link relevant issues.

## 📏 Zig Engineering Rules

All Zig code in the Zawra project must adhere to the following core engineering rules:

### 1. Unified I/O (Zig 0.16+)
Always use the `std.Io` interface for networking, file systems, and timers. This pattern centralizes I/O and uses dependency injection.
**Rule**: All structs or functions performing I/O must accept an `io_ctx: *std.Io` parameter.

### 2. OS-Agnosticism ("1 API, 3 Fast Code Paths")
When implementing OS-specific logic, use compile-time dispatch to provide the fastest native implementation for each platform while maintaining a single public API.
**Rule**: Use `switch (builtin.os.tag)` for compile-time dispatch between Linux, BSD/macOS, and Windows implementations.

## 🧱 Module Development

### Adding a New Zig Module

1. Create a directory in `src/z_<name>`.
2. Implement your logic in `<name>.zig`.
3. Add a `build.zig` if necessary.
4. Export public types in `src/root.zig`.

## 🔍 Debugging Tips

- **Zig**: Use `std.log` for logging.
- **Rust**: Use the `log` crate or `println!`.

## 📚 Documentation

Keep the documentation in sync with your changes:
- Update `README.md` if you add/remove modules.
- Update `API_REFERENCE.md` for public API changes.
- Update `ARCHITECTURE.md` for significant structural changes.

---

*Thank you for contributing to the Zawra Networking Stack!*
