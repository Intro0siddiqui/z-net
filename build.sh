#!/usr/bin/env bash

# Zawra Networking Stack Build System
# Cross-platform build automation

set -e

# Configuration
PROJECT_NAME="zawra-netstack"
VERSION="1.1.0"
BUILD_DIR="build"
SOURCE_DIR="src"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Utility functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Platform detection
detect_platform() {
    case "$(uname -s)" in
        Linux*)     PLATFORM="linux";;
        Darwin*)    PLATFORM="macos";;
        CYGWIN*|MINGW*|MSYS*) PLATFORM="windows";;
        *)          PLATFORM="unknown";;
    esac
    echo $PLATFORM
}

# Architecture detection
detect_arch() {
    ARCH=$(uname -m)
    case $ARCH in
        x86_64)    ARCH="x86_64";;
        aarch64)   ARCH="aarch64";;
        armv7l)    ARCH="arm";;
        *)         ARCH="unknown";;
    esac
    echo $ARCH
}

# Check dependencies
check_dependencies() {
    log_info "Checking dependencies..."
    
    # Check Zig
    if ! command -v zig &> /dev/null; then
        log_error "Zig not found. Please install Zig 0.12.0 or later."
        exit 1
    fi
    
    ZIG_VERSION=$(zig version | head -n 1)
    log_info "Using Zig: $ZIG_VERSION"
    
    # Check Rust
    if ! command -v rustc &> /dev/null; then
        log_error "Rust not found. Please install Rust."
        exit 1
    fi
    
    RUST_VERSION=$(rustc --version | head -n 1)
    log_info "Using Rust: $RUST_VERSION"
}

# Build system
build() {
    log_info "Building Zawra Networking Stack..."
    zig build || {
        log_error "Zig build failed"
        exit 1
    }
    log_success "Build completed successfully"
}

# Run tests
run_tests() {
    log_info "Running tests..."
    zig build test || {
        log_warning "Tests failed"
    }
    log_success "Tests completed"
}

# Run examples
run_examples() {
    log_info "Running examples..."
    zig build example || {
        log_warning "Examples failed"
    }
    log_success "Examples completed"
}

# Benchmarking
run_benchmarks() {
    log_info "Running benchmarks..."
    zig build benchmark || {
        log_warning "Benchmarks failed"
    }
    log_success "Benchmarks completed"
}

# Clean build artifacts
clean() {
    log_info "Cleaning build artifacts..."
    rm -rf zig-out
    rm -rf .zig-cache
    rm -rf $BUILD_DIR
    log_success "Cleaned build artifacts"
}

# Create release package
package() {
    log_info "Creating release package..."
    
    mkdir -p $BUILD_DIR
    
    # Build first
    build
    
    # Copy binaries from zig-out
    if [ -d "zig-out/bin" ]; then
        cp -r zig-out/bin $BUILD_DIR/
    fi
    
    if [ -d "zig-out/lib" ]; then
        cp -r zig-out/lib $BUILD_DIR/
    fi
    
    # Copy documentation
    cp README.md $BUILD_DIR/
    cp QUICKSTART.md $BUILD_DIR/
    
    # Create package info
    cat > $BUILD_DIR/PACKAGE_INFO << EOF
Zawra Networking Stack v$VERSION
Platform: $PLATFORM-$ARCH
Build Date: $(date)
Components:
- z_socket (Zig)
- z_tls (Zig)
- z_dns (Zig)
- z_http (Zig)
- z_quic (Zig)
- z_http3 (Zig)
- z_cache (Zig)
- z_pipeline (Rust)
- z_fetch (Zig)
- z_security (Zig)
- z_monitoring (Zig)
- z_event_loop (Zig)
- z_policy (Zig)
- z_storage (Zig)
- z_websocket (Zig)
- z_service_worker (Zig)

Usage:
Check QUICKSTART.md for usage instructions.
EOF
    
    # Create tarball
    tar -czf $PROJECT_NAME-$VERSION-$PLATFORM-$ARCH.tar.gz -C $BUILD_DIR .
    
    log_success "Package created: $PROJECT_NAME-$VERSION-$PLATFORM-$ARCH.tar.gz"
}

# Help function
show_help() {
    echo "Zawra Networking Stack Build System"
    echo ""
    echo "Usage: $0 [COMMAND]"
    echo ""
    echo "Commands:"
    echo "  build       Build all components (via zig build)"
    echo "  clean       Clean build artifacts"
    echo "  test        Run tests"
    echo "  example     Run examples"
    echo "  benchmark   Run benchmarks"
    echo "  package     Create release package"
    echo "  deps        Check dependencies"
    echo "  help        Show this help message"
}

# Main function
main() {
    local command=${1:-build}
    
    # Detect platform
    PLATFORM=$(detect_platform)
    ARCH=$(detect_arch)
    
    case $command in
        deps)
            check_dependencies
            ;;
        build)
            check_dependencies
            build
            ;;
        clean)
            clean
            ;;
        test)
            check_dependencies
            run_tests
            ;;
        example)
            check_dependencies
            run_examples
            ;;
        benchmark)
            check_dependencies
            run_benchmarks
            ;;
        package)
            check_dependencies
            package
            ;;
        help|--help|-h)
            show_help
            ;;
        *)
            log_error "Unknown command: $command"
            show_help
            exit 1
            ;;
    esac
}

# Run main function
main "$@"
