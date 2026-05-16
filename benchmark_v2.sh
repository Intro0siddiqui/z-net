#!/bin/bash

# Configuration
ITERATIONS=10000
PORT=8080
ZIG_BIN="/workspaces/codespaces-blank/zig-bin/zig"
RUST_LIB="rust_net/target/release/liblean_net.a"

export PATH=$PATH:/workspaces/codespaces-blank/zig-bin:/home/codespace/.cargo/bin:$HOME/.bun/bin:$HOME/.deno/bin

# Ensure binaries are up to date
echo "Building binaries..."
gcc -O3 js_runtime_native.c -o js_runtime_native
$ZIG_BIN build-exe js_runtime_znet.zig -O ReleaseSafe --name js_runtime_znet -lc $RUST_LIB -lgcc_s
$ZIG_BIN build-exe high_perf_server.zig -O ReleaseSafe --name high_perf_server

# Start high-performance server
pkill -f "./high_perf_server"
./high_perf_server > /dev/null 2>&1 &
SERVER_PID=$!
sleep 2

echo "Running Benchmarks ($ITERATIONS iterations, Keep-Alive)..."

echo -e "\n--- [Binary A: Native C Sockets] ---"
timeout 60s perf stat ./js_runtime_native dummy.js $ITERATIONS

echo -e "\n--- [Binary B: Z-net (Zig + Rust/Mio)] ---"
timeout 60s perf stat ./js_runtime_znet dummy.js $ITERATIONS

echo -e "\n--- [Control: Bun] ---"
timeout 60s perf stat bun benchmark_script.js $ITERATIONS

echo -e "\n--- [Control: Deno] ---"
timeout 60s perf stat deno run --allow-net benchmark_script.js $ITERATIONS

echo -e "\n--- [Control: Node.js] ---"
timeout 60s perf stat node benchmark_script.js $ITERATIONS

# Cleanup
kill $SERVER_PID
echo -e "\nBenchmark complete."
