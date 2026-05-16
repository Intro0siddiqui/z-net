#!/bin/bash

# Configuration
ITERATIONS=50000
HOST="127.0.0.1"
PORT=8080
ZIG_BIN="/workspaces/codespaces-blank/zig-bin/zig"
RUST_LIB="rust_net/target/release/liblean_net.a"

# Ensure binaries are up to date
echo "Building binaries..."
gcc -O3 js_runtime_native.c -o js_runtime_native
$ZIG_BIN build-exe js_runtime_znet.zig -O ReleaseSafe --name js_runtime_znet -lc $RUST_LIB -lgcc_s

# Start/Restart mock server
pkill -f "python3 -m http.server"
python3 -m http.server $PORT > /dev/null 2>&1 &
SERVER_PID=$!
sleep 2

echo "Running Benchmarks ($ITERATIONS iterations)..."

echo -e "\n--- [Binary A: Native C Sockets] ---"
perf stat ./js_runtime_native benchmark_script.js $ITERATIONS

echo -e "\n--- [Binary B: Z-net (Zig + Rust/Mio)] ---"
perf stat ./js_runtime_znet benchmark_script.js $ITERATIONS

echo -e "\n--- [Control: Node.js] ---"
# Update benchmark_script.js to match iterations
sed -i "s/for (let i = 0; i < [0-9]*/for (let i = 0; i < $ITERATIONS/" benchmark_script.js
perf stat node benchmark_script.js

# Cleanup
kill $SERVER_PID
echo -e "\nBenchmark complete."
