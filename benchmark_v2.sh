#!/bin/bash
ITERATIONS=10000
PORT=8080
ZIG_BIN="./zig-bin/zig"
RUST_LIB="rust_net/target/release/liblean_net.a"

echo "Building binaries..."
gcc -O3 js_runtime_native.c -o js_runtime_native
$ZIG_BIN build-exe js_runtime_znet.zig -O ReleaseSafe --name js_runtime_znet -lc $RUST_LIB -lgcc_s
$ZIG_BIN build-exe high_perf_server.zig -O ReleaseSafe --name high_perf_server

# Start high-performance server
pkill -f "./high_perf_server" || true
./high_perf_server > server.log 2>&1 &
SERVER_PID=$!
sleep 2

echo "Running Benchmarks ($ITERATIONS iterations, Keep-Alive)..."

echo -e "\n--- [Binary A: Native C Sockets] ---"
time ./js_runtime_native dummy $ITERATIONS

echo -e "\n--- [Binary B: Z-net (Zig + Rust/Mio)] ---"
time ./js_runtime_znet dummy $ITERATIONS

if command -v node &> /dev/null; then
    echo -e "\n--- [Control: Node.js] ---"
    time node benchmark_script.js $ITERATIONS
fi

kill $SERVER_PID
echo -e "\nBenchmark complete."
