const ITERATIONS = parseInt(process.argv[2]) || 50000;

async function run() {
    // Bun and Deno both support the global fetch API
    // Node.js also supports global fetch since v18+
    for (let i = 0; i < ITERATIONS; i++) {
        const res = await fetch('http://127.0.0.1:8080/');
        await res.arrayBuffer();
    }
}

run();
