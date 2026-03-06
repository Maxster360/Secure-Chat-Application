# Benchmark Results

## Test Environment

- **Python**: 3.13.7
- **OS**: Windows
- **All ciphers operate on raw bytes (mod 256)**
- **No external dependencies** for cipher implementations

## Throughput Benchmark

Measures encrypt/decrypt speed in MB/s across payload sizes (100 iterations per size).

| Cipher | 64 B | 256 B | 1 KB | 4 KB | 16 KB | 64 KB |
|--------|------|-------|------|------|-------|-------|
| **Caesar** (encrypt) | 4.46 | 6.69 | 8.38 | 25.30 | 26.16 | 25.08 |
| **Caesar** (decrypt) | 4.83 | 6.27 | 16.12 | 26.67 | 24.84 | 24.46 |
| **Columnar** (encrypt) | 17.48 | 24.39 | 21.94 | 20.44 | 19.99 | 19.70 |
| **Columnar** (decrypt) | 10.34 | 11.40 | 14.17 | 13.34 | 13.55 | 12.01 |
| **Hill** (encrypt) | 2.38 | 2.64 | 2.59 | 2.38 | 2.59 | 1.10 |
| **Hill** (decrypt) | 2.14 | 2.49 | 2.52 | 2.59 | 2.52 | 0.76 |
| **Vigenere** (encrypt) | 3.31 | 2.82 | 2.76 | 5.80 | 3.94 | 4.08 |
| **Vigenere** (decrypt) | 3.45 | 2.99 | 2.99 | 6.16 | 3.57 | 2.80 |

### Key Observations
- **Caesar** is the fastest cipher due to its single-operation-per-byte nature
- **Columnar Transposition** has strong encrypt throughput but slower decrypt (column reconstruction)
- **Hill cipher** is the slowest due to matrix multiplication per block
- All ciphers achieve practical throughput for chat workloads (messages are typically < 1 KB)

## Latency Benchmark

Measures per-message round-trip time through a real TCP server (100 messages per cipher, 64-byte payload).

| Cipher | Avg (ms) | P50 (ms) | P99 (ms) | Min (ms) | Max (ms) |
|--------|----------|----------|----------|----------|----------|
| **Caesar** | 0.810 | 0.800 | 1.207 | 0.438 | 1.207 |
| **Columnar** | 0.512 | 0.463 | 1.304 | 0.098 | 1.304 |
| **Hill** | 0.840 | 0.887 | 1.810 | 0.347 | 1.810 |
| **Vigenere** | 0.433 | 0.348 | 1.831 | 0.151 | 1.831 |

### Key Observations
- All ciphers achieve **sub-millisecond median latency** — imperceptible to users
- P99 latencies are under 2ms for all ciphers
- Network overhead dominates over encryption time at these message sizes
- Hill cipher has slightly higher latency due to matrix operations

## CPU Benchmark

Measures CPU utilization during sustained encrypt+decrypt operations (3-second workload, 4 KB payload).

| Cipher | Ops/sec | CPU % | Memory (MB) |
|--------|---------|-------|-------------|
| **Caesar** | 1,961 | 81.1% | 27.2 |
| **Columnar** | 865 | 43.8% | 27.4 |
| **Hill** | 52 | 6.0% | 27.4 |
| **Vigenere** | 227 | 14.6% | 27.4 |

### Key Observations
- **Caesar** achieves nearly 2,000 ops/sec and saturates a single CPU core
- **Hill cipher** is ~38x slower than Caesar due to matrix math complexity
- Memory footprint is constant across all ciphers (~27 MB baseline)
- CPU usage correlates directly with cipher computational complexity

## Running the Benchmarks

```bash
# Install benchmark dependencies
pip install -e ".[bench]"

# Run individual benchmarks
python benchmarks/bench_throughput.py
python benchmarks/bench_latency.py
python benchmarks/bench_cpu.py
```

Results are saved as JSON in `benchmarks/results/` for programmatic access.
