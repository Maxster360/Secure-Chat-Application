"""CPU benchmark — measures CPU usage during encryption operations.

Uses psutil to track CPU percent during sustained encryption workloads.
Results are printed and saved to ``benchmarks/results/cpu.json``.

Usage::

    python benchmarks/bench_cpu.py
"""

from __future__ import annotations

import json
import os
import sys
import time

# Ensure the package is importable
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import securechat.ciphers  # noqa: F401, E402
from securechat.ciphers.base import CipherRegistry  # noqa: E402
from securechat.ciphers.keys import (  # noqa: E402
    CaesarKey,
    ColumnarKey,
    HillKey,
    VigenereKey,
)

PAYLOAD_SIZE = 4096
DURATION_SECONDS = 3.0

KEYS = {
    "caesar": CaesarKey(shift=42),
    "vigenere": VigenereKey(key_bytes=b"benchmarkkey"),
    "columnar": ColumnarKey(permutation=(2, 0, 3, 1, 4)),
    "hill": HillKey(matrix=((1, 2), (3, 5)), size=2),
}


def _measure_cpu(cipher_name: str, key) -> dict:
    """Measure CPU usage during sustained encryption for *cipher_name*."""
    try:
        import psutil
    except ImportError:
        return {
            "cipher": cipher_name,
            "error": "psutil not installed",
        }

    cipher = CipherRegistry.get(cipher_name)
    plaintext = os.urandom(PAYLOAD_SIZE)
    process = psutil.Process(os.getpid())

    # Warm up
    for _ in range(10):
        cipher.encrypt(plaintext, key)

    # Reset CPU measurement
    process.cpu_percent()
    time.sleep(0.1)

    # Sustained workload
    iterations = 0
    start = time.perf_counter()
    while time.perf_counter() - start < DURATION_SECONDS:
        cipher.encrypt(plaintext, key)
        cipher.decrypt(cipher.encrypt(plaintext, key), key)
        iterations += 1

    elapsed = time.perf_counter() - start
    cpu_percent = process.cpu_percent()
    memory_mb = process.memory_info().rss / (1024 * 1024)

    return {
        "cipher": cipher_name,
        "duration_s": round(elapsed, 3),
        "iterations": iterations,
        "ops_per_sec": round(iterations / elapsed, 1),
        "cpu_percent": round(cpu_percent, 1),
        "memory_mb": round(memory_mb, 1),
        "payload_bytes": PAYLOAD_SIZE,
    }


def run_cpu_benchmark() -> list[dict]:
    """Run the full CPU benchmark suite."""
    results = []
    for cipher_name in CipherRegistry.list_ciphers():
        key = KEYS.get(cipher_name)
        if key is None:
            continue
        result = _measure_cpu(cipher_name, key)
        results.append(result)
    return results


def main() -> None:
    try:
        from rich.console import Console
        from rich.table import Table

        console = Console()
        use_rich = True
    except ImportError:
        use_rich = False

    print("=" * 60)
    print("  SecureChat CPU Benchmark")
    print("=" * 60)
    print()

    results = run_cpu_benchmark()

    if use_rich:
        table = Table(title="CPU Usage Results")
        table.add_column("Cipher", style="cyan")
        table.add_column("Ops/sec", justify="right", style="green")
        table.add_column("CPU %", justify="right", style="yellow")
        table.add_column("Memory (MB)", justify="right")
        table.add_column("Iterations", justify="right")
        for r in results:
            if "error" in r:
                table.add_row(r["cipher"], "—", "—", "—", r["error"])
            else:
                table.add_row(
                    r["cipher"],
                    f"{r['ops_per_sec']:,.1f}",
                    f"{r['cpu_percent']:.1f}",
                    f"{r['memory_mb']:.1f}",
                    f"{r['iterations']:,}",
                )
        console.print(table)
    else:
        print(f"{'Cipher':<12} {'Ops/sec':>10} {'CPU %':>8} {'Mem MB':>8} {'Iters':>10}")
        print("-" * 50)
        for r in results:
            if "error" in r:
                print(f"{r['cipher']:<12} {r['error']}")
            else:
                print(
                    f"{r['cipher']:<12} {r['ops_per_sec']:>10,.1f} "
                    f"{r['cpu_percent']:>7.1f} {r['memory_mb']:>7.1f} "
                    f"{r['iterations']:>10,}"
                )

    results_dir = os.path.join(os.path.dirname(__file__), "results")
    os.makedirs(results_dir, exist_ok=True)
    out_path = os.path.join(results_dir, "cpu.json")
    with open(out_path, "w") as f:
        json.dump(results, f, indent=2)
    print(f"\nResults saved to {out_path}")


if __name__ == "__main__":
    main()
