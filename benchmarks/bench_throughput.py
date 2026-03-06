"""Throughput benchmark — measures encrypt/decrypt bytes per second.

Runs each cipher over a range of payload sizes and reports throughput
in MB/s. Results are printed to the console and saved to
``benchmarks/results/throughput.json``.

Usage::

    python benchmarks/bench_throughput.py
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


PAYLOAD_SIZES = [64, 256, 1024, 4096, 16384, 65536]
ITERATIONS = 100

# Keys for each cipher
KEYS = {
    "caesar": CaesarKey(shift=42),
    "vigenere": VigenereKey(key_bytes=b"benchmarkkey"),
    "columnar": ColumnarKey(permutation=(2, 0, 3, 1, 4)),
    "hill": HillKey(matrix=((1, 2), (3, 5)), size=2),
}


def _benchmark_cipher(cipher_name: str, key, payload_size: int, iterations: int) -> dict:
    """Run throughput benchmark for a single cipher/size combination."""
    cipher = CipherRegistry.get(cipher_name)
    plaintext = os.urandom(payload_size)

    # Encrypt benchmark
    start = time.perf_counter()
    for _ in range(iterations):
        ct = cipher.encrypt(plaintext, key)
    encrypt_time = time.perf_counter() - start

    # Decrypt benchmark
    ciphertext = cipher.encrypt(plaintext, key)
    start = time.perf_counter()
    for _ in range(iterations):
        cipher.decrypt(ciphertext, key)
    decrypt_time = time.perf_counter() - start

    total_bytes = payload_size * iterations
    return {
        "cipher": cipher_name,
        "payload_bytes": payload_size,
        "iterations": iterations,
        "encrypt_time_s": round(encrypt_time, 6),
        "decrypt_time_s": round(decrypt_time, 6),
        "encrypt_mbps": round(total_bytes / encrypt_time / 1_000_000, 2),
        "decrypt_mbps": round(total_bytes / decrypt_time / 1_000_000, 2),
    }


def run_throughput_benchmark() -> list[dict]:
    """Run the full throughput benchmark suite."""
    results = []
    for cipher_name in CipherRegistry.list_ciphers():
        key = KEYS.get(cipher_name)
        if key is None:
            continue
        for size in PAYLOAD_SIZES:
            result = _benchmark_cipher(cipher_name, key, size, ITERATIONS)
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
    print("  SecureChat Throughput Benchmark")
    print("=" * 60)
    print()

    results = run_throughput_benchmark()

    if use_rich:
        table = Table(title="Throughput Results")
        table.add_column("Cipher", style="cyan")
        table.add_column("Payload", justify="right")
        table.add_column("Encrypt (MB/s)", justify="right", style="green")
        table.add_column("Decrypt (MB/s)", justify="right", style="green")
        for r in results:
            table.add_row(
                r["cipher"],
                f"{r['payload_bytes']:,} B",
                f"{r['encrypt_mbps']:.2f}",
                f"{r['decrypt_mbps']:.2f}",
            )
        console.print(table)
    else:
        print(f"{'Cipher':<12} {'Payload':>10} {'Encrypt MB/s':>14} {'Decrypt MB/s':>14}")
        print("-" * 52)
        for r in results:
            print(
                f"{r['cipher']:<12} {r['payload_bytes']:>10,} B "
                f"{r['encrypt_mbps']:>13.2f} {r['decrypt_mbps']:>13.2f}"
            )

    # Save results
    results_dir = os.path.join(os.path.dirname(__file__), "results")
    os.makedirs(results_dir, exist_ok=True)
    out_path = os.path.join(results_dir, "throughput.json")
    with open(out_path, "w") as f:
        json.dump(results, f, indent=2)
    print(f"\nResults saved to {out_path}")


if __name__ == "__main__":
    main()
