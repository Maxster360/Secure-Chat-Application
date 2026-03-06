"""Latency benchmark — measures per-message round-trip time.

Sends messages through a real server and measures the time from send to
receipt. Results are printed and saved to ``benchmarks/results/latency.json``.

Usage::

    python benchmarks/bench_latency.py
"""

from __future__ import annotations

import json
import os
import socket
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
from securechat.client.client import ChatClient  # noqa: E402
from securechat.protocol.message import MessageType  # noqa: E402
from securechat.server.server import ChatServer  # noqa: E402


MESSAGES_PER_CIPHER = 100
PAYLOAD = b"Benchmark latency test payload -- 64 bytes of data here!!!!!!!!"

KEYS = {
    "caesar": CaesarKey(shift=42),
    "vigenere": VigenereKey(key_bytes=b"benchmarkkey"),
    "columnar": ColumnarKey(permutation=(2, 0, 3, 1, 4)),
    "hill": HillKey(matrix=((1, 2), (3, 5)), size=2),
}


def _measure_latency(cipher_name: str, key, server: ChatServer) -> dict:
    """Measure per-message latency for a cipher."""
    host, port = server.address

    sender = ChatClient(host, port, "bench-sender", f"lat-{cipher_name}", cipher_name, key)
    receiver = ChatClient(host, port, "bench-receiver", f"lat-{cipher_name}", cipher_name, key)

    assert sender.connect(timeout=5.0)
    assert receiver.connect(timeout=5.0)

    # Drain initial messages
    sender._sock.settimeout(1.0)  # type: ignore[union-attr]
    receiver._sock.settimeout(1.0)  # type: ignore[union-attr]
    try:
        while True:
            sender.recv()
    except (socket.timeout, ConnectionError, OSError):
        pass
    try:
        while True:
            receiver.recv()
    except (socket.timeout, ConnectionError, OSError):
        pass

    latencies: list[float] = []
    receiver._sock.settimeout(5.0)  # type: ignore[union-attr]

    for _ in range(MESSAGES_PER_CIPHER):
        start = time.perf_counter()
        sender.send_chat(PAYLOAD.decode("utf-8"))
        msg = receiver.recv()
        elapsed = time.perf_counter() - start
        latencies.append(elapsed * 1000)  # ms

    sender.disconnect()
    receiver.disconnect()

    avg = sum(latencies) / len(latencies)
    p50 = sorted(latencies)[len(latencies) // 2]
    p99 = sorted(latencies)[int(len(latencies) * 0.99)]
    min_l = min(latencies)
    max_l = max(latencies)

    return {
        "cipher": cipher_name,
        "messages": MESSAGES_PER_CIPHER,
        "avg_ms": round(avg, 3),
        "p50_ms": round(p50, 3),
        "p99_ms": round(p99, 3),
        "min_ms": round(min_l, 3),
        "max_ms": round(max_l, 3),
    }


def run_latency_benchmark() -> list[dict]:
    """Run the full latency benchmark suite."""
    server = ChatServer(host="127.0.0.1", port=0)
    server.start()
    time.sleep(0.2)

    results = []
    try:
        for cipher_name in CipherRegistry.list_ciphers():
            key = KEYS.get(cipher_name)
            if key is None:
                continue
            result = _measure_latency(cipher_name, key, server)
            results.append(result)
    finally:
        server.stop()

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
    print("  SecureChat Latency Benchmark")
    print("=" * 60)
    print()

    results = run_latency_benchmark()

    if use_rich:
        table = Table(title="Latency Results (ms)")
        table.add_column("Cipher", style="cyan")
        table.add_column("Avg", justify="right", style="green")
        table.add_column("P50", justify="right")
        table.add_column("P99", justify="right", style="yellow")
        table.add_column("Min", justify="right")
        table.add_column("Max", justify="right", style="red")
        for r in results:
            table.add_row(
                r["cipher"],
                f"{r['avg_ms']:.3f}",
                f"{r['p50_ms']:.3f}",
                f"{r['p99_ms']:.3f}",
                f"{r['min_ms']:.3f}",
                f"{r['max_ms']:.3f}",
            )
        console.print(table)
    else:
        print(f"{'Cipher':<12} {'Avg':>8} {'P50':>8} {'P99':>8} {'Min':>8} {'Max':>8}")
        print("-" * 56)
        for r in results:
            print(
                f"{r['cipher']:<12} {r['avg_ms']:>7.3f} {r['p50_ms']:>7.3f} "
                f"{r['p99_ms']:>7.3f} {r['min_ms']:>7.3f} {r['max_ms']:>7.3f}"
            )

    results_dir = os.path.join(os.path.dirname(__file__), "results")
    os.makedirs(results_dir, exist_ok=True)
    out_path = os.path.join(results_dir, "latency.json")
    with open(out_path, "w") as f:
        json.dump(results, f, indent=2)
    print(f"\nResults saved to {out_path}")


if __name__ == "__main__":
    main()
