"""Multi-cipher demo -- four clients, four different ciphers, one room.

This example demonstrates SecureChat's ability to handle mixed cipher
sessions. Each client independently negotiates its own cipher during
the handshake, so the server transparently re-encrypts for every
recipient using their own key.

Run this script to see it in action:

    python examples/multi_cipher.py
"""

from __future__ import annotations

import os
import socket
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import securechat.ciphers  # noqa: F401, E402
from securechat.ciphers.keys import (  # noqa: E402
    CaesarKey,
    ColumnarKey,
    HillKey,
    VigenereKey,
)
from securechat.client.client import ChatClient  # noqa: E402
from securechat.protocol.message import MessageType  # noqa: E402
from securechat.server.server import ChatServer  # noqa: E402

ROOM = "crypto-showcase"


def drain(client: ChatClient) -> None:
    """Drain all pending messages (JOIN notifications, LIST_USERS, etc.)."""
    client._sock.settimeout(0.5)  # type: ignore[union-attr]
    try:
        while True:
            client.recv()
    except (socket.timeout, ConnectionError, OSError):
        pass


def main() -> None:
    # ── 1. Start server ──────────────────────────────────────────────
    print("[*] Starting server...")
    server = ChatServer(host="127.0.0.1", port=0)
    server.start()
    host, port = server.address
    print(f"[*] Server listening on {host}:{port}\n")

    # ── 2. Prepare four clients, each with a different cipher ────────
    clients_cfg: list[tuple[str, str, object]] = [
        ("Alice", "caesar", CaesarKey(shift=13)),
        ("Bob", "vigenere", VigenereKey(key_bytes=b"SECRETKEY")),
        ("Charlie", "columnar", ColumnarKey(permutation=(2, 0, 3, 1))),
        ("Diana", "hill", HillKey.from_lists([[3, 2], [5, 7]])),
    ]

    clients: list[ChatClient] = []
    for name, cipher, key in clients_cfg:
        print(f"[*] Connecting {name} with {cipher} cipher...")
        c = ChatClient(host, port, name, ROOM, cipher, key)  # type: ignore[arg-type]
        assert c.connect(), f"{name} failed to connect"
        clients.append(c)
        print(f"[+] {name} connected  (cipher={cipher})")

    print()
    time.sleep(0.3)

    # Drain setup messages from all clients
    for c in clients:
        drain(c)

    # ── 3. Each client sends a message ───────────────────────────────
    messages = [
        "Hello from Caesar land!",
        "Vigenere says hi!",
        "Columnar Transposition checking in!",
        "Hill cipher reporting for duty!",
    ]

    for client, text in zip(clients, messages):
        name = clients_cfg[clients.index(client)][0]
        print(f"[{name}] Sending: {text}")
        client.send_chat(text)
        time.sleep(0.15)  # small delay so messages arrive in order

    print()

    # ── 4. Each client reads messages from the others ────────────────
    for i, client in enumerate(clients):
        name = clients_cfg[i][0]
        client._sock.settimeout(2.0)  # type: ignore[union-attr]
        received: list[str] = []
        try:
            while True:
                msg = client.recv()
                if msg.msg_type == MessageType.CHAT:
                    received.append(msg.payload.decode("utf-8"))
        except (socket.timeout, ConnectionError, OSError):
            pass

        # The client should NOT see its own message back, only others'
        for text in received:
            print(f"[{name}] Received: {text}")

    # ── 5. Cleanup ───────────────────────────────────────────────────
    print("\n[*] Disconnecting all clients...")
    for c in clients:
        c.disconnect()
    server.stop()
    print("[*] Done! All four ciphers worked in the same room.")


if __name__ == "__main__":
    main()
