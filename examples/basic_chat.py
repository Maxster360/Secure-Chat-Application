"""Basic chat example — start a server and two clients.

This example demonstrates the simplest possible SecureChat setup:
one server, two clients, both using Caesar cipher.

Run this script to see encrypted chat in action:

    python examples/basic_chat.py
"""

from __future__ import annotations

import sys
import os
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import securechat.ciphers  # noqa: F401, E402
from securechat.ciphers.keys import CaesarKey  # noqa: E402
from securechat.client.client import ChatClient  # noqa: E402
from securechat.protocol.message import MessageType  # noqa: E402
from securechat.server.server import ChatServer  # noqa: E402


def main() -> None:
    # 1. Start the server
    print("[*] Starting server...")
    server = ChatServer(host="127.0.0.1", port=0)
    server.start()
    host, port = server.address
    print(f"[*] Server listening on {host}:{port}")

    # 2. Connect Alice (Caesar, shift=7)
    print("[*] Connecting Alice...")
    alice = ChatClient(host, port, "Alice", "demo-room", "caesar", CaesarKey(shift=7))
    assert alice.connect(), "Alice failed to connect"
    print("[+] Alice connected")

    # 3. Connect Bob (Caesar, shift=42)
    print("[*] Connecting Bob...")
    bob = ChatClient(host, port, "Bob", "demo-room", "caesar", CaesarKey(shift=42))
    assert bob.connect(), "Bob failed to connect"
    print("[+] Bob connected")

    # 4. Drain initial messages (LIST_USERS, JOINs)
    import socket

    for client in (alice, bob):
        client._sock.settimeout(1.0)  # type: ignore[union-attr]
        try:
            while True:
                client.recv()
        except (socket.timeout, ConnectionError, OSError):
            pass

    # 5. Alice sends a message
    print("\n[Alice] Sending: Hello Bob!")
    alice.send_chat("Hello Bob!")

    # 6. Bob receives it (automatically decrypted)
    bob._sock.settimeout(3.0)  # type: ignore[union-attr]
    msg = bob.recv()
    assert msg.msg_type == MessageType.CHAT
    print(f"[Bob] Received: {msg.payload.decode('utf-8')}")

    # 7. Bob replies
    print("[Bob] Sending: Hey Alice, crypto works!")
    bob.send_chat("Hey Alice, crypto works!")

    alice._sock.settimeout(3.0)  # type: ignore[union-attr]
    msg = alice.recv()
    print(f"[Alice] Received: {msg.payload.decode('utf-8')}")

    # 8. Cleanup
    print("\n[*] Disconnecting...")
    alice.disconnect()
    bob.disconnect()
    server.stop()
    print("[*] Done!")


if __name__ == "__main__":
    main()
