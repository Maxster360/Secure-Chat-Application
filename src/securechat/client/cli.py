"""CLI interface for the SecureChat client.

Provides an interactive terminal-based chat REPL with cipher selection,
room joining, and real-time message display.

Usage::

    python -m securechat.client.cli [--host HOST] [--port PORT]

Commands inside the chat REPL:
    /quit, /exit    — Leave the room and disconnect
    /users          — List users in the current room
    /help           — Show available commands
    (anything else) — Send as a chat message
"""

from __future__ import annotations

import logging
import os
import sys
import threading
from typing import Any

from securechat.ciphers import CipherRegistry
from securechat.ciphers.keys import (
    CaesarKey,
    ColumnarKey,
    HillKey,
    VigenereKey,
)
from securechat.client.client import ChatClient
from securechat.protocol.message import Message, MessageType

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Key generation helpers
# ---------------------------------------------------------------------------


def _prompt_caesar_key() -> CaesarKey:
    """Prompt user for a Caesar key (shift value)."""
    while True:
        try:
            shift = int(input("  Enter shift value (0-255): ").strip())
            return CaesarKey(shift=shift)
        except (ValueError, KeyError) as e:
            print(f"  Invalid shift: {e}. Try again.")


def _prompt_vigenere_key() -> VigenereKey:
    """Prompt user for a Vigenere key."""
    while True:
        raw = input("  Enter key string (non-empty): ").strip()
        if raw:
            return VigenereKey(key_bytes=raw.encode("utf-8"))
        print("  Key must not be empty. Try again.")


def _prompt_columnar_key() -> ColumnarKey:
    """Prompt user for a Columnar Transposition key."""
    while True:
        try:
            raw = input("  Enter permutation (comma-separated, e.g. 2,0,1): ").strip()
            perm = tuple(int(x.strip()) for x in raw.split(","))
            return ColumnarKey(permutation=perm)
        except (ValueError, KeyError) as e:
            print(f"  Invalid permutation: {e}. Try again.")


def _prompt_hill_key() -> HillKey:
    """Prompt user for a Hill cipher key (2x2 matrix)."""
    while True:
        try:
            print("  Enter a 2x2 matrix (4 integers, comma-separated):")
            raw = input("  e.g. 1,2,3,5: ").strip()
            vals = [int(x.strip()) for x in raw.split(",")]
            if len(vals) != 4:
                print("  Need exactly 4 values for a 2x2 matrix.")
                continue
            matrix = [vals[:2], vals[2:]]
            return HillKey.from_lists(matrix)
        except (ValueError, KeyError) as e:
            print(f"  Invalid matrix: {e}. Try again.")


KEY_PROMPTERS = {
    "caesar": _prompt_caesar_key,
    "vigenere": _prompt_vigenere_key,
    "columnar": _prompt_columnar_key,
    "hill": _prompt_hill_key,
}


# ---------------------------------------------------------------------------
# Message display
# ---------------------------------------------------------------------------


def _display_message(msg: Message) -> None:
    """Print a received message to the terminal."""
    if msg.msg_type == MessageType.CHAT:
        text = msg.payload.decode("utf-8", errors="replace")
        print(f"\r[{msg.sender}] {text}")
    elif msg.msg_type == MessageType.JOIN:
        info = msg.extra.get("info", f"{msg.sender} joined")
        print(f"\r*** {info}")
    elif msg.msg_type == MessageType.LEAVE:
        info = msg.extra.get("info", f"{msg.sender} left")
        print(f"\r*** {info}")
    elif msg.msg_type == MessageType.LIST_USERS:
        users = msg.extra.get("users", "")
        user_list = users.split(",") if users else []
        print(f"\r--- Online ({len(user_list)}): {', '.join(user_list)}")
    elif msg.msg_type == MessageType.ERROR:
        error = msg.extra.get("error", "Unknown error")
        print(f"\r!!! Server error: {error}")
    else:
        print(f"\r[?] {msg.msg_type.name}: {msg.extra}")

    # Re-display prompt
    sys.stdout.write("> ")
    sys.stdout.flush()


def _on_disconnect() -> None:
    """Handle disconnection from server."""
    print("\n*** Disconnected from server")


# ---------------------------------------------------------------------------
# Interactive setup
# ---------------------------------------------------------------------------


def _interactive_setup(default_host: str, default_port: int) -> tuple[str, int, str, str, str, Any]:
    """Interactively gather connection parameters from the user.

    Returns:
        (host, port, username, room, cipher_name, key)
    """
    print("=" * 50)
    print("       SecureChat — Classical Cryptography")
    print("=" * 50)
    print()

    # Host and port
    host = input(f"  Server host [{default_host}]: ").strip() or default_host
    port_str = input(f"  Server port [{default_port}]: ").strip()
    port = int(port_str) if port_str else default_port

    # Username
    username = ""
    while not username:
        username = input("  Your username: ").strip()
        if not username:
            print("  Username cannot be empty.")

    # Room
    room = input("  Room name [general]: ").strip() or "general"

    # Cipher selection
    available = CipherRegistry.list_ciphers()
    print(f"\n  Available ciphers: {', '.join(available)}")
    cipher_name = ""
    while cipher_name not in available:
        cipher_name = input(f"  Choose cipher ({'/'.join(available)}): ").strip().lower()
        if cipher_name not in available:
            print(f"  Unknown cipher. Available: {', '.join(available)}")

    # Key
    print(f"\n  Configure {cipher_name} key:")
    prompter = KEY_PROMPTERS.get(cipher_name)
    if prompter is None:
        print(f"  No key prompter for {cipher_name}. Aborting.")
        sys.exit(1)
    key = prompter()

    print()
    return host, port, username, room, cipher_name, key


# ---------------------------------------------------------------------------
# Chat REPL
# ---------------------------------------------------------------------------


def _chat_repl(client: ChatClient) -> None:
    """Run the interactive chat read-eval-print loop."""
    print()
    print(f"Connected to {client.host}:{client.port} as '{client.username}'")
    print(f"Room: {client.room} | Cipher: {client.cipher_name}")
    print("Type /help for commands. Start chatting!")
    print("-" * 50)

    # Start background receive loop
    client.start_recv_loop(
        on_message=_display_message,
        on_disconnect=_on_disconnect,
    )

    try:
        while client.is_connected:
            try:
                sys.stdout.write("> ")
                sys.stdout.flush()
                line = input()
            except EOFError:
                break

            line = line.strip()
            if not line:
                continue

            if line.lower() in ("/quit", "/exit"):
                break
            elif line.lower() == "/users":
                client.request_user_list()
            elif line.lower() == "/help":
                print("  /quit, /exit  — Leave and disconnect")
                print("  /users        — List users in this room")
                print("  /help         — Show this help")
                print("  (anything)    — Send as chat message")
            else:
                try:
                    client.send_chat(line)
                except ConnectionError:
                    print("*** Connection lost")
                    break
    except KeyboardInterrupt:
        pass
    finally:
        client.disconnect()
        print("Goodbye!")


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------


def main() -> None:
    """Run the SecureChat client CLI."""
    import argparse

    # Ensure ciphers are registered
    import securechat.ciphers  # noqa: F401

    parser = argparse.ArgumentParser(description="SecureChat Client")
    parser.add_argument("--host", default="127.0.0.1", help="Server host (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=5000, help="Server port (default: 5000)")
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable debug logging")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.WARNING,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    host, port, username, room, cipher_name, key = _interactive_setup(args.host, args.port)

    client = ChatClient(
        host=host,
        port=port,
        username=username,
        room=room,
        cipher_name=cipher_name,
        key=key,
    )

    print(f"Connecting to {host}:{port}...")
    if not client.connect():
        print("Failed to connect. Check that the server is running.")
        sys.exit(1)

    _chat_repl(client)


if __name__ == "__main__":
    main()
