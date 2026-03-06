"""Tests for client/client.py — client networking with encryption (Phase 14).

These tests spin up a real ChatServer on a random port and test the
ChatClient against it.
"""

from __future__ import annotations

import socket
import threading
import time

import pytest

import securechat.ciphers  # noqa: F401
from securechat.ciphers.keys import CaesarKey, VigenereKey
from securechat.client.client import ChatClient
from securechat.protocol.message import Message, MessageType
from securechat.server.server import ChatServer


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_server() -> ChatServer:
    """Create and start a server on an OS-assigned port."""
    server = ChatServer(host="127.0.0.1", port=0)
    server.start()
    time.sleep(0.1)
    return server


def _make_client(
    server: ChatServer,
    username: str,
    room: str = "general",
    cipher: str = "caesar",
    shift: int = 7,
) -> ChatClient:
    """Create a ChatClient pointed at *server*."""
    host, port = server.address
    key = CaesarKey(shift=shift)
    return ChatClient(
        host=host,
        port=port,
        username=username,
        room=room,
        cipher_name=cipher,
        key=key,
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestChatClient:
    """Tests for ChatClient lifecycle and messaging."""

    def test_connect_and_disconnect(self) -> None:
        server = _make_server()
        try:
            client = _make_client(server, "alice")
            assert client.connect() is True
            assert client.is_connected

            # Should have received LIST_USERS during connect recv_loop not started yet
            # but the handshake ack was consumed by client_handshake already

            client.disconnect()
            assert not client.is_connected
        finally:
            server.stop()

    def test_send_and_receive_chat(self) -> None:
        """Two clients: alice sends, bob receives decrypted."""
        server = _make_server()
        try:
            alice = _make_client(server, "alice", "chat", shift=3)
            bob = _make_client(server, "bob", "chat", shift=10)

            assert alice.connect()
            assert bob.connect()

            # Drain initial messages (LIST_USERS, JOINs)
            alice._sock.settimeout(2.0)  # type: ignore[union-attr]
            bob._sock.settimeout(2.0)  # type: ignore[union-attr]

            # Drain alice's messages
            try:
                while True:
                    alice.recv()
            except (socket.timeout, ConnectionError, OSError):
                pass

            # Drain bob's messages
            try:
                while True:
                    bob.recv()
            except (socket.timeout, ConnectionError, OSError):
                pass

            # Alice sends a chat
            alice.send_chat("Hello Bob!")

            # Bob receives and decrypts
            bob._sock.settimeout(3.0)  # type: ignore[union-attr]
            msg = bob.recv()
            assert msg.msg_type == MessageType.CHAT
            assert msg.sender == "alice"
            assert msg.payload == b"Hello Bob!"

            alice.disconnect()
            bob.disconnect()
        finally:
            server.stop()

    def test_recv_loop_callback(self) -> None:
        """start_recv_loop delivers messages via callback."""
        server = _make_server()
        try:
            alice = _make_client(server, "alice", "callback-room", shift=5)
            bob = _make_client(server, "bob", "callback-room", shift=8)

            assert alice.connect()
            assert bob.connect()

            received: list[Message] = []
            disconnect_called = threading.Event()

            bob.start_recv_loop(
                on_message=lambda m: received.append(m),
                on_disconnect=disconnect_called.set,
            )

            # Small delay for recv loop to start and drain initial messages
            time.sleep(0.5)

            # Alice sends
            alice.send_chat("callback test")

            # Wait for bob to receive
            deadline = time.time() + 5
            while time.time() < deadline:
                chat_msgs = [m for m in received if m.msg_type == MessageType.CHAT]
                if chat_msgs:
                    break
                time.sleep(0.1)

            chat_msgs = [m for m in received if m.msg_type == MessageType.CHAT]
            assert len(chat_msgs) >= 1
            assert chat_msgs[0].payload == b"callback test"

            alice.disconnect()
            bob.disconnect()
        finally:
            server.stop()

    def test_disconnect_sends_leave(self) -> None:
        """disconnect() sends LEAVE and cleans up the room."""
        server = _make_server()
        try:
            client = _make_client(server, "leaver", "leave-room")
            assert client.connect()

            # Drain initial LIST_USERS (and allow server to register client)
            client._sock.settimeout(2.0)  # type: ignore[union-attr]
            msg = client.recv()
            assert msg.msg_type == MessageType.LIST_USERS

            # Now the room definitely exists and has the member
            room = server.room_manager.get("leave-room")
            assert room is not None
            assert room.has_member("leaver")

            client.disconnect()
            time.sleep(0.5)  # give server time to process

            # Room should be cleaned up (empty -> removed)
            assert server.room_manager.get("leave-room") is None
        finally:
            server.stop()

    def test_connection_failure(self) -> None:
        """Connecting to a non-existent server returns False."""
        client = ChatClient(
            host="127.0.0.1",
            port=1,  # unlikely to be running
            username="fail",
            room="x",
            cipher_name="caesar",
            key=CaesarKey(shift=1),
        )
        assert client.connect(timeout=1.0) is False
        assert not client.is_connected

    def test_send_without_connect_raises(self) -> None:
        """Sending before connecting raises ConnectionError."""
        client = ChatClient(
            host="127.0.0.1",
            port=9999,
            username="x",
            room="x",
            cipher_name="caesar",
            key=CaesarKey(shift=1),
        )
        with pytest.raises(ConnectionError, match="Not connected"):
            client.send_chat("hello")

    def test_recv_without_connect_raises(self) -> None:
        """Receiving before connecting raises ConnectionError."""
        client = ChatClient(
            host="127.0.0.1",
            port=9999,
            username="x",
            room="x",
            cipher_name="caesar",
            key=CaesarKey(shift=1),
        )
        with pytest.raises(ConnectionError, match="Not connected"):
            client.recv()

    def test_request_user_list(self) -> None:
        """request_user_list() triggers a LIST_USERS response."""
        server = _make_server()
        try:
            client = _make_client(server, "lister", "list-room")
            assert client.connect()

            # Drain initial LIST_USERS
            client._sock.settimeout(2.0)  # type: ignore[union-attr]
            msg = client.recv()
            assert msg.msg_type == MessageType.LIST_USERS

            # Request again
            client.request_user_list()
            msg2 = client.recv()
            assert msg2.msg_type == MessageType.LIST_USERS
            assert "lister" in msg2.extra.get("users", "")

            client.disconnect()
        finally:
            server.stop()

    def test_repr(self) -> None:
        client = ChatClient(
            host="127.0.0.1",
            port=5000,
            username="alice",
            room="general",
            cipher_name="caesar",
            key=CaesarKey(shift=1),
        )
        r = repr(client)
        assert "alice" in r
        assert "caesar" in r
        assert "disconnected" in r

    def test_disconnect_idempotent(self) -> None:
        """Calling disconnect() when not connected doesn't crash."""
        client = ChatClient(
            host="127.0.0.1",
            port=5000,
            username="x",
            room="x",
            cipher_name="caesar",
            key=CaesarKey(shift=1),
        )
        client.disconnect()  # should not raise

    def test_vigenere_encryption(self) -> None:
        """Chat works with Vigenere cipher too."""
        server = _make_server()
        try:
            host, port = server.address
            key = VigenereKey(key_bytes=b"secretkey")
            alice = ChatClient(host, port, "alice", "vig-room", "vigenere", key)
            bob = ChatClient(host, port, "bob", "vig-room", "vigenere", key)

            assert alice.connect()
            assert bob.connect()

            # Drain initial messages
            alice._sock.settimeout(1.5)  # type: ignore[union-attr]
            bob._sock.settimeout(1.5)  # type: ignore[union-attr]
            try:
                while True:
                    alice.recv()
            except (socket.timeout, ConnectionError, OSError):
                pass
            try:
                while True:
                    bob.recv()
            except (socket.timeout, ConnectionError, OSError):
                pass

            alice.send_chat("Vigenere works!")
            bob._sock.settimeout(3.0)  # type: ignore[union-attr]
            msg = bob.recv()
            assert msg.msg_type == MessageType.CHAT
            assert msg.payload == b"Vigenere works!"

            alice.disconnect()
            bob.disconnect()
        finally:
            server.stop()
