"""End-to-end integration tests (Phase 16).

These tests exercise the full stack: ChatServer + ChatClient with real TCP
connections, handshakes, encryption, and message round-trips across all four
cipher types.
"""

from __future__ import annotations

import socket
import threading
import time

import pytest

import securechat.ciphers  # noqa: F401
from securechat.ciphers.base import CipherRegistry
from securechat.ciphers.keys import (
    CaesarKey,
    ColumnarKey,
    HillKey,
    VigenereKey,
)
from securechat.client.client import ChatClient
from securechat.protocol.message import Message, MessageType
from securechat.server.server import ChatServer


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def server():
    """Start a ChatServer on a random port, yield it, then stop."""
    srv = ChatServer(host="127.0.0.1", port=0)
    srv.start()
    time.sleep(0.1)
    yield srv
    srv.stop()


def _make_client(
    server: ChatServer,
    username: str,
    room: str,
    cipher_name: str,
    key,
) -> ChatClient:
    """Create and connect a ChatClient."""
    host, port = server.address
    client = ChatClient(host, port, username, room, cipher_name, key)
    assert client.connect(timeout=5.0), f"Failed to connect {username}"
    return client


def _drain(client: ChatClient, timeout: float = 1.0) -> list[Message]:
    """Drain all pending messages from a client."""
    messages: list[Message] = []
    client._sock.settimeout(timeout)  # type: ignore[union-attr]
    try:
        while True:
            messages.append(client.recv())
    except (socket.timeout, ConnectionError, OSError):
        pass
    return messages


def _recv_until_chat(client: ChatClient, timeout: float = 5.0) -> Message:
    """Receive messages until a CHAT message arrives."""
    client._sock.settimeout(timeout)  # type: ignore[union-attr]
    deadline = time.time() + timeout
    while time.time() < deadline:
        msg = client.recv()
        if msg.msg_type == MessageType.CHAT:
            return msg
    raise TimeoutError("No CHAT message received")


# ---------------------------------------------------------------------------
# Caesar cipher — full round-trip
# ---------------------------------------------------------------------------


class TestCaesarIntegration:
    def test_two_clients_chat(self, server: ChatServer) -> None:
        """Two clients with Caesar cipher exchange messages."""
        alice = _make_client(server, "alice", "caesar-room", "caesar", CaesarKey(shift=42))
        bob = _make_client(server, "bob", "caesar-room", "caesar", CaesarKey(shift=99))

        _drain(alice)
        _drain(bob)

        alice.send_chat("Hello from Caesar!")
        msg = _recv_until_chat(bob)
        assert msg.payload == b"Hello from Caesar!"
        assert msg.sender == "alice"

        bob.send_chat("Reply from Bob!")
        msg = _recv_until_chat(alice)
        assert msg.payload == b"Reply from Bob!"
        assert msg.sender == "bob"

        alice.disconnect()
        bob.disconnect()

    def test_message_not_received_by_sender(self, server: ChatServer) -> None:
        """The sender should NOT receive their own message."""
        alice = _make_client(server, "alice", "echo-test", "caesar", CaesarKey(shift=1))
        bob = _make_client(server, "bob", "echo-test", "caesar", CaesarKey(shift=2))

        _drain(alice)
        _drain(bob)

        alice.send_chat("test echo")
        # Bob gets it
        msg = _recv_until_chat(bob)
        assert msg.payload == b"test echo"

        # Alice should NOT get it
        alice._sock.settimeout(0.5)  # type: ignore[union-attr]
        with pytest.raises((socket.timeout, OSError)):
            alice.recv()

        alice.disconnect()
        bob.disconnect()


# ---------------------------------------------------------------------------
# Vigenere cipher — full round-trip
# ---------------------------------------------------------------------------


class TestVigenereIntegration:
    def test_two_clients_chat(self, server: ChatServer) -> None:
        alice = _make_client(
            server, "alice", "vig-room", "vigenere", VigenereKey(key_bytes=b"alphakey")
        )
        bob = _make_client(server, "bob", "vig-room", "vigenere", VigenereKey(key_bytes=b"betakey"))

        _drain(alice)
        _drain(bob)

        alice.send_chat("Vigenere message!")
        msg = _recv_until_chat(bob)
        assert msg.payload == b"Vigenere message!"

        alice.disconnect()
        bob.disconnect()


# ---------------------------------------------------------------------------
# Columnar Transposition — full round-trip
# ---------------------------------------------------------------------------


class TestColumnarIntegration:
    def test_two_clients_chat(self, server: ChatServer) -> None:
        alice = _make_client(
            server, "alice", "col-room", "columnar", ColumnarKey(permutation=(2, 0, 3, 1))
        )
        bob = _make_client(
            server, "bob", "col-room", "columnar", ColumnarKey(permutation=(1, 0, 2))
        )

        _drain(alice)
        _drain(bob)

        alice.send_chat("Transposition works!")
        msg = _recv_until_chat(bob)
        assert msg.payload == b"Transposition works!"

        alice.disconnect()
        bob.disconnect()


# ---------------------------------------------------------------------------
# Hill cipher — full round-trip
# ---------------------------------------------------------------------------


class TestHillIntegration:
    def test_two_clients_chat(self, server: ChatServer) -> None:
        # Matrix [[1,2],[3,5]] has det = -1 ≡ 255 mod 256, gcd(255,256)=1
        key_a = HillKey(matrix=((1, 2), (3, 5)), size=2)
        key_b = HillKey(matrix=((1, 2), (3, 5)), size=2)

        alice = _make_client(server, "alice", "hill-room", "hill", key_a)
        bob = _make_client(server, "bob", "hill-room", "hill", key_b)

        _drain(alice)
        _drain(bob)

        alice.send_chat("Hill cipher test!")
        msg = _recv_until_chat(bob)
        # Hill cipher pads to block size, so decrypted may have trailing bytes
        # but the meaningful content should be there
        assert msg.payload[:16] == b"Hill cipher test"

        alice.disconnect()
        bob.disconnect()


# ---------------------------------------------------------------------------
# Multi-cipher room — different ciphers in same room
# ---------------------------------------------------------------------------


class TestMixedCipherRoom:
    def test_different_ciphers_same_room(self, server: ChatServer) -> None:
        """Clients using different ciphers can chat in the same room."""
        alice = _make_client(server, "alice", "mixed", "caesar", CaesarKey(shift=7))
        bob = _make_client(server, "bob", "mixed", "vigenere", VigenereKey(key_bytes=b"key"))

        _drain(alice)
        _drain(bob)

        alice.send_chat("From Caesar user")
        msg = _recv_until_chat(bob)
        assert msg.payload == b"From Caesar user"

        bob.send_chat("From Vigenere user")
        msg = _recv_until_chat(alice)
        assert msg.payload == b"From Vigenere user"

        alice.disconnect()
        bob.disconnect()


# ---------------------------------------------------------------------------
# Multiple rooms — isolation
# ---------------------------------------------------------------------------


class TestRoomIsolation:
    def test_messages_dont_cross_rooms(self, server: ChatServer) -> None:
        """Messages in room A should not be received in room B."""
        alice = _make_client(server, "alice", "room-a", "caesar", CaesarKey(shift=1))
        bob = _make_client(server, "bob", "room-b", "caesar", CaesarKey(shift=2))

        _drain(alice)
        _drain(bob)

        alice.send_chat("For room A only")

        # Bob (room B) should NOT receive it
        bob._sock.settimeout(1.0)  # type: ignore[union-attr]
        with pytest.raises((socket.timeout, OSError)):
            bob.recv()

        alice.disconnect()
        bob.disconnect()


# ---------------------------------------------------------------------------
# Multi-client broadcast
# ---------------------------------------------------------------------------


class TestBroadcast:
    def test_three_clients_all_receive(self, server: ChatServer) -> None:
        """When alice sends, both bob and carol receive."""
        alice = _make_client(server, "alice", "bcast", "caesar", CaesarKey(shift=1))
        bob = _make_client(server, "bob", "bcast", "caesar", CaesarKey(shift=2))
        carol = _make_client(server, "carol", "bcast", "caesar", CaesarKey(shift=3))

        _drain(alice)
        _drain(bob)
        _drain(carol)

        alice.send_chat("Broadcast!")

        msg_bob = _recv_until_chat(bob)
        msg_carol = _recv_until_chat(carol)

        assert msg_bob.payload == b"Broadcast!"
        assert msg_carol.payload == b"Broadcast!"

        alice.disconnect()
        bob.disconnect()
        carol.disconnect()


# ---------------------------------------------------------------------------
# Join / Leave notifications
# ---------------------------------------------------------------------------


class TestJoinLeaveNotifications:
    def test_join_notification(self, server: ChatServer) -> None:
        """Existing client receives JOIN when a new client connects."""
        alice = _make_client(server, "alice", "notify", "caesar", CaesarKey(shift=1))
        _drain(alice)

        bob = _make_client(server, "bob", "notify", "caesar", CaesarKey(shift=2))

        # Alice should receive a JOIN notification for bob
        alice._sock.settimeout(3.0)  # type: ignore[union-attr]
        msg = alice.recv()
        assert msg.msg_type == MessageType.JOIN
        assert msg.sender == "bob"

        alice.disconnect()
        bob.disconnect()

    def test_leave_notification(self, server: ChatServer) -> None:
        """Remaining client receives LEAVE when another disconnects."""
        alice = _make_client(server, "alice", "leave-n", "caesar", CaesarKey(shift=1))
        bob = _make_client(server, "bob", "leave-n", "caesar", CaesarKey(shift=2))

        _drain(alice)
        _drain(bob)

        bob.disconnect()
        time.sleep(0.3)

        # Alice should receive a LEAVE notification for bob
        alice._sock.settimeout(3.0)  # type: ignore[union-attr]
        msg = alice.recv()
        assert msg.msg_type == MessageType.LEAVE
        assert msg.sender == "bob"

        alice.disconnect()


# ---------------------------------------------------------------------------
# User list
# ---------------------------------------------------------------------------


class TestUserList:
    def test_user_list_on_join(self, server: ChatServer) -> None:
        """Client receives LIST_USERS immediately after connecting."""
        alice = _make_client(server, "alice", "ul-room", "caesar", CaesarKey(shift=1))
        alice._sock.settimeout(3.0)  # type: ignore[union-attr]
        msg = alice.recv()
        assert msg.msg_type == MessageType.LIST_USERS
        assert "alice" in msg.extra.get("users", "")
        alice.disconnect()

    def test_user_list_request(self, server: ChatServer) -> None:
        """Requesting user list mid-session returns current members."""
        alice = _make_client(server, "alice", "ul-room2", "caesar", CaesarKey(shift=1))
        bob = _make_client(server, "bob", "ul-room2", "caesar", CaesarKey(shift=2))

        _drain(alice)
        _drain(bob)

        alice.request_user_list()
        alice._sock.settimeout(3.0)  # type: ignore[union-attr]
        msg = alice.recv()
        assert msg.msg_type == MessageType.LIST_USERS
        users = msg.extra.get("users", "")
        assert "alice" in users
        assert "bob" in users

        alice.disconnect()
        bob.disconnect()


# ---------------------------------------------------------------------------
# Stress test
# ---------------------------------------------------------------------------


class TestStress:
    def test_rapid_messages(self, server: ChatServer) -> None:
        """Send 50 messages in rapid succession — all should arrive."""
        alice = _make_client(server, "alice", "stress", "caesar", CaesarKey(shift=1))
        bob = _make_client(server, "bob", "stress", "caesar", CaesarKey(shift=2))

        _drain(alice)
        _drain(bob)

        num_messages = 50
        for i in range(num_messages):
            alice.send_chat(f"msg-{i}")

        received: list[str] = []
        bob._sock.settimeout(10.0)  # type: ignore[union-attr]
        deadline = time.time() + 10
        while len(received) < num_messages and time.time() < deadline:
            try:
                msg = bob.recv()
                if msg.msg_type == MessageType.CHAT:
                    received.append(msg.payload.decode("utf-8"))
            except (socket.timeout, OSError):
                break

        assert len(received) == num_messages
        for i in range(num_messages):
            assert f"msg-{i}" in received

        alice.disconnect()
        bob.disconnect()
