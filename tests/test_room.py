"""Tests for server/room.py — thread-safe chat room management (Phase 11)."""

from __future__ import annotations

import socket
import struct
import threading
import json

import pytest

import securechat.ciphers  # noqa: F401  — register ciphers
from securechat.ciphers.base import CipherRegistry
from securechat.ciphers.keys import CaesarKey, VigenereKey
from securechat.protocol.message import Message, MessageType
from securechat.server.room import ClientInfo, Room, RoomManager


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_client(
    username: str,
    room_name: str = "general",
    cipher_name: str = "caesar",
    shift: int = 7,
) -> tuple[ClientInfo, socket.socket]:
    """Create a ClientInfo backed by a real socket pair.

    Returns (client_info, peer_socket) where peer_socket is the "reading"
    end that receives whatever the Room sends to client_info.sock.
    """
    write_sock, read_sock = socket.socketpair()
    cipher = CipherRegistry.get(cipher_name)
    key = CaesarKey(shift=shift)
    info = ClientInfo(
        username=username,
        sock=write_sock,
        cipher=cipher,
        key=key,
        room_name=room_name,
    )
    return info, read_sock


def _recv_one_message(sock: socket.socket) -> Message:
    """Read one framed message from *sock* (blocking)."""
    raw_len = b""
    while len(raw_len) < 4:
        chunk = sock.recv(4 - len(raw_len))
        if not chunk:
            raise ConnectionError("closed")
        raw_len += chunk
    header_len = struct.unpack(">I", raw_len)[0]
    header_bytes = b""
    while len(header_bytes) < header_len:
        chunk = sock.recv(header_len - len(header_bytes))
        if not chunk:
            raise ConnectionError("closed")
        header_bytes += chunk
    msg = Message.from_json_header(header_bytes)
    if msg.payload_len > 0:
        payload = b""
        while len(payload) < msg.payload_len:
            chunk = sock.recv(msg.payload_len - len(payload))
            if not chunk:
                raise ConnectionError("closed")
            payload += chunk
        msg.payload = payload
    return msg


# ---------------------------------------------------------------------------
# ClientInfo tests
# ---------------------------------------------------------------------------


class TestClientInfo:
    def test_hash_by_socket_identity(self) -> None:
        c1, r1 = _make_client("alice")
        c2, r2 = _make_client("bob")
        # Different sockets → different hashes
        assert hash(c1) != hash(c2)
        r1.close()
        r2.close()
        c1.sock.close()
        c2.sock.close()

    def test_equality_by_socket_identity(self) -> None:
        c1, r1 = _make_client("alice")
        c2, r2 = _make_client("alice")  # same username, different socket
        assert c1 != c2
        r1.close()
        r2.close()
        c1.sock.close()
        c2.sock.close()

    def test_equality_not_implemented_for_other(self) -> None:
        c1, r1 = _make_client("alice")
        assert c1 != "alice"
        r1.close()
        c1.sock.close()


# ---------------------------------------------------------------------------
# Room tests
# ---------------------------------------------------------------------------


class TestRoom:
    def test_join_and_members(self) -> None:
        room = Room("test")
        c1, r1 = _make_client("alice")
        c2, r2 = _make_client("bob")
        room.join(c1)
        room.join(c2)
        assert room.size == 2
        assert room.members() == ["alice", "bob"]
        r1.close()
        r2.close()
        c1.sock.close()
        c2.sock.close()

    def test_leave(self) -> None:
        room = Room("test")
        c1, r1 = _make_client("alice")
        room.join(c1)
        removed = room.leave("alice")
        assert removed is c1
        assert room.size == 0
        assert room.is_empty
        r1.close()
        c1.sock.close()

    def test_leave_nonexistent(self) -> None:
        room = Room("test")
        assert room.leave("ghost") is None

    def test_has_member(self) -> None:
        room = Room("test")
        c1, r1 = _make_client("alice")
        room.join(c1)
        assert room.has_member("alice")
        assert not room.has_member("bob")
        r1.close()
        c1.sock.close()

    def test_is_empty(self) -> None:
        room = Room("test")
        assert room.is_empty
        c1, r1 = _make_client("alice")
        room.join(c1)
        assert not room.is_empty
        r1.close()
        c1.sock.close()

    def test_rejoin_replaces_old_entry(self) -> None:
        """Joining with same username replaces the old socket."""
        room = Room("test")
        c1, r1 = _make_client("alice", shift=1)
        c2, r2 = _make_client("alice", shift=2)
        room.join(c1)
        room.join(c2)  # should replace c1
        assert room.size == 1
        assert room.members() == ["alice"]
        r1.close()
        r2.close()
        c1.sock.close()
        c2.sock.close()

    def test_broadcast_system(self) -> None:
        """broadcast_system sends unencrypted message to all (except excluded)."""
        room = Room("test")
        c1, r1 = _make_client("alice")
        c2, r2 = _make_client("bob")
        room.join(c1)
        room.join(c2)

        join_msg = Message(
            msg_type=MessageType.JOIN,
            sender="alice",
            room="test",
            extra={"info": "alice joined"},
        )
        room.broadcast_system(join_msg, exclude="alice")

        # Bob should receive it, alice should not
        r2.settimeout(2.0)
        msg = _recv_one_message(r2)
        assert msg.msg_type == MessageType.JOIN
        assert msg.sender == "alice"

        # alice's socket should have nothing
        r1.settimeout(0.2)
        with pytest.raises((socket.timeout, OSError, BlockingIOError)):
            _recv_one_message(r1)

        r1.close()
        r2.close()
        c1.sock.close()
        c2.sock.close()

    def test_broadcast_encrypted(self) -> None:
        """broadcast encrypts the payload individually per client."""
        room = Room("test")
        # alice: caesar shift=3, bob: caesar shift=10
        c1, r1 = _make_client("alice", shift=3)
        c2, r2 = _make_client("bob", shift=10)
        room.join(c1)
        room.join(c2)

        plaintext = b"Hello, world!"
        chat_msg = Message(
            msg_type=MessageType.CHAT,
            sender="carol",
            room="test",
            payload=plaintext,
        )
        # Carol sends, both alice and bob should get encrypted copies
        room.broadcast(chat_msg)

        r1.settimeout(2.0)
        r2.settimeout(2.0)

        msg_alice = _recv_one_message(r1)
        msg_bob = _recv_one_message(r2)

        # Each should be encrypted with their own key
        caesar = CipherRegistry.get("caesar")
        pt_alice = caesar.decrypt(msg_alice.payload, CaesarKey(shift=3))
        pt_bob = caesar.decrypt(msg_bob.payload, CaesarKey(shift=10))

        assert pt_alice == plaintext
        assert pt_bob == plaintext

        # The ciphertext should differ because keys differ (for non-trivial plaintext)
        assert msg_alice.payload != msg_bob.payload

        r1.close()
        r2.close()
        c1.sock.close()
        c2.sock.close()

    def test_broadcast_exclude_sender(self) -> None:
        """broadcast with exclude should skip the sender."""
        room = Room("test")
        c1, r1 = _make_client("alice", shift=1)
        c2, r2 = _make_client("bob", shift=2)
        room.join(c1)
        room.join(c2)

        chat_msg = Message(
            msg_type=MessageType.CHAT,
            sender="alice",
            room="test",
            payload=b"hi",
        )
        room.broadcast(chat_msg, exclude="alice")

        # Bob gets it
        r2.settimeout(2.0)
        msg = _recv_one_message(r2)
        assert msg.sender == "alice"

        # Alice does not
        r1.settimeout(0.2)
        with pytest.raises((socket.timeout, OSError, BlockingIOError)):
            _recv_one_message(r1)

        r1.close()
        r2.close()
        c1.sock.close()
        c2.sock.close()

    def test_broadcast_handles_closed_socket(self) -> None:
        """broadcast should not crash if a client's socket is closed."""
        room = Room("test")
        c1, r1 = _make_client("alice", shift=1)
        c2, r2 = _make_client("bob", shift=2)
        room.join(c1)
        room.join(c2)

        # Close bob's socket before broadcast
        c2.sock.close()
        r2.close()

        chat_msg = Message(
            msg_type=MessageType.CHAT,
            sender="carol",
            room="test",
            payload=b"test",
        )
        # Should not raise
        room.broadcast(chat_msg)

        # Alice should still get her message
        r1.settimeout(2.0)
        msg = _recv_one_message(r1)
        assert msg.sender == "carol"

        r1.close()
        c1.sock.close()

    def test_repr(self) -> None:
        room = Room("lobby")
        assert "lobby" in repr(room)

    def test_thread_safety_concurrent_joins(self) -> None:
        """Concurrent joins from multiple threads shouldn't corrupt state."""
        room = Room("test")
        clients = []
        readers = []
        for i in range(20):
            c, r = _make_client(f"user{i}", shift=i % 256)
            clients.append(c)
            readers.append(r)

        errors: list[Exception] = []

        def join_client(client: ClientInfo) -> None:
            try:
                room.join(client)
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=join_client, args=(c,)) for c in clients]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=5)

        assert not errors
        assert room.size == 20
        assert len(room.members()) == 20

        for r in readers:
            r.close()
        for c in clients:
            c.sock.close()


# ---------------------------------------------------------------------------
# RoomManager tests
# ---------------------------------------------------------------------------


class TestRoomManager:
    def test_get_or_create(self) -> None:
        rm = RoomManager()
        room = rm.get_or_create("general")
        assert isinstance(room, Room)
        assert room.name == "general"

    def test_get_or_create_returns_same(self) -> None:
        rm = RoomManager()
        r1 = rm.get_or_create("general")
        r2 = rm.get_or_create("general")
        assert r1 is r2

    def test_get_nonexistent(self) -> None:
        rm = RoomManager()
        assert rm.get("no-such-room") is None

    def test_get_existing(self) -> None:
        rm = RoomManager()
        rm.get_or_create("lobby")
        assert rm.get("lobby") is not None

    def test_list_rooms(self) -> None:
        rm = RoomManager()
        rm.get_or_create("beta")
        rm.get_or_create("alpha")
        assert rm.list_rooms() == ["alpha", "beta"]

    def test_room_count(self) -> None:
        rm = RoomManager()
        assert rm.room_count == 0
        rm.get_or_create("a")
        rm.get_or_create("b")
        assert rm.room_count == 2

    def test_remove_if_empty(self) -> None:
        rm = RoomManager()
        room = rm.get_or_create("temp")
        assert rm.remove_if_empty("temp") is True
        assert rm.get("temp") is None

    def test_remove_if_empty_with_members(self) -> None:
        rm = RoomManager()
        room = rm.get_or_create("busy")
        c, r = _make_client("alice")
        room.join(c)
        assert rm.remove_if_empty("busy") is False
        assert rm.get("busy") is not None
        r.close()
        c.sock.close()

    def test_remove_nonexistent(self) -> None:
        rm = RoomManager()
        assert rm.remove_if_empty("nope") is False

    def test_repr(self) -> None:
        rm = RoomManager()
        rm.get_or_create("x")
        assert "x" in repr(rm)
