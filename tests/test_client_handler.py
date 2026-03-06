"""Tests for server/client_handler.py — per-client thread handler (Phase 12).

These tests exercise the full client handler lifecycle using socket pairs:
handshake → join → chat → leave → cleanup.
"""

from __future__ import annotations

import socket
import struct
import json
import threading
import time

import pytest

import securechat.ciphers  # noqa: F401  — register ciphers
from securechat.ciphers.base import CipherRegistry
from securechat.ciphers.keys import CaesarKey
from securechat.protocol.framing import recv_message, send_message
from securechat.protocol.handshake import serialize_key, client_handshake
from securechat.protocol.message import Message, MessageType
from securechat.server.client_handler import handle_client
from securechat.server.room import RoomManager


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _recv_one_message(sock: socket.socket) -> Message:
    """Read one framed message from *sock* (blocking)."""
    from securechat.protocol.framing import recv_message as _recv

    return _recv(sock)


def _start_handler(
    server_sock: socket.socket,
    room_manager: RoomManager,
    addr: tuple[str, int] = ("127.0.0.1", 9999),
) -> threading.Thread:
    """Start handle_client in a daemon thread."""
    t = threading.Thread(
        target=handle_client,
        args=(server_sock, addr, room_manager),
        daemon=True,
    )
    t.start()
    return t


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestClientHandler:
    """Full lifecycle tests for handle_client."""

    def test_successful_join_and_user_list(self) -> None:
        """Client completes handshake, joins room, and receives user list."""
        client_sock, server_sock = socket.socketpair()
        rm = RoomManager()
        try:
            t = _start_handler(server_sock, rm)

            key = CaesarKey(shift=5)
            ok = client_handshake(client_sock, "alice", "lobby", "caesar", key)
            assert ok is True

            # Should receive LIST_USERS message
            client_sock.settimeout(3.0)
            msg = _recv_one_message(client_sock)
            assert msg.msg_type == MessageType.LIST_USERS
            assert "alice" in msg.extra.get("users", "")

            # Verify room was created
            room = rm.get("lobby")
            assert room is not None
            assert room.has_member("alice")

            # Close to trigger cleanup
            client_sock.close()
            t.join(timeout=5)

        finally:
            try:
                client_sock.close()
            except OSError:
                pass
            try:
                server_sock.close()
            except OSError:
                pass

    def test_chat_message_decrypted_and_broadcast(self) -> None:
        """Two clients: one sends encrypted chat, other receives re-encrypted."""
        # Client A
        clientA_sock, serverA_sock = socket.socketpair()
        # Client B
        clientB_sock, serverB_sock = socket.socketpair()
        rm = RoomManager()

        try:
            tA = _start_handler(serverA_sock, rm, ("127.0.0.1", 1001))
            tB = _start_handler(serverB_sock, rm, ("127.0.0.1", 1002))

            keyA = CaesarKey(shift=3)
            keyB = CaesarKey(shift=10)

            # Handshake both
            okA = client_handshake(clientA_sock, "alice", "chat", "caesar", keyA)
            assert okA is True

            okB = client_handshake(clientB_sock, "bob", "chat", "caesar", keyB)
            assert okB is True

            # Drain the LIST_USERS messages
            clientA_sock.settimeout(3.0)
            clientB_sock.settimeout(3.0)

            msgA = _recv_one_message(clientA_sock)
            assert msgA.msg_type == MessageType.LIST_USERS

            # Bob should also get a JOIN notification from alice (or a LIST_USERS)
            # and then his own LIST_USERS. Let's read until we get LIST_USERS.
            msgs_for_b: list[Message] = []
            for _ in range(3):  # at most 3 messages
                try:
                    m = _recv_one_message(clientB_sock)
                    msgs_for_b.append(m)
                    if m.msg_type == MessageType.LIST_USERS:
                        break
                except (socket.timeout, ConnectionError):
                    break

            # Now alice sends an encrypted CHAT message
            plaintext = b"Hello Bob!"
            cipher = CipherRegistry.get("caesar")
            ciphertext = cipher.encrypt(plaintext, keyA)

            chat_msg = Message(
                msg_type=MessageType.CHAT,
                sender="alice",
                room="chat",
                cipher="caesar",
                payload_len=len(ciphertext),
                payload=ciphertext,
            )
            send_message(clientA_sock, chat_msg)

            # Bob should receive a re-encrypted message
            clientB_sock.settimeout(3.0)
            received = _recv_one_message(clientB_sock)
            assert received.msg_type == MessageType.CHAT
            assert received.sender == "alice"

            # Decrypt with bob's key
            decrypted = cipher.decrypt(received.payload, keyB)
            assert decrypted == plaintext

        finally:
            for s in (clientA_sock, clientB_sock, serverA_sock, serverB_sock):
                try:
                    s.close()
                except OSError:
                    pass
            tA.join(timeout=5)
            tB.join(timeout=5)

    def test_leave_message_triggers_cleanup(self) -> None:
        """Sending a LEAVE message causes the handler to exit cleanly."""
        client_sock, server_sock = socket.socketpair()
        rm = RoomManager()
        try:
            t = _start_handler(server_sock, rm)

            key = CaesarKey(shift=1)
            ok = client_handshake(client_sock, "carol", "temp", "caesar", key)
            assert ok is True

            # Drain LIST_USERS
            client_sock.settimeout(3.0)
            _recv_one_message(client_sock)

            # Send LEAVE
            leave_msg = Message(msg_type=MessageType.LEAVE, sender="carol", room="temp")
            send_message(client_sock, leave_msg)

            # Handler thread should exit
            t.join(timeout=5)
            assert not t.is_alive()

            # Room should be cleaned up (empty -> removed)
            assert rm.get("temp") is None

        finally:
            try:
                client_sock.close()
            except OSError:
                pass
            try:
                server_sock.close()
            except OSError:
                pass

    def test_client_disconnect_triggers_cleanup(self) -> None:
        """Closing the socket mid-session triggers proper cleanup."""
        client_sock, server_sock = socket.socketpair()
        rm = RoomManager()
        try:
            t = _start_handler(server_sock, rm)

            key = CaesarKey(shift=1)
            ok = client_handshake(client_sock, "dave", "volatile", "caesar", key)
            assert ok is True

            # Drain LIST_USERS
            client_sock.settimeout(3.0)
            _recv_one_message(client_sock)

            # Verify dave is in the room
            room = rm.get("volatile")
            assert room is not None
            assert room.has_member("dave")

            # Abruptly close
            client_sock.close()
            t.join(timeout=5)

            # Room should be cleaned up
            assert rm.get("volatile") is None

        finally:
            try:
                client_sock.close()
            except OSError:
                pass
            try:
                server_sock.close()
            except OSError:
                pass

    def test_failed_handshake_closes_cleanly(self) -> None:
        """If handshake fails, handler exits without crashing."""
        client_sock, server_sock = socket.socketpair()
        rm = RoomManager()
        try:
            t = _start_handler(server_sock, rm)

            # Send garbage instead of a proper handshake
            bad_msg = Message(
                msg_type=MessageType.CHAT,
                sender="eve",
                payload=b"no handshake",
                payload_len=12,
            )
            send_message(client_sock, bad_msg)

            # Read the error ACK
            client_sock.settimeout(3.0)
            ack = _recv_one_message(client_sock)
            assert ack.msg_type == MessageType.HANDSHAKE_ACK
            assert ack.extra.get("status") == "error"

            t.join(timeout=5)
            assert not t.is_alive()

            # No rooms should have been created
            assert rm.room_count == 0

        finally:
            try:
                client_sock.close()
            except OSError:
                pass
            try:
                server_sock.close()
            except OSError:
                pass

    def test_list_users_request(self) -> None:
        """Client can request user list mid-session."""
        client_sock, server_sock = socket.socketpair()
        rm = RoomManager()
        try:
            t = _start_handler(server_sock, rm)

            key = CaesarKey(shift=1)
            ok = client_handshake(client_sock, "frank", "general", "caesar", key)
            assert ok is True

            # Drain initial LIST_USERS
            client_sock.settimeout(3.0)
            _recv_one_message(client_sock)

            # Request user list
            list_msg = Message(
                msg_type=MessageType.LIST_USERS,
                sender="frank",
                room="general",
            )
            send_message(client_sock, list_msg)

            # Should receive updated list
            resp = _recv_one_message(client_sock)
            assert resp.msg_type == MessageType.LIST_USERS
            assert "frank" in resp.extra.get("users", "")

            client_sock.close()
            t.join(timeout=5)

        finally:
            try:
                client_sock.close()
            except OSError:
                pass
            try:
                server_sock.close()
            except OSError:
                pass

    def test_join_notification_sent_to_others(self) -> None:
        """When a new client joins, existing members get a JOIN notification."""
        clientA_sock, serverA_sock = socket.socketpair()
        clientB_sock, serverB_sock = socket.socketpair()
        rm = RoomManager()

        try:
            tA = _start_handler(serverA_sock, rm, ("127.0.0.1", 2001))

            keyA = CaesarKey(shift=1)
            okA = client_handshake(clientA_sock, "alice", "notify", "caesar", keyA)
            assert okA is True

            # Drain alice's LIST_USERS
            clientA_sock.settimeout(3.0)
            _recv_one_message(clientA_sock)

            # Now bob joins — alice should get a JOIN notification
            tB = _start_handler(serverB_sock, rm, ("127.0.0.1", 2002))
            keyB = CaesarKey(shift=2)
            okB = client_handshake(clientB_sock, "bob", "notify", "caesar", keyB)
            assert okB is True

            # Alice should receive JOIN from bob
            msg = _recv_one_message(clientA_sock)
            assert msg.msg_type == MessageType.JOIN
            assert msg.sender == "bob"

        finally:
            for s in (clientA_sock, clientB_sock, serverA_sock, serverB_sock):
                try:
                    s.close()
                except OSError:
                    pass
            tA.join(timeout=5)
            tB.join(timeout=5)
