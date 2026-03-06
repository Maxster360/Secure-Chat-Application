"""Tests for server/server.py — main server with accept loop (Phase 13)."""

from __future__ import annotations

import socket
import threading
import time

import pytest

import securechat.ciphers  # noqa: F401
from securechat.ciphers.keys import CaesarKey
from securechat.protocol.framing import recv_message, send_message
from securechat.protocol.handshake import client_handshake
from securechat.protocol.message import Message, MessageType
from securechat.server.server import ChatServer


class TestChatServer:
    """Tests for the ChatServer accept loop and lifecycle."""

    def _make_server(self) -> ChatServer:
        """Create a server bound to an OS-assigned port."""
        server = ChatServer(host="127.0.0.1", port=0)
        server.start()
        # Give the accept thread a moment to be ready
        time.sleep(0.1)
        return server

    def _connect(self, server: ChatServer) -> socket.socket:
        """Create a TCP connection to the running server."""
        host, port = server.address
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5.0)
        sock.connect((host, port))
        return sock

    def test_start_and_stop(self) -> None:
        """Server starts, is_running is True, then stops cleanly."""
        server = self._make_server()
        try:
            assert server.is_running
            host, port = server.address
            assert port > 0
        finally:
            server.stop()
        assert not server.is_running

    def test_accept_single_client(self) -> None:
        """Server accepts a connection, client completes handshake."""
        server = self._make_server()
        try:
            sock = self._connect(server)
            key = CaesarKey(shift=7)
            ok = client_handshake(sock, "alice", "general", "caesar", key)
            assert ok is True

            # Should receive LIST_USERS
            msg = recv_message(sock)
            assert msg.msg_type == MessageType.LIST_USERS
            assert "alice" in msg.extra.get("users", "")

            sock.close()
        finally:
            server.stop()

    def test_accept_multiple_clients(self) -> None:
        """Server handles multiple concurrent client connections."""
        server = self._make_server()
        try:
            sockets = []
            for i in range(3):
                sock = self._connect(server)
                key = CaesarKey(shift=i + 1)
                ok = client_handshake(sock, f"user{i}", "multi", "caesar", key)
                assert ok is True
                # Drain messages (LIST_USERS, possibly JOINs)
                sock.settimeout(2.0)
                try:
                    while True:
                        recv_message(sock)
                except (socket.timeout, ConnectionError):
                    pass
                sockets.append(sock)

            # Verify room has all 3 members
            room = server.room_manager.get("multi")
            assert room is not None
            assert room.size == 3

            for sock in sockets:
                sock.close()
        finally:
            server.stop()

    def test_repr(self) -> None:
        server = self._make_server()
        try:
            assert "running" in repr(server)
        finally:
            server.stop()
        assert "stopped" in repr(server)

    def test_address_before_bind(self) -> None:
        """address returns defaults before the server is started."""
        server = ChatServer(host="1.2.3.4", port=9999)
        assert server.address == ("1.2.3.4", 9999)

    def test_stop_idempotent(self) -> None:
        """Calling stop() multiple times doesn't crash."""
        server = self._make_server()
        server.stop()
        server.stop()  # should not raise

    def test_room_manager_shared(self) -> None:
        """The server's room_manager is accessible and shared."""
        server = self._make_server()
        try:
            sock = self._connect(server)
            key = CaesarKey(shift=1)
            ok = client_handshake(sock, "tester", "shared", "caesar", key)
            assert ok is True

            # Drain LIST_USERS
            recv_message(sock)

            assert "shared" in server.room_manager.list_rooms()
            sock.close()
        finally:
            server.stop()
