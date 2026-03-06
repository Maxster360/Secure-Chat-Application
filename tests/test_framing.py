"""Tests for the TCP framing layer."""

from __future__ import annotations

import socket
import struct
import threading

import pytest

from securechat.protocol.framing import recv_message, send_message
from securechat.protocol.message import Message, MessageType


def make_socket_pair() -> tuple[socket.socket, socket.socket]:
    """Create a connected pair of TCP sockets for testing."""
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.bind(("127.0.0.1", 0))
    server_sock.listen(1)
    port = server_sock.getsockname()[1]

    client_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_sock.connect(("127.0.0.1", port))

    conn, _ = server_sock.accept()
    server_sock.close()
    return client_sock, conn


class TestFramingRoundTrip:
    def test_chat_message(self) -> None:
        """Send a CHAT message with payload and receive it back."""
        client, server = make_socket_pair()
        try:
            payload = b"Hello, encrypted world!"
            msg = Message(
                msg_type=MessageType.CHAT,
                sender="alice",
                room="general",
                cipher="caesar",
                payload_len=len(payload),
                payload=payload,
            )

            send_message(client, msg)
            received = recv_message(server)

            assert received.msg_type == MessageType.CHAT
            assert received.sender == "alice"
            assert received.room == "general"
            assert received.cipher == "caesar"
            assert received.payload_len == len(payload)
            assert received.payload == payload
        finally:
            client.close()
            server.close()

    def test_control_message_no_payload(self) -> None:
        """Send a JOIN message with no payload."""
        client, server = make_socket_pair()
        try:
            msg = Message(
                msg_type=MessageType.JOIN,
                sender="bob",
                room="general",
            )

            send_message(client, msg)
            received = recv_message(server)

            assert received.msg_type == MessageType.JOIN
            assert received.sender == "bob"
            assert received.room == "general"
            assert received.payload == b""
        finally:
            client.close()
            server.close()

    def test_message_with_extra(self) -> None:
        """Send a LIST_USERS message with extra metadata."""
        client, server = make_socket_pair()
        try:
            msg = Message(
                msg_type=MessageType.LIST_USERS,
                extra={"users": "alice,bob,charlie"},
            )

            send_message(client, msg)
            received = recv_message(server)

            assert received.msg_type == MessageType.LIST_USERS
            assert received.extra == {"users": "alice,bob,charlie"}
        finally:
            client.close()
            server.close()

    def test_binary_payload(self) -> None:
        """Send a message with full byte-range binary payload."""
        client, server = make_socket_pair()
        try:
            payload = bytes(range(256)) * 4  # 1024 bytes
            msg = Message(
                msg_type=MessageType.CHAT,
                sender="alice",
                cipher="vigenere",
                payload_len=len(payload),
                payload=payload,
            )

            send_message(client, msg)
            received = recv_message(server)

            assert received.payload == payload
            assert received.payload_len == len(payload)
        finally:
            client.close()
            server.close()

    def test_multiple_messages(self) -> None:
        """Send and receive multiple messages on the same connection."""
        client, server = make_socket_pair()
        try:
            messages = [
                Message(msg_type=MessageType.JOIN, sender="alice"),
                Message(
                    msg_type=MessageType.CHAT,
                    sender="alice",
                    payload_len=5,
                    payload=b"hello",
                ),
                Message(msg_type=MessageType.LEAVE, sender="alice"),
            ]

            for msg in messages:
                send_message(client, msg)

            for original in messages:
                received = recv_message(server)
                assert received.msg_type == original.msg_type
                assert received.sender == original.sender
                assert received.payload == original.payload
        finally:
            client.close()
            server.close()

    def test_bidirectional(self) -> None:
        """Both sides can send and receive."""
        client, server = make_socket_pair()
        try:
            msg1 = Message(msg_type=MessageType.CHAT, sender="a", payload_len=2, payload=b"hi")
            msg2 = Message(msg_type=MessageType.CHAT, sender="b", payload_len=2, payload=b"yo")

            send_message(client, msg1)
            received1 = recv_message(server)
            assert received1.sender == "a"

            send_message(server, msg2)
            received2 = recv_message(client)
            assert received2.sender == "b"
        finally:
            client.close()
            server.close()


class TestFramingErrors:
    def test_connection_closed_during_header_length(self) -> None:
        """Closing the socket before header length is fully sent."""
        client, server = make_socket_pair()
        try:
            client.sendall(b"\x00\x00")  # only 2 of 4 bytes
            client.close()
            with pytest.raises(ConnectionError):
                recv_message(server)
        finally:
            server.close()

    def test_connection_closed_during_header(self) -> None:
        """Closing the socket after header length but before full header."""
        client, server = make_socket_pair()
        try:
            header = b'{"type": "CHAT", "sender": "alice"}'
            client.sendall(struct.pack(">I", len(header)))
            client.sendall(header[:5])  # partial header
            client.close()
            with pytest.raises(ConnectionError):
                recv_message(server)
        finally:
            server.close()

    def test_connection_closed_during_payload(self) -> None:
        """Closing the socket after header but before full payload."""
        client, server = make_socket_pair()
        try:
            msg = Message(
                msg_type=MessageType.CHAT,
                sender="alice",
                payload_len=100,
                payload=b"short",  # only 5 bytes, but header says 100
            )
            # Manually send to simulate partial payload
            header_bytes = msg.to_json_header()
            client.sendall(struct.pack(">I", len(header_bytes)))
            client.sendall(header_bytes)
            client.sendall(b"short")  # only 5 of 100 bytes
            client.close()
            with pytest.raises(ConnectionError):
                recv_message(server)
        finally:
            server.close()


class TestFramingConcurrent:
    def test_threaded_send_recv(self) -> None:
        """Send from one thread, receive from another."""
        client, server = make_socket_pair()
        results: list[Message] = []
        errors: list[Exception] = []

        def sender() -> None:
            try:
                for i in range(10):
                    payload = f"msg-{i}".encode()
                    msg = Message(
                        msg_type=MessageType.CHAT,
                        sender="alice",
                        payload_len=len(payload),
                        payload=payload,
                    )
                    send_message(client, msg)
            except Exception as e:
                errors.append(e)

        def receiver() -> None:
            try:
                for _ in range(10):
                    msg = recv_message(server)
                    results.append(msg)
            except Exception as e:
                errors.append(e)

        t_send = threading.Thread(target=sender)
        t_recv = threading.Thread(target=receiver)
        t_recv.start()
        t_send.start()
        t_send.join(timeout=5)
        t_recv.join(timeout=5)

        client.close()
        server.close()

        assert not errors, f"Errors occurred: {errors}"
        assert len(results) == 10
        for i, msg in enumerate(results):
            assert msg.payload == f"msg-{i}".encode()
