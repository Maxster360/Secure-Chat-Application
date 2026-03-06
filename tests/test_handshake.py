"""Tests for the handshake protocol (Phase 10).

Uses ``socket.socketpair()`` to create connected socket pairs so we can test
the full client/server handshake over real TCP framing without a network.
"""

from __future__ import annotations

import json
import socket
import threading

import pytest

# Ensure ciphers are registered before handshake tests run
import securechat.ciphers  # noqa: F401
from securechat.ciphers.keys import (
    CaesarKey,
    ColumnarKey,
    HillKey,
    VigenereKey,
)
from securechat.protocol.framing import recv_message, send_message
from securechat.protocol.handshake import (
    HandshakeResult,
    client_handshake,
    deserialize_key,
    serialize_key,
    server_handshake,
)
from securechat.protocol.message import Message, MessageType


# ---------------------------------------------------------------------------
# Key serialisation / deserialisation round-trips
# ---------------------------------------------------------------------------


class TestSerializeKey:
    """Test key serialisation to JSON string."""

    def test_caesar_key(self) -> None:
        key = CaesarKey(shift=42)
        data = serialize_key(key)
        d = json.loads(data)
        assert d["type"] == "caesar"
        assert d["shift"] == 42

    def test_vigenere_key(self) -> None:
        key = VigenereKey(key_bytes=b"\x01\x02\xff")
        data = serialize_key(key)
        d = json.loads(data)
        assert d["type"] == "vigenere"
        # base64 of b"\x01\x02\xff" is "AQL/"
        import base64

        assert base64.b64decode(d["key_bytes"]) == b"\x01\x02\xff"

    def test_hill_key(self) -> None:
        key = HillKey(matrix=((1, 2), (3, 5)), size=2)
        data = serialize_key(key)
        d = json.loads(data)
        assert d["type"] == "hill"
        assert d["matrix"] == [[1, 2], [3, 5]]
        assert d["size"] == 2

    def test_columnar_key(self) -> None:
        key = ColumnarKey(permutation=(2, 0, 1))
        data = serialize_key(key)
        d = json.loads(data)
        assert d["type"] == "columnar"
        assert d["permutation"] == [2, 0, 1]

    def test_unknown_key_type_raises(self) -> None:
        with pytest.raises(ValueError, match="Cannot serialise"):
            serialize_key("not a key")  # type: ignore[arg-type]


class TestDeserializeKey:
    """Test key deserialisation from JSON string."""

    def test_caesar_roundtrip(self) -> None:
        original = CaesarKey(shift=100)
        result = deserialize_key(serialize_key(original))
        assert isinstance(result, CaesarKey)
        assert result.shift == 100

    def test_vigenere_roundtrip(self) -> None:
        original = VigenereKey(key_bytes=b"secret")
        result = deserialize_key(serialize_key(original))
        assert isinstance(result, VigenereKey)
        assert result.key_bytes == b"secret"

    def test_hill_roundtrip(self) -> None:
        original = HillKey(matrix=((3, 5), (7, 11)), size=2)
        result = deserialize_key(serialize_key(original))
        assert isinstance(result, HillKey)
        assert result.matrix == ((3, 5), (7, 11))
        assert result.size == 2

    def test_columnar_roundtrip(self) -> None:
        original = ColumnarKey(permutation=(1, 0, 2))
        result = deserialize_key(serialize_key(original))
        assert isinstance(result, ColumnarKey)
        assert result.permutation == (1, 0, 2)

    def test_unknown_type_raises(self) -> None:
        with pytest.raises(ValueError, match="Unknown key type"):
            deserialize_key('{"type": "rot13"}')

    def test_malformed_json_raises(self) -> None:
        with pytest.raises(json.JSONDecodeError):
            deserialize_key("not json at all{{{")

    def test_missing_fields_raises(self) -> None:
        with pytest.raises(KeyError):
            deserialize_key('{"type": "caesar"}')  # missing shift


# ---------------------------------------------------------------------------
# Full handshake integration tests using socket pairs
# ---------------------------------------------------------------------------


def _run_in_thread(fn, *args, **kwargs):
    """Run *fn* in a thread and return the thread + a container for the result."""
    result_box: list = []
    error_box: list = []

    def wrapper():
        try:
            result_box.append(fn(*args, **kwargs))
        except Exception as e:
            error_box.append(e)

    t = threading.Thread(target=wrapper, daemon=True)
    t.start()
    return t, result_box, error_box


class TestHandshakeIntegration:
    """Full client <-> server handshake over socket pairs."""

    def _make_pair(self) -> tuple[socket.socket, socket.socket]:
        """Create a connected pair of sockets."""
        return socket.socketpair()

    def test_caesar_handshake_success(self) -> None:
        client_sock, server_sock = self._make_pair()
        try:
            key = CaesarKey(shift=7)
            t, results, errors = _run_in_thread(server_handshake, server_sock)

            ok = client_handshake(client_sock, "alice", "general", "caesar", key)
            t.join(timeout=5)

            assert ok is True
            assert not errors
            assert len(results) == 1
            hs: HandshakeResult = results[0]
            assert hs.success is True
            assert hs.username == "alice"
            assert hs.room == "general"
            assert hs.cipher_name == "caesar"
            assert isinstance(hs.key, CaesarKey)
            assert hs.key.shift == 7
        finally:
            client_sock.close()
            server_sock.close()

    def test_vigenere_handshake_success(self) -> None:
        client_sock, server_sock = self._make_pair()
        try:
            key = VigenereKey(key_bytes=b"mysecretkey")
            t, results, errors = _run_in_thread(server_handshake, server_sock)

            ok = client_handshake(client_sock, "bob", "crypto-club", "vigenere", key)
            t.join(timeout=5)

            assert ok is True
            assert not errors
            hs: HandshakeResult = results[0]
            assert hs.success is True
            assert hs.username == "bob"
            assert hs.room == "crypto-club"
            assert hs.cipher_name == "vigenere"
            assert isinstance(hs.key, VigenereKey)
            assert hs.key.key_bytes == b"mysecretkey"
        finally:
            client_sock.close()
            server_sock.close()

    def test_columnar_handshake_success(self) -> None:
        client_sock, server_sock = self._make_pair()
        try:
            key = ColumnarKey(permutation=(2, 0, 3, 1))
            t, results, errors = _run_in_thread(server_handshake, server_sock)

            ok = client_handshake(client_sock, "carol", "general", "columnar", key)
            t.join(timeout=5)

            assert ok is True
            assert not errors
            hs: HandshakeResult = results[0]
            assert hs.success is True
            assert hs.cipher_name == "columnar"
            assert isinstance(hs.key, ColumnarKey)
            assert hs.key.permutation == (2, 0, 3, 1)
        finally:
            client_sock.close()
            server_sock.close()

    def test_hill_handshake_success(self) -> None:
        client_sock, server_sock = self._make_pair()
        try:
            # Use a matrix that is invertible mod 256: det = 1*5 - 2*3 = -1 ≡ 255 mod 256
            # gcd(255, 256) = 1, so it's invertible
            key = HillKey(matrix=((1, 2), (3, 5)), size=2)
            t, results, errors = _run_in_thread(server_handshake, server_sock)

            ok = client_handshake(client_sock, "dave", "math-room", "hill", key)
            t.join(timeout=5)

            assert ok is True
            assert not errors
            hs: HandshakeResult = results[0]
            assert hs.success is True
            assert hs.cipher_name == "hill"
            assert isinstance(hs.key, HillKey)
            assert hs.key.matrix == ((1, 2), (3, 5))
        finally:
            client_sock.close()
            server_sock.close()

    def test_unsupported_cipher_rejected(self) -> None:
        """Server should reject a cipher it doesn't know about."""
        client_sock, server_sock = self._make_pair()
        try:
            key = CaesarKey(shift=7)
            t, results, errors = _run_in_thread(server_handshake, server_sock)

            # Manually send a HANDSHAKE_INIT with an unknown cipher name
            init_msg = Message(
                msg_type=MessageType.HANDSHAKE_INIT,
                sender="eve",
                room="general",
                cipher="aes256",  # not a classical cipher!
                extra={"key": serialize_key(key)},
            )
            send_message(client_sock, init_msg)

            # Read the ACK
            ack = recv_message(client_sock)
            t.join(timeout=5)

            assert ack.msg_type == MessageType.HANDSHAKE_ACK
            assert ack.extra.get("status") == "error"
            assert "aes256" in ack.extra.get("error", "")

            assert not errors
            hs: HandshakeResult = results[0]
            assert hs.success is False
        finally:
            client_sock.close()
            server_sock.close()

    def test_no_key_rejected(self) -> None:
        """Server should reject when no key is provided."""
        client_sock, server_sock = self._make_pair()
        try:
            t, results, errors = _run_in_thread(server_handshake, server_sock)

            init_msg = Message(
                msg_type=MessageType.HANDSHAKE_INIT,
                sender="eve",
                room="general",
                cipher="caesar",
                extra={},  # no key!
            )
            send_message(client_sock, init_msg)

            ack = recv_message(client_sock)
            t.join(timeout=5)

            assert ack.extra.get("status") == "error"
            assert "No key" in ack.extra.get("error", "")

            assert not errors
            assert results[0].success is False
        finally:
            client_sock.close()
            server_sock.close()

    def test_invalid_key_data_rejected(self) -> None:
        """Server should reject garbage key data."""
        client_sock, server_sock = self._make_pair()
        try:
            t, results, errors = _run_in_thread(server_handshake, server_sock)

            init_msg = Message(
                msg_type=MessageType.HANDSHAKE_INIT,
                sender="eve",
                room="general",
                cipher="caesar",
                extra={"key": "not valid json {{{"},
            )
            send_message(client_sock, init_msg)

            ack = recv_message(client_sock)
            t.join(timeout=5)

            assert ack.extra.get("status") == "error"
            assert not errors
            assert results[0].success is False
        finally:
            client_sock.close()
            server_sock.close()

    def test_wrong_initial_message_type(self) -> None:
        """Server should reject if the first message isn't HANDSHAKE_INIT."""
        client_sock, server_sock = self._make_pair()
        try:
            t, results, errors = _run_in_thread(server_handshake, server_sock)

            # Send a CHAT message instead of HANDSHAKE_INIT
            bad_msg = Message(
                msg_type=MessageType.CHAT,
                sender="eve",
                payload=b"hello",
                payload_len=5,
            )
            send_message(client_sock, bad_msg)

            ack = recv_message(client_sock)
            t.join(timeout=5)

            assert ack.msg_type == MessageType.HANDSHAKE_ACK
            assert ack.extra.get("status") == "error"

            assert not errors
            assert results[0].success is False
        finally:
            client_sock.close()
            server_sock.close()

    def test_empty_room_defaults_to_general(self) -> None:
        """If room is empty, server defaults it to 'general'."""
        client_sock, server_sock = self._make_pair()
        try:
            key = CaesarKey(shift=1)
            t, results, errors = _run_in_thread(server_handshake, server_sock)

            ok = client_handshake(client_sock, "frank", "", "caesar", key)
            t.join(timeout=5)

            assert ok is True
            assert not errors
            hs: HandshakeResult = results[0]
            assert hs.room == "general"
        finally:
            client_sock.close()
            server_sock.close()

    def test_client_gets_false_on_rejection(self) -> None:
        """client_handshake() should return False when server rejects."""
        client_sock, server_sock = self._make_pair()
        try:
            # Server side: send back an error ACK manually
            def fake_server():
                msg = recv_message(server_sock)
                ack = Message(
                    msg_type=MessageType.HANDSHAKE_ACK,
                    extra={"status": "error", "error": "testing rejection"},
                )
                send_message(server_sock, ack)

            t = threading.Thread(target=fake_server, daemon=True)
            t.start()

            key = CaesarKey(shift=10)
            ok = client_handshake(client_sock, "george", "general", "caesar", key)
            t.join(timeout=5)

            assert ok is False
        finally:
            client_sock.close()
            server_sock.close()

    def test_client_gets_false_on_wrong_ack_type(self) -> None:
        """client_handshake() returns False if response isn't HANDSHAKE_ACK."""
        client_sock, server_sock = self._make_pair()
        try:

            def fake_server():
                msg = recv_message(server_sock)
                # Send back an ERROR instead of HANDSHAKE_ACK
                bad_ack = Message(
                    msg_type=MessageType.ERROR,
                    extra={"error": "something weird"},
                )
                send_message(server_sock, bad_ack)

            t = threading.Thread(target=fake_server, daemon=True)
            t.start()

            key = CaesarKey(shift=10)
            ok = client_handshake(client_sock, "helen", "general", "caesar", key)
            t.join(timeout=5)

            assert ok is False
        finally:
            client_sock.close()
            server_sock.close()

    def test_hill_invalid_key_rejected(self) -> None:
        """Server rejects Hill key whose matrix is not invertible mod 256."""
        client_sock, server_sock = self._make_pair()
        try:
            t, results, errors = _run_in_thread(server_handshake, server_sock)

            # det = 2*4 - 2*4 = 0, not invertible mod 256
            bad_key_data = json.dumps(
                {
                    "type": "hill",
                    "matrix": [[2, 2], [4, 4]],
                    "size": 2,
                }
            )
            init_msg = Message(
                msg_type=MessageType.HANDSHAKE_INIT,
                sender="ivan",
                room="general",
                cipher="hill",
                extra={"key": bad_key_data},
            )
            send_message(client_sock, init_msg)

            ack = recv_message(client_sock)
            t.join(timeout=5)

            assert ack.extra.get("status") == "error"
            assert not errors
            assert results[0].success is False
        finally:
            client_sock.close()
            server_sock.close()


# ---------------------------------------------------------------------------
# HandshakeResult tests
# ---------------------------------------------------------------------------


class TestHandshakeResult:
    """Test the HandshakeResult data class."""

    def test_success_result(self) -> None:
        hr = HandshakeResult(
            success=True,
            username="alice",
            room="general",
            cipher_name="caesar",
            key=CaesarKey(shift=7),
        )
        assert hr.success is True
        assert hr.username == "alice"
        assert hr.error == ""

    def test_failure_result(self) -> None:
        hr = HandshakeResult(success=False, error="bad cipher")
        assert hr.success is False
        assert hr.username == ""
        assert hr.error == "bad cipher"

    def test_defaults(self) -> None:
        hr = HandshakeResult(success=False)
        assert hr.username == ""
        assert hr.room == ""
        assert hr.cipher_name == ""
        assert hr.key is None
        assert hr.error == ""
