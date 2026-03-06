"""Handshake protocol for cipher negotiation and key exchange.

The handshake is the first exchange after a TCP connection is established.
It lets the client propose a cipher and transmit the key (in plaintext),
and the server responds to confirm or reject.

Flow::

    Client                              Server
      |                                    |
      |──HANDSHAKE_INIT───────────────────>|
      |  cipher, username, room, key(hex)  |
      |                                    |
      |<──HANDSHAKE_ACK────────────────────|
      |  status="ok" or status="error"     |

Key exchange is plaintext — this is an intentional limitation of classical
ciphers and is documented as such.
"""

from __future__ import annotations

import base64
import json
import logging
import socket
from typing import Any

from securechat.ciphers import CipherRegistry
from securechat.ciphers.keys import (
    CaesarKey,
    ColumnarKey,
    HillKey,
    VigenereKey,
)
from securechat.protocol.framing import recv_message, send_message
from securechat.protocol.message import Message, MessageType

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Key serialisation helpers
# ---------------------------------------------------------------------------


def serialize_key(key: Any) -> str:
    """Serialise a cipher key to a JSON string for transmission."""
    if isinstance(key, CaesarKey):
        return json.dumps({"type": "caesar", "shift": key.shift})
    if isinstance(key, VigenereKey):
        return json.dumps(
            {
                "type": "vigenere",
                "key_bytes": base64.b64encode(key.key_bytes).decode("ascii"),
            }
        )
    if isinstance(key, HillKey):
        return json.dumps(
            {
                "type": "hill",
                "matrix": [list(row) for row in key.matrix],
                "size": key.size,
            }
        )
    if isinstance(key, ColumnarKey):
        return json.dumps(
            {
                "type": "columnar",
                "permutation": list(key.permutation),
            }
        )
    raise ValueError(f"Cannot serialise key of type {type(key).__name__}")


def deserialize_key(data: str) -> Any:
    """Deserialise a cipher key from a JSON string.

    Raises:
        ValueError: If the key type is unknown or the data is malformed.
    """
    d = json.loads(data)
    key_type = d.get("type", "")

    if key_type == "caesar":
        return CaesarKey(shift=int(d["shift"]))
    if key_type == "vigenere":
        return VigenereKey(key_bytes=base64.b64decode(d["key_bytes"]))
    if key_type == "hill":
        return HillKey.from_lists(d["matrix"])
    if key_type == "columnar":
        return ColumnarKey(permutation=tuple(d["permutation"]))

    raise ValueError(f"Unknown key type: {key_type!r}")


# ---------------------------------------------------------------------------
# Client-side handshake
# ---------------------------------------------------------------------------


def client_handshake(
    sock: socket.socket,
    username: str,
    room: str,
    cipher_name: str,
    key: Any,
) -> bool:
    """Perform the client side of the handshake.

    Sends a HANDSHAKE_INIT and waits for a HANDSHAKE_ACK.

    Returns:
        True if the server accepted the handshake, False otherwise.
    """
    key_data = serialize_key(key)
    init_msg = Message(
        msg_type=MessageType.HANDSHAKE_INIT,
        sender=username,
        room=room,
        cipher=cipher_name,
        extra={"key": key_data},
    )
    send_message(sock, init_msg)
    logger.debug("Sent HANDSHAKE_INIT: cipher=%s, room=%s", cipher_name, room)

    ack = recv_message(sock)
    if ack.msg_type != MessageType.HANDSHAKE_ACK:
        logger.error("Expected HANDSHAKE_ACK, got %s", ack.msg_type)
        return False

    status = ack.extra.get("status", "error")
    if status != "ok":
        error_msg = ack.extra.get("error", "Unknown error")
        logger.error("Handshake rejected: %s", error_msg)
        return False

    logger.debug("Handshake accepted by server")
    return True


# ---------------------------------------------------------------------------
# Server-side handshake
# ---------------------------------------------------------------------------


class HandshakeResult:
    """Result of a server-side handshake."""

    def __init__(
        self,
        success: bool,
        username: str = "",
        room: str = "",
        cipher_name: str = "",
        key: Any = None,
        error: str = "",
    ) -> None:
        self.success = success
        self.username = username
        self.room = room
        self.cipher_name = cipher_name
        self.key = key
        self.error = error


def server_handshake(sock: socket.socket) -> HandshakeResult:
    """Perform the server side of the handshake.

    Waits for a HANDSHAKE_INIT, validates it, stores the key, and sends
    back a HANDSHAKE_ACK.

    Returns:
        A ``HandshakeResult`` with the negotiated parameters or an error.
    """
    try:
        init = recv_message(sock)
    except ConnectionError as e:
        return HandshakeResult(success=False, error=f"Connection error: {e}")

    if init.msg_type != MessageType.HANDSHAKE_INIT:
        _send_handshake_error(sock, f"Expected HANDSHAKE_INIT, got {init.msg_type.name}")
        return HandshakeResult(success=False, error="Wrong initial message type")

    cipher_name = init.cipher
    username = init.sender
    room = init.room or "general"

    # Validate cipher is registered
    try:
        CipherRegistry.get(cipher_name)
    except KeyError:
        _send_handshake_error(sock, f"Unsupported cipher: {cipher_name!r}")
        return HandshakeResult(success=False, error=f"Unsupported cipher: {cipher_name}")

    # Deserialise key
    key_data = init.extra.get("key", "")
    if not key_data:
        _send_handshake_error(sock, "No key provided")
        return HandshakeResult(success=False, error="No key provided")

    try:
        key = deserialize_key(key_data)
    except (ValueError, KeyError, json.JSONDecodeError) as e:
        _send_handshake_error(sock, f"Invalid key: {e}")
        return HandshakeResult(success=False, error=f"Invalid key: {e}")

    # Validate key against cipher
    try:
        cipher = CipherRegistry.get(cipher_name)
        cipher.validate_key(key)
    except ValueError as e:
        _send_handshake_error(sock, f"Key validation failed: {e}")
        return HandshakeResult(success=False, error=f"Key validation failed: {e}")

    # Success — send ACK
    ack = Message(
        msg_type=MessageType.HANDSHAKE_ACK,
        cipher=cipher_name,
        extra={"status": "ok"},
    )
    send_message(sock, ack)
    logger.debug("Handshake OK: user=%s, room=%s, cipher=%s", username, room, cipher_name)

    return HandshakeResult(
        success=True,
        username=username,
        room=room,
        cipher_name=cipher_name,
        key=key,
    )


def _send_handshake_error(sock: socket.socket, error: str) -> None:
    """Send a HANDSHAKE_ACK with error status."""
    ack = Message(
        msg_type=MessageType.HANDSHAKE_ACK,
        extra={"status": "error", "error": error},
    )
    try:
        send_message(sock, ack)
    except (OSError, ConnectionError):
        pass  # best-effort
