"""Length-prefixed TCP framing for the SecureChat protocol.

Wire format::

    ┌──────────────┬──────────────────────┬───────────────┐
    │ Header Length │     JSON Header      │ Binary Payload│
    │   (4 bytes)  │  (variable length)   │  (variable)   │
    └──────────────┴──────────────────────┴───────────────┘

- **Header Length**: 4-byte big-endian unsigned int (``>I``).
- **JSON Header**: UTF-8 encoded JSON containing message metadata.
- **Binary Payload**: Raw bytes (encrypted for CHAT messages, empty otherwise).

Functions:
    send_message(sock, msg)   — serialise and send a ``Message``.
    recv_message(sock)        — receive and deserialise a ``Message``.
"""

from __future__ import annotations

import socket
import struct

from securechat.protocol.message import Message


def _recv_exactly(sock: socket.socket, n: int) -> bytes:
    """Read exactly *n* bytes from *sock*.

    Raises:
        ConnectionError: If the connection is closed before *n* bytes are read.
    """
    data = bytearray()
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            raise ConnectionError("Connection closed while reading data")
        data.extend(chunk)
    return bytes(data)


def send_message(sock: socket.socket, msg: Message) -> None:
    """Serialise *msg* and send it over *sock* using length-prefixed framing.

    1. Encode the header as JSON bytes.
    2. Send the 4-byte header length.
    3. Send the JSON header.
    4. Send the binary payload.
    """
    header_bytes = msg.to_json_header()
    header_len = struct.pack(">I", len(header_bytes))
    sock.sendall(header_len + header_bytes + msg.payload)


def recv_message(sock: socket.socket) -> Message:
    """Receive and deserialise a ``Message`` from *sock*.

    1. Read 4 bytes → header length.
    2. Read that many bytes → JSON header.
    3. Read ``payload_len`` bytes from the header → binary payload.

    Raises:
        ConnectionError: If the connection is closed mid-message.
    """
    # 1. Header length
    raw_len = _recv_exactly(sock, 4)
    header_len = struct.unpack(">I", raw_len)[0]

    # 2. JSON header
    header_bytes = _recv_exactly(sock, header_len)
    msg = Message.from_json_header(header_bytes)

    # 3. Binary payload (length is stored in the header's payload_len field)
    if msg.payload_len > 0:
        msg.payload = _recv_exactly(sock, msg.payload_len)

    return msg
