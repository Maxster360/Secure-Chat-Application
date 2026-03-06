"""Protocol message types and the ``Message`` dataclass.

Every piece of data exchanged between client and server is wrapped in a
``Message``.  The ``MessageType`` enum identifies what kind of message it is,
and the ``Message`` dataclass carries the header fields plus an optional
binary payload.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from enum import Enum, auto


class MessageType(Enum):
    """Types of messages in the SecureChat protocol."""

    HANDSHAKE_INIT = auto()  # Client -> Server: propose cipher + send key
    HANDSHAKE_ACK = auto()  # Server -> Client: confirm cipher
    CHAT = auto()  # Encrypted chat message
    JOIN = auto()  # User joined notification
    LEAVE = auto()  # User left notification
    ERROR = auto()  # Error notification
    LIST_USERS = auto()  # Request/response for online users


@dataclass
class Message:
    """A protocol message with header metadata and optional binary payload.

    Attributes:
        msg_type:    The type of this message.
        sender:      Username of the sender (empty string for server messages).
        room:        Chat room name (empty string if not applicable).
        cipher:      Cipher name used for encryption (empty for unencrypted msgs).
        payload_len: Length of the original plaintext payload in bytes.
                     Used by the Hill cipher to strip padding on the receiver side.
        payload:     Binary payload (encrypted bytes for CHAT, raw bytes otherwise).
        extra:       Additional key-value metadata (e.g. user list, error details).
    """

    msg_type: MessageType
    sender: str = ""
    room: str = ""
    cipher: str = ""
    payload_len: int = 0
    payload: bytes = b""
    extra: dict[str, str] = field(default_factory=dict)

    def to_header_dict(self) -> dict[str, object]:
        """Serialise the header fields to a JSON-compatible dict.

        The ``payload`` is **not** included — it is sent separately as raw
        bytes after the header.
        """
        return {
            "type": self.msg_type.name,
            "sender": self.sender,
            "room": self.room,
            "cipher": self.cipher,
            "payload_len": self.payload_len,
            "extra": self.extra,
        }

    @classmethod
    def from_header_dict(cls, d: dict[str, object], payload: bytes = b"") -> Message:
        """Reconstruct a ``Message`` from a header dict and optional payload.

        Raises:
            KeyError: If required header fields are missing.
            ValueError: If the message type is unknown.
        """
        type_name = str(d["type"])
        try:
            msg_type = MessageType[type_name]
        except KeyError:
            raise ValueError(f"Unknown message type: {type_name!r}") from None

        return cls(
            msg_type=msg_type,
            sender=str(d.get("sender", "")),
            room=str(d.get("room", "")),
            cipher=str(d.get("cipher", "")),
            payload_len=int(d.get("payload_len", 0)),  # type: ignore[arg-type]
            payload=payload,
            extra=dict(d.get("extra", {})),  # type: ignore[arg-type]
        )

    def to_json_header(self) -> bytes:
        """Serialise the header to a UTF-8 JSON bytestring."""
        return json.dumps(self.to_header_dict()).encode("utf-8")

    @classmethod
    def from_json_header(cls, data: bytes, payload: bytes = b"") -> Message:
        """Deserialise a ``Message`` from a UTF-8 JSON header and payload."""
        d = json.loads(data.decode("utf-8"))
        return cls.from_header_dict(d, payload=payload)
