"""Thread-safe chat room management.

Each ``Room`` holds a set of connected clients and can broadcast messages
to all members.  The ``RoomManager`` is a top-level registry of all active
rooms, creating them on demand.

Both classes are fully thread-safe — every mutation is protected by a
``threading.Lock``.
"""

from __future__ import annotations

import logging
import socket
import threading
from dataclasses import dataclass, field
from typing import Any

from securechat.ciphers.base import BaseCipher
from securechat.protocol.framing import send_message
from securechat.protocol.message import Message, MessageType

logger = logging.getLogger(__name__)


@dataclass
class ClientInfo:
    """Metadata about a connected client."""

    username: str
    sock: socket.socket
    cipher: BaseCipher
    key: Any
    room_name: str

    def __hash__(self) -> int:
        return id(self.sock)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, ClientInfo):
            return NotImplemented
        return self.sock is other.sock


class Room:
    """A named chat room that holds clients and broadcasts messages.

    All public methods are thread-safe.
    """

    def __init__(self, name: str) -> None:
        self.name = name
        self._clients: dict[str, ClientInfo] = {}  # username -> ClientInfo
        self._lock = threading.Lock()

    # ------------------------------------------------------------------
    # Membership
    # ------------------------------------------------------------------

    def join(self, client: ClientInfo) -> None:
        """Add *client* to this room.

        If a client with the same username is already present, the old entry
        is silently replaced (this handles reconnection scenarios).
        """
        with self._lock:
            self._clients[client.username] = client
        logger.info(
            "Room %r: %s joined (%d members)", self.name, client.username, len(self._clients)
        )

    def leave(self, username: str) -> ClientInfo | None:
        """Remove *username* from this room.

        Returns:
            The removed ``ClientInfo``, or ``None`` if the user was not in the room.
        """
        with self._lock:
            client = self._clients.pop(username, None)
        if client:
            logger.info("Room %r: %s left (%d members)", self.name, username, len(self._clients))
        return client

    def has_member(self, username: str) -> bool:
        """Return True if *username* is currently in this room."""
        with self._lock:
            return username in self._clients

    def members(self) -> list[str]:
        """Return a sorted list of usernames currently in this room."""
        with self._lock:
            return sorted(self._clients.keys())

    @property
    def size(self) -> int:
        """Return the number of clients in this room."""
        with self._lock:
            return len(self._clients)

    @property
    def is_empty(self) -> bool:
        """Return True if no clients are in this room."""
        with self._lock:
            return len(self._clients) == 0

    # ------------------------------------------------------------------
    # Broadcasting
    # ------------------------------------------------------------------

    def broadcast(self, msg: Message, exclude: str = "") -> None:
        """Send *msg* to every client in this room except *exclude*.

        Each client's copy of the message is encrypted with that client's
        own cipher and key.  Failures are logged but do not stop the
        broadcast to other clients.

        Args:
            msg: The message to broadcast.  ``msg.payload`` should contain
                 the **plaintext** bytes.  Each recipient's copy will be
                 encrypted individually.
            exclude: Username to skip (typically the sender).
        """
        with self._lock:
            targets = [c for c in self._clients.values() if c.username != exclude]

        plaintext = msg.payload
        for client in targets:
            try:
                ciphertext = client.cipher.encrypt(plaintext, client.key)
                encrypted_msg = Message(
                    msg_type=msg.msg_type,
                    sender=msg.sender,
                    room=self.name,
                    cipher=client.cipher.name,
                    payload_len=len(ciphertext),
                    payload=ciphertext,
                    extra=dict(msg.extra),
                )
                send_message(client.sock, encrypted_msg)
            except (OSError, ConnectionError) as e:
                logger.warning(
                    "Room %r: failed to send to %s: %s",
                    self.name,
                    client.username,
                    e,
                )

    def broadcast_system(self, msg: Message, exclude: str = "") -> None:
        """Broadcast a system (non-encrypted) message to all clients.

        Used for JOIN, LEAVE, LIST_USERS, and ERROR notifications that
        don't carry encrypted payloads.

        Args:
            msg: The system message to send.
            exclude: Username to skip.
        """
        with self._lock:
            targets = [c for c in self._clients.values() if c.username != exclude]

        for client in targets:
            try:
                send_message(client.sock, msg)
            except (OSError, ConnectionError) as e:
                logger.warning(
                    "Room %r: failed to send system msg to %s: %s",
                    self.name,
                    client.username,
                    e,
                )

    def __repr__(self) -> str:
        return f"Room(name={self.name!r}, size={self.size})"


class RoomManager:
    """Registry of active chat rooms, created on demand.

    Thread-safe: rooms are created lazily when a client first joins.
    """

    def __init__(self) -> None:
        self._rooms: dict[str, Room] = {}
        self._lock = threading.Lock()

    def get_or_create(self, name: str) -> Room:
        """Return the ``Room`` with *name*, creating it if needed."""
        with self._lock:
            if name not in self._rooms:
                self._rooms[name] = Room(name)
                logger.info("Created room %r", name)
            return self._rooms[name]

    def get(self, name: str) -> Room | None:
        """Return the ``Room`` with *name*, or ``None`` if it doesn't exist."""
        with self._lock:
            return self._rooms.get(name)

    def remove_if_empty(self, name: str) -> bool:
        """Remove *name* from the registry if the room is empty.

        Returns:
            True if the room was removed, False otherwise.
        """
        with self._lock:
            room = self._rooms.get(name)
            if room and room.is_empty:
                del self._rooms[name]
                logger.info("Removed empty room %r", name)
                return True
            return False

    def list_rooms(self) -> list[str]:
        """Return a sorted list of room names."""
        with self._lock:
            return sorted(self._rooms.keys())

    @property
    def room_count(self) -> int:
        """Return the number of active rooms."""
        with self._lock:
            return len(self._rooms)

    def __repr__(self) -> str:
        return f"RoomManager(rooms={self.list_rooms()})"
