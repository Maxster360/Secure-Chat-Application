"""Client networking with encryption integration.

The ``ChatClient`` connects to a ``ChatServer``, performs the handshake,
and then provides ``send()`` / ``recv()`` methods that handle encryption
and decryption transparently.

Usage::

    from securechat.client.client import ChatClient
    from securechat.ciphers.keys import CaesarKey

    client = ChatClient(
        host="127.0.0.1",
        port=5000,
        username="alice",
        room="general",
        cipher_name="caesar",
        key=CaesarKey(shift=7),
    )
    client.connect()
    client.send_chat("Hello everyone!")

    # In a receive loop (typically a separate thread):
    msg = client.recv()
    print(f"{msg.sender}: {msg.payload.decode()}")

    client.disconnect()
"""

from __future__ import annotations

import logging
import socket
import threading
from typing import Any, Callable

from securechat.ciphers.base import BaseCipher, CipherRegistry
from securechat.protocol.framing import recv_message, send_message
from securechat.protocol.handshake import client_handshake
from securechat.protocol.message import Message, MessageType

logger = logging.getLogger(__name__)


class ChatClient:
    """Client that connects to a SecureChat server with encryption.

    After calling ``connect()``, the client has completed the handshake
    and is ready to send and receive messages.

    Attributes:
        host: Server hostname.
        port: Server port.
        username: Display name for this client.
        room: Chat room to join.
        cipher_name: Name of the cipher to use.
        key: The cipher key object.
    """

    def __init__(
        self,
        host: str,
        port: int,
        username: str,
        room: str,
        cipher_name: str,
        key: Any,
    ) -> None:
        self.host = host
        self.port = port
        self.username = username
        self.room = room
        self.cipher_name = cipher_name
        self.key = key

        self._cipher: BaseCipher = CipherRegistry.get(cipher_name)
        self._sock: socket.socket | None = None
        self._connected = threading.Event()
        self._recv_thread: threading.Thread | None = None
        self._on_message: Callable[[Message], None] | None = None
        self._on_disconnect: Callable[[], None] | None = None

    # ------------------------------------------------------------------
    # Connection lifecycle
    # ------------------------------------------------------------------

    def connect(self, timeout: float = 10.0) -> bool:
        """Connect to the server, perform handshake, and join the room.

        Args:
            timeout: Socket timeout for the connection and handshake.

        Returns:
            True if the connection and handshake succeeded, False otherwise.
        """
        try:
            self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._sock.settimeout(timeout)
            self._sock.connect((self.host, self.port))

            ok = client_handshake(self._sock, self.username, self.room, self.cipher_name, self.key)
            if not ok:
                logger.error("Handshake rejected by server")
                self._sock.close()
                self._sock = None
                return False

            self._connected.set()
            logger.info(
                "Connected to %s:%d as %s (cipher=%s, room=%s)",
                self.host,
                self.port,
                self.username,
                self.cipher_name,
                self.room,
            )
            return True

        except (OSError, ConnectionError) as e:
            logger.error("Connection failed: %s", e)
            if self._sock:
                self._sock.close()
                self._sock = None
            return False

    def disconnect(self) -> None:
        """Disconnect from the server gracefully.

        Sends a LEAVE message and closes the socket.
        """
        if not self._connected.is_set():
            return

        self._connected.clear()

        if self._sock:
            try:
                leave_msg = Message(
                    msg_type=MessageType.LEAVE,
                    sender=self.username,
                    room=self.room,
                )
                send_message(self._sock, leave_msg)
            except (OSError, ConnectionError):
                pass
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None

        if self._recv_thread and self._recv_thread.is_alive():
            self._recv_thread.join(timeout=3)
        self._recv_thread = None
        logger.info("Disconnected from server")

    @property
    def is_connected(self) -> bool:
        """Return True if currently connected to the server."""
        return self._connected.is_set()

    # ------------------------------------------------------------------
    # Sending
    # ------------------------------------------------------------------

    def send_chat(self, text: str) -> None:
        """Encrypt and send a chat message.

        Args:
            text: The plaintext message to send.

        Raises:
            ConnectionError: If not connected.
        """
        self._require_connected()
        plaintext = text.encode("utf-8")
        ciphertext = self._cipher.encrypt(plaintext, self.key)

        msg = Message(
            msg_type=MessageType.CHAT,
            sender=self.username,
            room=self.room,
            cipher=self.cipher_name,
            payload_len=len(ciphertext),
            payload=ciphertext,
        )
        send_message(self._sock, msg)  # type: ignore[arg-type]

    def request_user_list(self) -> None:
        """Request the current room's user list from the server.

        Raises:
            ConnectionError: If not connected.
        """
        self._require_connected()
        msg = Message(
            msg_type=MessageType.LIST_USERS,
            sender=self.username,
            room=self.room,
        )
        send_message(self._sock, msg)  # type: ignore[arg-type]

    # ------------------------------------------------------------------
    # Receiving
    # ------------------------------------------------------------------

    def recv(self) -> Message:
        """Receive and process one message from the server (blocking).

        CHAT messages are automatically decrypted; other message types are
        returned as-is.

        Returns:
            The received ``Message`` with decrypted payload for CHAT messages.

        Raises:
            ConnectionError: If the connection is lost.
        """
        self._require_connected()
        msg = recv_message(self._sock)  # type: ignore[arg-type]

        if msg.msg_type == MessageType.CHAT and msg.payload:
            msg.payload = self._cipher.decrypt(msg.payload, self.key)

        return msg

    def start_recv_loop(
        self,
        on_message: Callable[[Message], None],
        on_disconnect: Callable[[], None] | None = None,
    ) -> None:
        """Start a background thread that calls *on_message* for each message.

        CHAT messages are automatically decrypted before the callback.

        Args:
            on_message: Called for each received message.
            on_disconnect: Called when the connection is lost.
        """
        self._on_message = on_message
        self._on_disconnect = on_disconnect
        self._recv_thread = threading.Thread(
            target=self._recv_loop, daemon=True, name=f"recv-{self.username}"
        )
        self._recv_thread.start()

    def _recv_loop(self) -> None:
        """Internal receive loop for the background thread."""
        try:
            while self._connected.is_set():
                try:
                    msg = self.recv()
                    if self._on_message:
                        self._on_message(msg)
                except ConnectionError:
                    break
                except OSError:
                    break
        finally:
            self._connected.clear()
            if self._on_disconnect:
                self._on_disconnect()

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _require_connected(self) -> None:
        """Raise ConnectionError if the client is not connected."""
        if not self._connected.is_set() or self._sock is None:
            raise ConnectionError("Not connected to server")

    def __repr__(self) -> str:
        status = "connected" if self.is_connected else "disconnected"
        return (
            f"ChatClient({self.username}@{self.host}:{self.port}, "
            f"cipher={self.cipher_name}, room={self.room}, {status})"
        )
