"""Per-client handler thread for the SecureChat server.

Each client connection is served by its own thread.  The lifecycle is:

1. **Handshake** — negotiate cipher and exchange key.
2. **Join** — add the client to the requested room and notify members.
3. **Receive loop** — read encrypted messages, decrypt, broadcast to the room.
4. **Cleanup** — remove the client from the room, close the socket.
"""

from __future__ import annotations

import logging
import socket
from typing import TYPE_CHECKING

from securechat.ciphers.base import CipherRegistry
from securechat.protocol.framing import recv_message, send_message
from securechat.protocol.handshake import server_handshake
from securechat.protocol.message import Message, MessageType
from securechat.server.room import ClientInfo, RoomManager

if TYPE_CHECKING:
    pass

logger = logging.getLogger(__name__)


def handle_client(
    sock: socket.socket,
    addr: tuple[str, int],
    room_manager: RoomManager,
) -> None:
    """Entry point for a per-client handler thread.

    This function runs for the entire lifetime of one client connection.
    It is designed to be the ``target`` of a ``threading.Thread``.

    Args:
        sock: The connected client socket.
        addr: The client's ``(host, port)`` address tuple.
        room_manager: The shared ``RoomManager`` for all rooms.
    """
    client: ClientInfo | None = None
    try:
        # ------------------------------------------------------------------
        # 1. Handshake
        # ------------------------------------------------------------------
        result = server_handshake(sock)
        if not result.success:
            logger.warning("Handshake failed from %s: %s", addr, result.error)
            return

        cipher = CipherRegistry.get(result.cipher_name)
        client = ClientInfo(
            username=result.username,
            sock=sock,
            cipher=cipher,
            key=result.key,
            room_name=result.room,
        )
        logger.info(
            "Client %s connected from %s (cipher=%s, room=%s)",
            client.username,
            addr,
            result.cipher_name,
            result.room,
        )

        # ------------------------------------------------------------------
        # 2. Join room and notify
        # ------------------------------------------------------------------
        room = room_manager.get_or_create(result.room)
        room.join(client)

        join_msg = Message(
            msg_type=MessageType.JOIN,
            sender=client.username,
            room=room.name,
            extra={"info": f"{client.username} joined the room"},
        )
        room.broadcast_system(join_msg, exclude=client.username)

        # Send user list to the joining client
        _send_user_list(sock, room)

        # ------------------------------------------------------------------
        # 3. Receive loop
        # ------------------------------------------------------------------
        _recv_loop(client, room)

    except ConnectionError as e:
        logger.info("Client %s disconnected: %s", addr, e)
    except Exception:
        logger.exception("Unexpected error handling client %s", addr)
    finally:
        # ------------------------------------------------------------------
        # 4. Cleanup
        # ------------------------------------------------------------------
        if client:
            room = room_manager.get(client.room_name)
            if room:
                room.leave(client.username)
                leave_msg = Message(
                    msg_type=MessageType.LEAVE,
                    sender=client.username,
                    room=client.room_name,
                    extra={"info": f"{client.username} left the room"},
                )
                room.broadcast_system(leave_msg)
                room_manager.remove_if_empty(client.room_name)
        try:
            sock.close()
        except OSError:
            pass
        logger.info("Connection closed for %s", addr)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _recv_loop(client: ClientInfo, room: "Room") -> None:  # type: ignore[name-defined]  # noqa: F821
    """Read messages from *client*, decrypt, and broadcast to *room*.

    Runs until the client disconnects or an error occurs.
    """
    while True:
        msg = recv_message(client.sock)

        if msg.msg_type == MessageType.CHAT:
            # Decrypt the payload
            plaintext = client.cipher.decrypt(msg.payload, client.key)
            # Build a broadcast message with the plaintext
            broadcast_msg = Message(
                msg_type=MessageType.CHAT,
                sender=client.username,
                room=room.name,
                payload=plaintext,
                extra=dict(msg.extra),
            )
            # Room.broadcast() re-encrypts for each recipient
            room.broadcast(broadcast_msg, exclude=client.username)

        elif msg.msg_type == MessageType.LIST_USERS:
            _send_user_list(client.sock, room)

        elif msg.msg_type == MessageType.LEAVE:
            # Client explicitly leaving
            break

        else:
            logger.debug(
                "Ignoring unexpected message type %s from %s",
                msg.msg_type.name,
                client.username,
            )


def _send_user_list(sock: socket.socket, room: "Room") -> None:  # type: ignore[name-defined]  # noqa: F821
    """Send the current room member list to a single client."""
    members = room.members()
    msg = Message(
        msg_type=MessageType.LIST_USERS,
        room=room.name,
        extra={"users": ",".join(members)},
    )
    send_message(sock, msg)
