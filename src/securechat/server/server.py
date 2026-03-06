"""Main SecureChat server — accept loop and room routing.

Usage::

    python -m securechat.server.server [--host HOST] [--port PORT]

Or programmatically::

    from securechat.server.server import ChatServer
    server = ChatServer(host="0.0.0.0", port=5000)
    server.serve_forever()       # blocks
    # or
    server.start()               # non-blocking (background thread)
    server.stop()
"""

from __future__ import annotations

import logging
import socket
import threading
from typing import Any

from securechat.server.client_handler import handle_client
from securechat.server.room import RoomManager

logger = logging.getLogger(__name__)


class ChatServer:
    """TCP chat server that accepts connections and spawns handler threads.

    Attributes:
        host: Bind address.
        port: Bind port.
        room_manager: The shared ``RoomManager`` for all rooms.
    """

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 5000,
        room_manager: RoomManager | None = None,
    ) -> None:
        self.host = host
        self.port = port
        self.room_manager = room_manager or RoomManager()
        self._server_sock: socket.socket | None = None
        self._accept_thread: threading.Thread | None = None
        self._running = threading.Event()
        self._client_threads: list[threading.Thread] = []
        self._lock = threading.Lock()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def serve_forever(self) -> None:
        """Start accepting connections on the calling thread (blocks).

        Call ``stop()`` from another thread or signal handler to shut down.
        """
        self._bind()
        self._running.set()
        logger.info("Server listening on %s:%d", self.host, self.port)
        self._accept_loop()

    def start(self) -> None:
        """Start the server in a background daemon thread (non-blocking).

        Returns immediately.  Call ``stop()`` to shut down.
        """
        self._bind()
        self._running.set()
        self._accept_thread = threading.Thread(
            target=self._accept_loop, daemon=True, name="accept-loop"
        )
        self._accept_thread.start()
        logger.info("Server started on %s:%d (background)", self.host, self.port)

    def stop(self) -> None:
        """Shut down the server gracefully.

        Closes the listening socket, which causes the accept loop to exit.
        Does **not** forcibly disconnect existing clients — their handler
        threads will finish naturally when the clients disconnect.
        """
        self._running.clear()
        if self._server_sock:
            try:
                self._server_sock.close()
            except OSError:
                pass
        if self._accept_thread and self._accept_thread.is_alive():
            self._accept_thread.join(timeout=5)
        logger.info("Server stopped")

    @property
    def is_running(self) -> bool:
        """Return True if the server is currently accepting connections."""
        return self._running.is_set()

    @property
    def address(self) -> tuple[str, int]:
        """Return the ``(host, port)`` the server is bound to.

        Useful when binding to port 0 (OS-assigned port).
        """
        if self._server_sock:
            addr = self._server_sock.getsockname()
            return (addr[0], addr[1])
        return (self.host, self.port)

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _bind(self) -> None:
        """Create and bind the server socket."""
        self._server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._server_sock.bind((self.host, self.port))
        self._server_sock.listen()
        # Short timeout so the accept loop can check _running periodically
        self._server_sock.settimeout(1.0)

    def _accept_loop(self) -> None:
        """Accept incoming connections and spawn handler threads."""
        assert self._server_sock is not None
        while self._running.is_set():
            try:
                client_sock, addr = self._server_sock.accept()
            except socket.timeout:
                continue  # check _running again
            except OSError:
                # Socket was closed (shutdown)
                break

            logger.info("Accepted connection from %s:%d", addr[0], addr[1])
            t = threading.Thread(
                target=handle_client,
                args=(client_sock, addr, self.room_manager),
                daemon=True,
                name=f"client-{addr[0]}:{addr[1]}",
            )
            t.start()
            with self._lock:
                self._client_threads.append(t)
                # Prune dead threads
                self._client_threads = [t for t in self._client_threads if t.is_alive()]

    def __repr__(self) -> str:
        status = "running" if self.is_running else "stopped"
        return f"ChatServer({self.host}:{self.port}, {status})"


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------


def main() -> None:
    """Run the server from the command line."""
    import argparse

    # Ensure ciphers are registered
    import securechat.ciphers  # noqa: F401

    parser = argparse.ArgumentParser(description="SecureChat Server")
    parser.add_argument("--host", default="127.0.0.1", help="Bind address (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=5000, help="Bind port (default: 5000)")
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable debug logging")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    server = ChatServer(host=args.host, port=args.port)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        logger.info("Shutting down...")
        server.stop()


if __name__ == "__main__":
    main()
