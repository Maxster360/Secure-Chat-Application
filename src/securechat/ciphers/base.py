"""Base cipher interface and cipher registry.

All ciphers inherit from ``BaseCipher`` and register themselves with
``CipherRegistry`` so the rest of the application can look them up by name.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any


class BaseCipher(ABC):
    """Abstract base class for all classical ciphers.

    All cipher implementations operate on raw ``bytes`` (mod 256) so they
    can handle arbitrary binary data without charset issues.
    """

    @abstractmethod
    def encrypt(self, plaintext: bytes, key: Any) -> bytes:
        """Encrypt *plaintext* using *key* and return the ciphertext bytes."""

    @abstractmethod
    def decrypt(self, ciphertext: bytes, key: Any) -> bytes:
        """Decrypt *ciphertext* using *key* and return the plaintext bytes."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Return the canonical name of this cipher (e.g. ``'caesar'``)."""

    @abstractmethod
    def validate_key(self, key: Any) -> None:
        """Validate *key* and raise ``ValueError`` if it is invalid."""

    def __repr__(self) -> str:
        return f"<{type(self).__name__}(name={self.name!r})>"


class CipherRegistry:
    """Registry that maps cipher names to ``BaseCipher`` instances.

    Usage::

        CipherRegistry.register(CaesarCipher())
        cipher = CipherRegistry.get("caesar")
    """

    _ciphers: dict[str, BaseCipher] = {}

    @classmethod
    def register(cls, cipher: BaseCipher) -> None:
        """Register a cipher instance. Overwrites if the name already exists."""
        cls._ciphers[cipher.name] = cipher

    @classmethod
    def get(cls, name: str) -> BaseCipher:
        """Return the cipher registered under *name*.

        Raises:
            KeyError: If no cipher is registered with that name.
        """
        try:
            return cls._ciphers[name]
        except KeyError:
            available = ", ".join(sorted(cls._ciphers)) or "(none)"
            raise KeyError(f"Unknown cipher {name!r}. Available: {available}") from None

    @classmethod
    def list_ciphers(cls) -> list[str]:
        """Return a sorted list of registered cipher names."""
        return sorted(cls._ciphers)

    @classmethod
    def clear(cls) -> None:
        """Remove all registered ciphers (mainly for testing)."""
        cls._ciphers.clear()
