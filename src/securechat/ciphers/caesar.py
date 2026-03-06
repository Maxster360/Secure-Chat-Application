"""Caesar cipher — byte-level shift cipher.

Each byte of plaintext is shifted by a fixed amount (mod 256).
This is the simplest classical cipher and serves as a baseline.
"""

from __future__ import annotations

from typing import Any

from securechat.ciphers.base import BaseCipher
from securechat.ciphers.keys import CaesarKey


class CaesarCipher(BaseCipher):
    """Caesar cipher operating on raw bytes.

    Encryption:  ``ciphertext[i] = (plaintext[i] + key.shift) % 256``
    Decryption:  ``plaintext[i] = (ciphertext[i] - key.shift) % 256``
    """

    @property
    def name(self) -> str:
        return "caesar"

    def validate_key(self, key: Any) -> None:
        """Validate that *key* is a ``CaesarKey`` with shift in [0, 255]."""
        if not isinstance(key, CaesarKey):
            raise ValueError(f"Expected CaesarKey, got {type(key).__name__}")

    def encrypt(self, plaintext: bytes, key: Any) -> bytes:
        """Encrypt *plaintext* by shifting each byte by ``key.shift``."""
        self.validate_key(key)
        shift = key.shift
        return bytes((b + shift) % 256 for b in plaintext)

    def decrypt(self, ciphertext: bytes, key: Any) -> bytes:
        """Decrypt *ciphertext* by shifting each byte back by ``key.shift``."""
        self.validate_key(key)
        shift = key.shift
        return bytes((b - shift) % 256 for b in ciphertext)
