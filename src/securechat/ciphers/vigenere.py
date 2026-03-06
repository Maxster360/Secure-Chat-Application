"""Vigenere cipher — polyalphabetic byte-level substitution.

Generalises the Caesar cipher by using a repeating key of arbitrary length.
Each byte of plaintext is shifted by the corresponding key byte (mod 256).
"""

from __future__ import annotations

from typing import Any

from securechat.ciphers.base import BaseCipher
from securechat.ciphers.keys import VigenereKey


class VigenereCipher(BaseCipher):
    """Vigenere cipher operating on raw bytes.

    Encryption:  ``ciphertext[i] = (plaintext[i] + key[i % len(key)]) % 256``
    Decryption:  ``plaintext[i]  = (ciphertext[i] - key[i % len(key)]) % 256``
    """

    @property
    def name(self) -> str:
        return "vigenere"

    def validate_key(self, key: Any) -> None:
        """Validate that *key* is a non-empty ``VigenereKey``."""
        if not isinstance(key, VigenereKey):
            raise ValueError(f"Expected VigenereKey, got {type(key).__name__}")

    def encrypt(self, plaintext: bytes, key: Any) -> bytes:
        """Encrypt *plaintext* using the repeating key."""
        self.validate_key(key)
        kb = key.key_bytes
        klen = len(kb)
        return bytes((p + kb[i % klen]) % 256 for i, p in enumerate(plaintext))

    def decrypt(self, ciphertext: bytes, key: Any) -> bytes:
        """Decrypt *ciphertext* using the repeating key."""
        self.validate_key(key)
        kb = key.key_bytes
        klen = len(kb)
        return bytes((c - kb[i % klen]) % 256 for i, c in enumerate(ciphertext))
