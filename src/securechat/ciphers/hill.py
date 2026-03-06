"""Hill cipher — polygraphic substitution using matrix multiplication mod 256.

Plaintext is split into blocks of size *n* (the matrix dimension).  Each block
is treated as a column vector and multiplied by the key matrix mod 256.
Decryption multiplies by the matrix inverse mod 256.

If the plaintext length is not a multiple of *n*, it is padded with zero bytes
on encryption.  The original length is **not** stored in the ciphertext, so the
caller must track it separately (the protocol layer handles this via the
``payload_len`` header field).

No external dependencies — all matrix math is done manually via
``securechat.utils.math_utils``.
"""

from __future__ import annotations

from typing import Any

from securechat.ciphers.base import BaseCipher
from securechat.ciphers.keys import HillKey
from securechat.utils.math_utils import (
    gcd,
    matrix_determinant,
    matrix_inverse,
    matrix_vector_multiply,
)


class HillCipher(BaseCipher):
    """Hill cipher operating on raw bytes (mod 256)."""

    @property
    def name(self) -> str:
        return "hill"

    def validate_key(self, key: Any) -> None:
        """Validate that *key* is a ``HillKey`` with an invertible matrix mod 256."""
        if not isinstance(key, HillKey):
            raise ValueError(f"Expected HillKey, got {type(key).__name__}")
        mat = [list(row) for row in key.matrix]
        det = matrix_determinant(mat, 256)
        if gcd(det, 256) != 1:
            raise ValueError(
                f"Hill key matrix is not invertible mod 256 "
                f"(det={det}, gcd(det,256)={gcd(det, 256)})"
            )

    def encrypt(self, plaintext: bytes, key: Any) -> bytes:
        """Encrypt *plaintext* by multiplying n-byte blocks by the key matrix."""
        self.validate_key(key)
        n = key.size
        mat = [list(row) for row in key.matrix]

        # Pad to multiple of n
        data = bytearray(plaintext)
        if len(data) % n != 0:
            data.extend(b"\x00" * (n - len(data) % n))

        result = bytearray()
        for i in range(0, len(data), n):
            block = list(data[i : i + n])
            encrypted_block = matrix_vector_multiply(mat, block, 256)
            result.extend(encrypted_block)

        return bytes(result)

    def decrypt(self, ciphertext: bytes, key: Any) -> bytes:
        """Decrypt *ciphertext* by multiplying blocks by the inverse key matrix."""
        self.validate_key(key)
        n = key.size
        mat = [list(row) for row in key.matrix]
        inv_mat = matrix_inverse(mat, 256)

        if len(ciphertext) % n != 0:
            raise ValueError(
                f"Ciphertext length ({len(ciphertext)}) is not a multiple of block size ({n})"
            )

        result = bytearray()
        for i in range(0, len(ciphertext), n):
            block = list(ciphertext[i : i + n])
            decrypted_block = matrix_vector_multiply(inv_mat, block, 256)
            result.extend(decrypted_block)

        return bytes(result)
