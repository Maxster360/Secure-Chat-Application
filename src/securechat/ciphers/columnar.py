"""Columnar Transposition cipher — rearranges bytes by column permutation.

Plaintext is written row-wise into a grid whose number of columns equals the
key length, then read out column-wise in the order specified by the key
permutation.  Decryption reverses the process.

The last row may be incomplete; during encryption the short columns are
tracked so that decryption can reconstruct the original length exactly
without any padding bytes leaking into the output.
"""

from __future__ import annotations

from typing import Any

from securechat.ciphers.base import BaseCipher
from securechat.ciphers.keys import ColumnarKey


class ColumnarTranspositionCipher(BaseCipher):
    """Columnar Transposition cipher operating on raw bytes."""

    @property
    def name(self) -> str:
        return "columnar"

    def validate_key(self, key: Any) -> None:
        """Validate that *key* is a ``ColumnarKey``."""
        if not isinstance(key, ColumnarKey):
            raise ValueError(f"Expected ColumnarKey, got {type(key).__name__}")

    def encrypt(self, plaintext: bytes, key: Any) -> bytes:
        """Encrypt by writing row-wise and reading column-wise per permutation."""
        self.validate_key(key)
        if not plaintext:
            return b""

        perm = key.permutation
        num_cols = len(perm)
        num_full_rows, extra = divmod(len(plaintext), num_cols)

        # Build columns: read plaintext into a grid row-by-row, then extract
        # each column in permutation order.
        ciphertext = bytearray()
        for col in perm:
            # Number of rows in this column
            col_len = num_full_rows + (1 if col < extra else 0)
            for row in range(col_len):
                ciphertext.append(plaintext[row * num_cols + col])

        return bytes(ciphertext)

    def decrypt(self, ciphertext: bytes, key: Any) -> bytes:
        """Decrypt by reversing the columnar read-out."""
        self.validate_key(key)
        if not ciphertext:
            return b""

        perm = key.permutation
        num_cols = len(perm)
        num_full_rows, extra = divmod(len(ciphertext), num_cols)

        # Determine how many bytes each column holds.
        col_lengths: dict[int, int] = {}
        for col in range(num_cols):
            col_lengths[col] = num_full_rows + (1 if col < extra else 0)

        # Split ciphertext into columns (in permutation order).
        columns: dict[int, list[int]] = {}
        idx = 0
        for col in perm:
            length = col_lengths[col]
            columns[col] = list(ciphertext[idx : idx + length])
            idx += length

        # Read back row-by-row in natural column order.
        plaintext = bytearray()
        total_rows = num_full_rows + (1 if extra > 0 else 0)
        for row in range(total_rows):
            for col in range(num_cols):
                if row < len(columns[col]):
                    plaintext.append(columns[col][row])

        return bytes(plaintext)
