"""Key dataclasses for each classical cipher.

Each key type is a frozen dataclass so it can be used as a dict key or
stored in sets.  Validation helpers live in each cipher's implementation.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class CaesarKey:
    """Key for the Caesar cipher: a single byte-level shift value.

    Attributes:
        shift: An integer in [0, 255].
    """

    shift: int

    def __post_init__(self) -> None:
        if not 0 <= self.shift <= 255:
            raise ValueError(f"Caesar shift must be in [0, 255], got {self.shift}")


@dataclass(frozen=True)
class VigenereKey:
    """Key for the Vigenere cipher: a sequence of bytes.

    Attributes:
        key_bytes: Non-empty bytes used as the repeating key.
    """

    key_bytes: bytes

    def __post_init__(self) -> None:
        if not self.key_bytes:
            raise ValueError("Vigenere key must not be empty")


@dataclass(frozen=True)
class HillKey:
    """Key for the Hill cipher: an n x n matrix invertible mod 256.

    Attributes:
        matrix: An n x n list-of-lists of ints in [0, 255].
        size: The dimension n of the matrix.
    """

    matrix: tuple[tuple[int, ...], ...]
    size: int

    def __post_init__(self) -> None:
        if len(self.matrix) != self.size:
            raise ValueError(
                f"Hill key matrix must be {self.size}x{self.size}, got {len(self.matrix)} rows"
            )
        for row in self.matrix:
            if len(row) != self.size:
                raise ValueError(
                    f"Hill key matrix rows must have {self.size} columns, got {len(row)}"
                )

    @classmethod
    def from_lists(cls, matrix: list[list[int]]) -> HillKey:
        """Create a ``HillKey`` from a mutable list-of-lists."""
        size = len(matrix)
        frozen = tuple(tuple(row) for row in matrix)
        return cls(matrix=frozen, size=size)


@dataclass(frozen=True)
class ColumnarKey:
    """Key for the Columnar Transposition cipher: a column permutation.

    Attributes:
        permutation: A tuple representing the column read-order.
                     Must be a permutation of ``range(len(permutation))``.
    """

    permutation: tuple[int, ...]

    def __post_init__(self) -> None:
        if not self.permutation:
            raise ValueError("Columnar key permutation must not be empty")
        expected = set(range(len(self.permutation)))
        if set(self.permutation) != expected:
            raise ValueError(
                f"Columnar key must be a permutation of {sorted(expected)}, got {self.permutation}"
            )
