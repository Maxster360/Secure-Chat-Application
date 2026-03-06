"""Tests for the Columnar Transposition cipher."""

from __future__ import annotations

import os

import pytest

from securechat.ciphers.columnar import ColumnarTranspositionCipher
from securechat.ciphers.keys import ColumnarKey


@pytest.fixture
def cipher() -> ColumnarTranspositionCipher:
    return ColumnarTranspositionCipher()


class TestColumnarEncrypt:
    def test_basic(self, cipher: ColumnarTranspositionCipher) -> None:
        """Example: 'HELLOWORLD' with perm (2,0,1) — 3 columns.

        Grid (row-wise):
            col0 col1 col2
            H    E    L
            L    O    W
            O    R    L
            D

        Read in perm order (2, 0, 1):
            col2: L W L
            col0: H L O D
            col1: E O R
        Ciphertext: LWL HLOD EOR
        """
        key = ColumnarKey(permutation=(2, 0, 1))
        plaintext = b"HELLOWORLD"
        ciphertext = cipher.encrypt(plaintext, key)
        assert ciphertext == b"LWLHLODEOR"

    def test_identity_permutation(self, cipher: ColumnarTranspositionCipher) -> None:
        """Identity permutation (0,1,2) should read columns in order."""
        key = ColumnarKey(permutation=(0, 1, 2))
        plaintext = b"ABCDEF"
        # Grid: A B C / D E F
        # col0: A D, col1: B E, col2: C F
        assert cipher.encrypt(plaintext, key) == b"ADBECF"

    def test_reverse_permutation(self, cipher: ColumnarTranspositionCipher) -> None:
        key = ColumnarKey(permutation=(2, 1, 0))
        plaintext = b"ABCDEF"
        # Grid: A B C / D E F
        # perm order: col2(CF), col1(BE), col0(AD)
        assert cipher.encrypt(plaintext, key) == b"CFBEAD"

    def test_single_column(self, cipher: ColumnarTranspositionCipher) -> None:
        """Single column key — no transposition."""
        key = ColumnarKey(permutation=(0,))
        plaintext = b"HELLO"
        assert cipher.encrypt(plaintext, key) == plaintext

    def test_empty_input(self, cipher: ColumnarTranspositionCipher) -> None:
        key = ColumnarKey(permutation=(1, 0))
        assert cipher.encrypt(b"", key) == b""

    def test_exact_fit(self, cipher: ColumnarTranspositionCipher) -> None:
        """Plaintext length is exact multiple of key length."""
        key = ColumnarKey(permutation=(1, 0))
        plaintext = b"ABCD"
        # Grid: A B / C D; perm (1,0): col1(BD), col0(AC)
        assert cipher.encrypt(plaintext, key) == b"BDAC"


class TestColumnarDecrypt:
    def test_basic(self, cipher: ColumnarTranspositionCipher) -> None:
        key = ColumnarKey(permutation=(2, 0, 1))
        ciphertext = b"LWLHLODEOR"
        assert cipher.decrypt(ciphertext, key) == b"HELLOWORLD"

    def test_identity_permutation(self, cipher: ColumnarTranspositionCipher) -> None:
        key = ColumnarKey(permutation=(0, 1, 2))
        ciphertext = b"ADBECF"
        assert cipher.decrypt(ciphertext, key) == b"ABCDEF"

    def test_empty_input(self, cipher: ColumnarTranspositionCipher) -> None:
        key = ColumnarKey(permutation=(1, 0))
        assert cipher.decrypt(b"", key) == b""


class TestColumnarRoundTrip:
    def test_round_trip_text(self, cipher: ColumnarTranspositionCipher) -> None:
        key = ColumnarKey(permutation=(3, 1, 4, 0, 2))
        plaintext = b"The quick brown fox jumps over the lazy dog"
        assert cipher.decrypt(cipher.encrypt(plaintext, key), key) == plaintext

    def test_round_trip_binary(self, cipher: ColumnarTranspositionCipher) -> None:
        key = ColumnarKey(permutation=(2, 0, 3, 1))
        plaintext = bytes(range(256))
        assert cipher.decrypt(cipher.encrypt(plaintext, key), key) == plaintext

    def test_round_trip_random(self, cipher: ColumnarTranspositionCipher) -> None:
        key = ColumnarKey(permutation=(4, 2, 0, 3, 1, 5))
        plaintext = os.urandom(1024)
        assert cipher.decrypt(cipher.encrypt(plaintext, key), key) == plaintext

    def test_round_trip_not_multiple(self, cipher: ColumnarTranspositionCipher) -> None:
        """Plaintext length not a multiple of key length."""
        key = ColumnarKey(permutation=(2, 0, 1))
        for length in range(1, 20):
            plaintext = os.urandom(length)
            assert cipher.decrypt(cipher.encrypt(plaintext, key), key) == plaintext

    def test_round_trip_various_keys(self, cipher: ColumnarTranspositionCipher) -> None:
        """Test several different key sizes."""
        plaintext = b"ABCDEFGHIJKLMNOP"
        for n in range(1, 8):
            perm = tuple(range(n - 1, -1, -1))  # reverse order
            key = ColumnarKey(permutation=perm)
            assert cipher.decrypt(cipher.encrypt(plaintext, key), key) == plaintext


class TestColumnarValidation:
    def test_invalid_key_type(self, cipher: ColumnarTranspositionCipher) -> None:
        with pytest.raises(ValueError, match="Expected ColumnarKey"):
            cipher.encrypt(b"hello", "not a key")

    def test_invalid_key_type_decrypt(self, cipher: ColumnarTranspositionCipher) -> None:
        with pytest.raises(ValueError, match="Expected ColumnarKey"):
            cipher.decrypt(b"hello", 42)

    def test_empty_permutation(self) -> None:
        with pytest.raises(ValueError, match="must not be empty"):
            ColumnarKey(permutation=())

    def test_invalid_permutation(self) -> None:
        with pytest.raises(ValueError, match="permutation"):
            ColumnarKey(permutation=(0, 0, 1))

    def test_non_contiguous_permutation(self) -> None:
        with pytest.raises(ValueError, match="permutation"):
            ColumnarKey(permutation=(0, 2))


class TestColumnarProperties:
    def test_name(self, cipher: ColumnarTranspositionCipher) -> None:
        assert cipher.name == "columnar"

    def test_repr(self, cipher: ColumnarTranspositionCipher) -> None:
        assert "columnar" in repr(cipher).lower()
