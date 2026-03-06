"""Tests for the Hill cipher."""

from __future__ import annotations

import os

import pytest

from securechat.ciphers.hill import HillCipher
from securechat.ciphers.keys import HillKey


@pytest.fixture
def cipher() -> HillCipher:
    return HillCipher()


def make_key(matrix: list[list[int]]) -> HillKey:
    """Helper to build a HillKey from a mutable list-of-lists."""
    return HillKey.from_lists(matrix)


# A known invertible 2x2 matrix mod 256: [[3,2],[1,1]], det=1
KEY_2X2 = make_key([[3, 2], [1, 1]])

# A known invertible 3x3 matrix mod 256: [[1,2,0],[0,1,0],[0,0,1]], det=1
KEY_3X3 = make_key([[1, 2, 0], [0, 1, 0], [0, 0, 1]])


class TestHillEncrypt:
    def test_basic_2x2(self, cipher: HillCipher) -> None:
        # plaintext [1, 2]: [3*1+2*2, 1*1+1*2] = [7, 3]
        plaintext = bytes([1, 2])
        ct = cipher.encrypt(plaintext, KEY_2X2)
        assert ct == bytes([7, 3])

    def test_two_blocks_2x2(self, cipher: HillCipher) -> None:
        plaintext = bytes([1, 2, 3, 4])
        ct = cipher.encrypt(plaintext, KEY_2X2)
        # block1: [3+4, 1+2]=[7,3]  block2: [9+8, 3+4]=[17,7]
        assert ct == bytes([7, 3, 17, 7])

    def test_padding(self, cipher: HillCipher) -> None:
        """Odd-length plaintext should be padded with zero byte."""
        plaintext = bytes([5])  # padded to [5, 0]
        ct = cipher.encrypt(plaintext, KEY_2X2)
        # [3*5+2*0, 1*5+1*0] = [15, 5]
        assert ct == bytes([15, 5])

    def test_empty_input(self, cipher: HillCipher) -> None:
        ct = cipher.encrypt(b"", KEY_2X2)
        assert ct == b""

    def test_3x3(self, cipher: HillCipher) -> None:
        # [[1,2,0],[0,1,0],[0,0,1]] * [10,20,30] = [10+40, 20, 30] = [50,20,30]
        plaintext = bytes([10, 20, 30])
        ct = cipher.encrypt(plaintext, KEY_3X3)
        assert ct == bytes([50, 20, 30])

    def test_wrap_around(self, cipher: HillCipher) -> None:
        """Values that exceed 255 should wrap mod 256."""
        plaintext = bytes([200, 100])
        ct = cipher.encrypt(plaintext, KEY_2X2)
        # [3*200+2*100, 1*200+1*100] = [800, 300] mod 256 = [32, 44]
        assert ct == bytes([800 % 256, 300 % 256])


class TestHillDecrypt:
    def test_basic_2x2(self, cipher: HillCipher) -> None:
        ciphertext = bytes([7, 3])
        pt = cipher.decrypt(ciphertext, KEY_2X2)
        assert pt == bytes([1, 2])

    def test_two_blocks(self, cipher: HillCipher) -> None:
        ciphertext = bytes([7, 3, 17, 7])
        pt = cipher.decrypt(ciphertext, KEY_2X2)
        assert pt == bytes([1, 2, 3, 4])

    def test_empty_input(self, cipher: HillCipher) -> None:
        assert cipher.decrypt(b"", KEY_2X2) == b""

    def test_invalid_length(self, cipher: HillCipher) -> None:
        with pytest.raises(ValueError, match="not a multiple"):
            cipher.decrypt(bytes([1, 2, 3]), KEY_2X2)


class TestHillRoundTrip:
    def test_round_trip_exact(self, cipher: HillCipher) -> None:
        """Plaintext that is an exact multiple of block size."""
        plaintext = bytes([10, 20, 30, 40])
        ct = cipher.encrypt(plaintext, KEY_2X2)
        pt = cipher.decrypt(ct, KEY_2X2)
        assert pt == plaintext

    def test_round_trip_with_padding(self, cipher: HillCipher) -> None:
        """Plaintext that requires padding — decrypted result includes pad bytes."""
        plaintext = bytes([10, 20, 30])  # padded to [10, 20, 30, 0]
        ct = cipher.encrypt(plaintext, KEY_2X2)
        pt = cipher.decrypt(ct, KEY_2X2)
        # Decryption gives back 4 bytes (original 3 + 1 pad byte)
        assert pt == bytes([10, 20, 30, 0])

    def test_round_trip_text(self, cipher: HillCipher) -> None:
        plaintext = b"HELLO!"  # 6 bytes, exact multiple of 2
        ct = cipher.encrypt(plaintext, KEY_2X2)
        pt = cipher.decrypt(ct, KEY_2X2)
        assert pt == plaintext

    def test_round_trip_3x3(self, cipher: HillCipher) -> None:
        plaintext = b"ABCDEFGHI"  # 9 bytes = 3 blocks of 3
        ct = cipher.encrypt(plaintext, KEY_3X3)
        pt = cipher.decrypt(ct, KEY_3X3)
        assert pt == plaintext

    def test_round_trip_random(self, cipher: HillCipher) -> None:
        """Random data, exact multiple of block size."""
        plaintext = os.urandom(100)  # 100 = 50 blocks of 2
        ct = cipher.encrypt(plaintext, KEY_2X2)
        pt = cipher.decrypt(ct, KEY_2X2)
        assert pt == plaintext

    def test_round_trip_large(self, cipher: HillCipher) -> None:
        plaintext = os.urandom(1024)
        ct = cipher.encrypt(plaintext, KEY_2X2)
        pt = cipher.decrypt(ct, KEY_2X2)
        assert pt == plaintext


class TestHillValidation:
    def test_invalid_key_type(self, cipher: HillCipher) -> None:
        with pytest.raises(ValueError, match="Expected HillKey"):
            cipher.encrypt(b"hello", "not a key")

    def test_non_invertible_matrix(self, cipher: HillCipher) -> None:
        """Matrix with even determinant is not invertible mod 256."""
        key = make_key([[1, 1], [1, 3]])  # det = 2
        with pytest.raises(ValueError, match="not invertible"):
            cipher.encrypt(b"AB", key)

    def test_zero_determinant(self, cipher: HillCipher) -> None:
        key = make_key([[2, 4], [1, 2]])  # det = 0
        with pytest.raises(ValueError, match="not invertible"):
            cipher.encrypt(b"AB", key)

    def test_key_dimension_mismatch(self) -> None:
        with pytest.raises(ValueError):
            HillKey(matrix=((1, 2), (3, 4), (5, 6)), size=2)


class TestHillProperties:
    def test_name(self, cipher: HillCipher) -> None:
        assert cipher.name == "hill"

    def test_repr(self, cipher: HillCipher) -> None:
        assert "hill" in repr(cipher).lower()
