"""Tests for the Caesar cipher."""

from __future__ import annotations

import os

import pytest

from securechat.ciphers.caesar import CaesarCipher
from securechat.ciphers.keys import CaesarKey


@pytest.fixture
def cipher() -> CaesarCipher:
    return CaesarCipher()


class TestCaesarEncrypt:
    def test_basic_shift(self, cipher: CaesarCipher) -> None:
        key = CaesarKey(shift=3)
        plaintext = b"HELLO"
        ciphertext = cipher.encrypt(plaintext, key)
        # H=72 -> 75=K, E=69 -> 72=H, L=76 -> 79=O, O=79 -> 82=R
        assert ciphertext == b"KHOOR"

    def test_shift_zero(self, cipher: CaesarCipher) -> None:
        key = CaesarKey(shift=0)
        plaintext = b"hello world"
        assert cipher.encrypt(plaintext, key) == plaintext

    def test_wrap_around(self, cipher: CaesarCipher) -> None:
        key = CaesarKey(shift=1)
        # byte 255 should wrap to 0
        plaintext = bytes([255])
        ciphertext = cipher.encrypt(plaintext, key)
        assert ciphertext == bytes([0])

    def test_empty_input(self, cipher: CaesarCipher) -> None:
        key = CaesarKey(shift=10)
        assert cipher.encrypt(b"", key) == b""

    def test_single_byte(self, cipher: CaesarCipher) -> None:
        key = CaesarKey(shift=100)
        plaintext = bytes([50])
        assert cipher.encrypt(plaintext, key) == bytes([150])

    def test_full_byte_range(self, cipher: CaesarCipher) -> None:
        """Encrypt all 256 byte values — should be a permutation."""
        key = CaesarKey(shift=42)
        plaintext = bytes(range(256))
        ciphertext = cipher.encrypt(plaintext, key)
        assert len(set(ciphertext)) == 256  # all unique


class TestCaesarDecrypt:
    def test_basic_shift(self, cipher: CaesarCipher) -> None:
        key = CaesarKey(shift=3)
        ciphertext = b"KHOOR"
        assert cipher.decrypt(ciphertext, key) == b"HELLO"

    def test_shift_zero(self, cipher: CaesarCipher) -> None:
        key = CaesarKey(shift=0)
        ciphertext = b"hello world"
        assert cipher.decrypt(ciphertext, key) == ciphertext

    def test_wrap_around(self, cipher: CaesarCipher) -> None:
        key = CaesarKey(shift=1)
        # byte 0 should wrap to 255
        ciphertext = bytes([0])
        assert cipher.decrypt(ciphertext, key) == bytes([255])

    def test_empty_input(self, cipher: CaesarCipher) -> None:
        key = CaesarKey(shift=10)
        assert cipher.decrypt(b"", key) == b""


class TestCaesarRoundTrip:
    def test_round_trip_text(self, cipher: CaesarCipher) -> None:
        key = CaesarKey(shift=13)
        plaintext = b"The quick brown fox jumps over the lazy dog"
        assert cipher.decrypt(cipher.encrypt(plaintext, key), key) == plaintext

    def test_round_trip_binary(self, cipher: CaesarCipher) -> None:
        key = CaesarKey(shift=200)
        plaintext = bytes(range(256))
        assert cipher.decrypt(cipher.encrypt(plaintext, key), key) == plaintext

    def test_round_trip_random(self, cipher: CaesarCipher) -> None:
        """Round-trip with random data and random key."""
        plaintext = os.urandom(1024)
        key = CaesarKey(shift=int.from_bytes(os.urandom(1), "big"))
        assert cipher.decrypt(cipher.encrypt(plaintext, key), key) == plaintext

    def test_round_trip_all_shifts(self, cipher: CaesarCipher) -> None:
        """Every possible shift value should round-trip correctly."""
        plaintext = b"test data 123"
        for shift in range(256):
            key = CaesarKey(shift=shift)
            assert cipher.decrypt(cipher.encrypt(plaintext, key), key) == plaintext


class TestCaesarValidation:
    def test_invalid_key_type(self, cipher: CaesarCipher) -> None:
        with pytest.raises(ValueError, match="Expected CaesarKey"):
            cipher.encrypt(b"hello", "not a key")

    def test_invalid_key_type_decrypt(self, cipher: CaesarCipher) -> None:
        with pytest.raises(ValueError, match="Expected CaesarKey"):
            cipher.decrypt(b"hello", 42)

    def test_key_shift_out_of_range(self) -> None:
        with pytest.raises(ValueError):
            CaesarKey(shift=256)

    def test_key_shift_negative(self) -> None:
        with pytest.raises(ValueError):
            CaesarKey(shift=-1)


class TestCaesarProperties:
    def test_name(self, cipher: CaesarCipher) -> None:
        assert cipher.name == "caesar"

    def test_repr(self, cipher: CaesarCipher) -> None:
        assert "caesar" in repr(cipher)
