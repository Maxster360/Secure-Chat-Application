"""Tests for the Vigenere cipher."""

from __future__ import annotations

import os

import pytest

from securechat.ciphers.keys import VigenereKey
from securechat.ciphers.vigenere import VigenereCipher


@pytest.fixture
def cipher() -> VigenereCipher:
    return VigenereCipher()


class TestVigenereEncrypt:
    def test_basic(self, cipher: VigenereCipher) -> None:
        key = VigenereKey(key_bytes=b"\x01\x02\x03")
        plaintext = b"\x10\x20\x30"
        # [0x10+1, 0x20+2, 0x30+3] = [0x11, 0x22, 0x33]
        assert cipher.encrypt(plaintext, key) == bytes([0x11, 0x22, 0x33])

    def test_key_repeats(self, cipher: VigenereCipher) -> None:
        key = VigenereKey(key_bytes=b"\x01\x02")
        plaintext = b"\x10\x20\x30\x40"
        # [0x10+1, 0x20+2, 0x30+1, 0x40+2] = [0x11, 0x22, 0x31, 0x42]
        assert cipher.encrypt(plaintext, key) == bytes([0x11, 0x22, 0x31, 0x42])

    def test_wrap_around(self, cipher: VigenereCipher) -> None:
        key = VigenereKey(key_bytes=b"\x01")
        plaintext = bytes([255])
        assert cipher.encrypt(plaintext, key) == bytes([0])

    def test_zero_key(self, cipher: VigenereCipher) -> None:
        key = VigenereKey(key_bytes=b"\x00\x00\x00")
        plaintext = b"hello"
        assert cipher.encrypt(plaintext, key) == plaintext

    def test_empty_plaintext(self, cipher: VigenereCipher) -> None:
        key = VigenereKey(key_bytes=b"key")
        assert cipher.encrypt(b"", key) == b""

    def test_single_byte_key(self, cipher: VigenereCipher) -> None:
        """A single-byte Vigenere key is equivalent to Caesar."""
        key = VigenereKey(key_bytes=bytes([5]))
        plaintext = b"ABCDEF"
        expected = bytes((b + 5) % 256 for b in plaintext)
        assert cipher.encrypt(plaintext, key) == expected


class TestVigenereDecrypt:
    def test_basic(self, cipher: VigenereCipher) -> None:
        key = VigenereKey(key_bytes=b"\x01\x02\x03")
        ciphertext = bytes([0x11, 0x22, 0x33])
        assert cipher.decrypt(ciphertext, key) == b"\x10\x20\x30"

    def test_wrap_around(self, cipher: VigenereCipher) -> None:
        key = VigenereKey(key_bytes=b"\x01")
        ciphertext = bytes([0])
        assert cipher.decrypt(ciphertext, key) == bytes([255])

    def test_empty_ciphertext(self, cipher: VigenereCipher) -> None:
        key = VigenereKey(key_bytes=b"key")
        assert cipher.decrypt(b"", key) == b""


class TestVigenereRoundTrip:
    def test_round_trip_text(self, cipher: VigenereCipher) -> None:
        key = VigenereKey(key_bytes=b"SECRET")
        plaintext = b"The quick brown fox jumps over the lazy dog"
        assert cipher.decrypt(cipher.encrypt(plaintext, key), key) == plaintext

    def test_round_trip_binary(self, cipher: VigenereCipher) -> None:
        key = VigenereKey(key_bytes=bytes(range(1, 32)))
        plaintext = bytes(range(256))
        assert cipher.decrypt(cipher.encrypt(plaintext, key), key) == plaintext

    def test_round_trip_random(self, cipher: VigenereCipher) -> None:
        key = VigenereKey(key_bytes=os.urandom(16))
        plaintext = os.urandom(2048)
        assert cipher.decrypt(cipher.encrypt(plaintext, key), key) == plaintext

    def test_round_trip_long_key(self, cipher: VigenereCipher) -> None:
        """Key longer than plaintext should still work."""
        key = VigenereKey(key_bytes=os.urandom(100))
        plaintext = b"short"
        assert cipher.decrypt(cipher.encrypt(plaintext, key), key) == plaintext

    def test_round_trip_key_same_length(self, cipher: VigenereCipher) -> None:
        """Key exactly the same length as plaintext (one-time pad style)."""
        plaintext = b"exact match!"
        key = VigenereKey(key_bytes=os.urandom(len(plaintext)))
        assert cipher.decrypt(cipher.encrypt(plaintext, key), key) == plaintext


class TestVigenereValidation:
    def test_invalid_key_type(self, cipher: VigenereCipher) -> None:
        with pytest.raises(ValueError, match="Expected VigenereKey"):
            cipher.encrypt(b"hello", "not a key")

    def test_invalid_key_type_decrypt(self, cipher: VigenereCipher) -> None:
        with pytest.raises(ValueError, match="Expected VigenereKey"):
            cipher.decrypt(b"hello", 42)

    def test_empty_key(self) -> None:
        with pytest.raises(ValueError, match="must not be empty"):
            VigenereKey(key_bytes=b"")


class TestVigenereProperties:
    def test_name(self, cipher: VigenereCipher) -> None:
        assert cipher.name == "vigenere"

    def test_repr(self, cipher: VigenereCipher) -> None:
        assert "vigenere" in repr(cipher)
