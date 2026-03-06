"""Tests for the CipherRegistry and auto-registration wiring."""

from __future__ import annotations

import pytest

from securechat.ciphers import CipherRegistry
from securechat.ciphers.base import BaseCipher


class TestCipherRegistry:
    def test_all_ciphers_registered(self) -> None:
        """Importing the ciphers package registers all four built-in ciphers."""
        names = CipherRegistry.list_ciphers()
        assert "caesar" in names
        assert "vigenere" in names
        assert "columnar" in names
        assert "hill" in names

    def test_get_caesar(self) -> None:
        cipher = CipherRegistry.get("caesar")
        assert isinstance(cipher, BaseCipher)
        assert cipher.name == "caesar"

    def test_get_vigenere(self) -> None:
        cipher = CipherRegistry.get("vigenere")
        assert isinstance(cipher, BaseCipher)
        assert cipher.name == "vigenere"

    def test_get_columnar(self) -> None:
        cipher = CipherRegistry.get("columnar")
        assert isinstance(cipher, BaseCipher)
        assert cipher.name == "columnar"

    def test_get_hill(self) -> None:
        cipher = CipherRegistry.get("hill")
        assert isinstance(cipher, BaseCipher)
        assert cipher.name == "hill"

    def test_get_unknown_raises(self) -> None:
        with pytest.raises(KeyError, match="Unknown cipher"):
            CipherRegistry.get("aes256")

    def test_list_ciphers_sorted(self) -> None:
        names = CipherRegistry.list_ciphers()
        assert names == sorted(names)

    def test_count(self) -> None:
        assert len(CipherRegistry.list_ciphers()) >= 4
