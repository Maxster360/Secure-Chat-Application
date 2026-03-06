"""Cipher package — auto-registers all built-in ciphers on import.

Usage::

    from securechat.ciphers import CipherRegistry

    cipher = CipherRegistry.get("caesar")
    ct = cipher.encrypt(b"hello", CaesarKey(shift=3))
"""

from securechat.ciphers.base import BaseCipher, CipherRegistry
from securechat.ciphers.caesar import CaesarCipher
from securechat.ciphers.columnar import ColumnarTranspositionCipher
from securechat.ciphers.hill import HillCipher
from securechat.ciphers.keys import CaesarKey, ColumnarKey, HillKey, VigenereKey
from securechat.ciphers.vigenere import VigenereCipher

# Auto-register all built-in ciphers
CipherRegistry.register(CaesarCipher())
CipherRegistry.register(VigenereCipher())
CipherRegistry.register(ColumnarTranspositionCipher())
CipherRegistry.register(HillCipher())

__all__ = [
    "BaseCipher",
    "CipherRegistry",
    "CaesarCipher",
    "CaesarKey",
    "VigenereCipher",
    "VigenereKey",
    "ColumnarTranspositionCipher",
    "ColumnarKey",
    "HillCipher",
    "HillKey",
]
