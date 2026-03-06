# Cipher Analysis

## Overview

SecureChat implements four classical ciphers, all operating on **raw bytes (mod 256)** for consistency. This document analyzes each cipher's properties, strengths, weaknesses, and historical context.

---

## 1. Caesar Cipher

### Algorithm
A **monoalphabetic substitution cipher** that shifts each byte by a fixed amount.

```
E(x) = (x + k) mod 256
D(y) = (y - k) mod 256
```

### Key Space
- **Key**: Single integer `k` in `[0, 255]`
- **Key space**: 256 possible keys
- **Effective key space**: 255 (shift of 0 is identity)

### Properties
| Property | Value |
|----------|-------|
| Type | Monoalphabetic substitution |
| Block/Stream | Stream (byte-by-byte) |
| Key size | 1 byte |
| Preserves length | Yes |
| Historical origin | Julius Caesar (~100 BC) |

### Security Analysis
- **Brute force**: Trivial — only 256 keys to try
- **Frequency analysis**: Effective — preserves byte frequency distribution (just shifted)
- **Known plaintext**: One known byte reveals the key
- **Strength**: Essentially none by modern standards

### Implementation Notes
- Operates on raw bytes, not just ASCII letters
- Shift of 0 and 256 are equivalent (identity)

---

## 2. Vigenere Cipher

### Algorithm
A **polyalphabetic substitution cipher** using a repeating key of arbitrary length.

```
E(x_i) = (x_i + k_{i mod len(k)}) mod 256
D(y_i) = (y_i - k_{i mod len(k)}) mod 256
```

### Key Space
- **Key**: Sequence of bytes (arbitrary length, minimum 1)
- **Key space**: 256^n for key length n
- **Practical key space**: Depends on key length

### Properties
| Property | Value |
|----------|-------|
| Type | Polyalphabetic substitution |
| Block/Stream | Stream (byte-by-byte with cycling key) |
| Key size | Variable (1+ bytes) |
| Preserves length | Yes |
| Historical origin | Blaise de Vigenere (1586) |

### Security Analysis
- **Kasiski examination**: Can determine key length by finding repeated patterns
- **Friedman test**: Index of coincidence reveals key length
- **Frequency analysis**: Effective once key length is known (reduces to multiple Caesar ciphers)
- **Key length = plaintext length**: Equivalent to one-time pad (theoretically unbreakable if key is truly random)
- **Strength**: Moderate for short keys, strong for long random keys

### Implementation Notes
- Key wraps around cyclically for messages longer than the key
- Operates on full byte range (0-255), not just alphabetic characters

---

## 3. Columnar Transposition Cipher

### Algorithm
A **transposition cipher** that rearranges byte positions by writing into columns and reading in a permuted column order.

```
1. Write plaintext into rows of width = len(permutation)
2. Read columns in the order specified by the permutation
3. Pad with zero bytes if needed to fill the last row
```

### Key Space
- **Key**: A permutation of `{0, 1, ..., n-1}` for column count n
- **Key space**: n! (factorial of column count)
- **Example**: 5 columns = 120 keys; 10 columns = 3,628,800 keys

### Properties
| Property | Value |
|----------|-------|
| Type | Transposition |
| Block/Stream | Block (block size = column count) |
| Key size | Permutation of n elements |
| Preserves length | No (pads to multiple of column count) |
| Historical origin | Ancient Greece (scytale), systematized in WWI |

### Security Analysis
- **Anagramming**: Effective — try different column arrangements
- **Frequency analysis**: Byte frequencies are preserved (only positions change)
- **Multiple rounds**: Significantly stronger with 2+ transposition rounds
- **Digram analysis**: Column adjacency patterns can reveal the permutation
- **Strength**: Weak alone, useful as a component in composite ciphers

### Implementation Notes
- Encryption pads with zero bytes to fill the last row
- Decryption must account for short columns in the last row
- The permutation is validated to be a proper permutation of `range(n)`

---

## 4. Hill Cipher

### Algorithm
A **polygraphic substitution cipher** that encrypts blocks of bytes using matrix multiplication mod 256.

```
E(P) = K * P mod 256      (matrix multiplication)
D(C) = K^{-1} * C mod 256 (using modular matrix inverse)
```

### Key Space
- **Key**: n x n matrix of integers mod 256 that is invertible mod 256
- **Requirement**: `gcd(det(K), 256) = 1` (determinant must be coprime with 256)
- **Key space**: A fraction of 256^(n*n) matrices (those that are invertible mod 256)

### Properties
| Property | Value |
|----------|-------|
| Type | Polygraphic substitution |
| Block/Stream | Block (block size = matrix dimension) |
| Key size | n^2 integers mod 256 |
| Preserves length | No (pads to multiple of block size) |
| Historical origin | Lester Hill (1929) |

### Security Analysis
- **Known plaintext**: n^2 known plaintext-ciphertext byte pairs can recover the key via linear algebra
- **Frequency analysis**: Resists single-byte frequency analysis (multi-byte blocks)
- **Chosen plaintext**: Completely broken with n plaintext blocks
- **Strength**: Moderate against ciphertext-only attacks, weak against known-plaintext

### Implementation Notes
- **Manual matrix math**: No numpy dependency — all matrix operations (multiply, determinant, adjugate, inverse) are implemented from scratch mod 256
- **Invertibility check**: Matrix must have determinant coprime with 256; validated during key creation and handshake
- **Padding**: Plaintext is padded with zero bytes to fill the last block

---

## Comparative Summary

| Cipher | Type | Key Space | Frequency Resistant | Length Preserving | Speed |
|--------|------|-----------|--------------------|--------------------|-------|
| Caesar | Substitution | 256 | No | Yes | Fastest |
| Vigenere | Poly-substitution | 256^n | Partially | Yes | Fast |
| Columnar | Transposition | n! | No | No (padding) | Fast |
| Hill | Polygraphic | Subset of 256^(n^2) | Partially | No (padding) | Slowest |

## Security Disclaimer

All four ciphers implemented in this project are **classical ciphers** and are **not suitable for securing real communications**. They are implemented for **educational purposes** to demonstrate:

- Core cryptographic concepts (substitution, transposition, matrix crypto)
- Key management and negotiation protocols
- Network programming with encryption integration
- The historical evolution of cryptography

For real-world secure communication, use modern algorithms like AES-256-GCM with TLS 1.3.
