# Secure Chat Application — Implementation Plan

> Secure Chat Application – Classical Cryptography | Python, Sockets, Linux, TCP/IP

## Project Vision

- Implement Caesar, Vigenere, Hill, and Columnar Transposition ciphers from scratch in Python with real-time socket-based messaging over the TCP/IP stack; handle concurrent client sessions using threading
- Benchmark cipher performance under load measuring encryption/decryption throughput, latency per message, and CPU utilization; evaluate confidentiality and protocol security trade-offs across schemes
- Design a modular encryption/decryption pipeline with a plug-in architecture extensible to AES/RSA; document performance analysis, key-space analysis, and security implications of each cipher

---

## Table of Contents

1. [Project Structure](#project-structure)
2. [Architecture Overview](#architecture-overview)
3. [Cipher Plugin Architecture](#cipher-plugin-architecture)
4. [Protocol Design](#protocol-design)
5. [Key Design Decisions](#key-design-decisions)
6. [Implementation Phases](#implementation-phases)
7. [Commit Strategy](#commit-strategy)
8. [Dependencies](#dependencies)
9. [Testing Strategy](#testing-strategy)
10. [Benchmarking Design](#benchmarking-design)
11. [README Dashboard Plan](#readme-dashboard-plan)
12. [Estimated Scope](#estimated-scope)

---

## Project Structure

```
Secure-Chat-Application/
├── src/
│   └── securechat/
│       ├── __init__.py
│       ├── ciphers/
│       │   ├── __init__.py
│       │   ├── base.py          # BaseCipher ABC + CipherRegistry
│       │   ├── keys.py          # Key dataclasses for each cipher
│       │   ├── caesar.py        # Caesar cipher (byte-level shift)
│       │   ├── vigenere.py      # Vigenere cipher (polyalphabetic, bytes)
│       │   ├── hill.py          # Hill cipher (matrix math mod 256, no numpy)
│       │   └── columnar.py      # Columnar Transposition cipher
│       ├── protocol/
│       │   ├── __init__.py
│       │   ├── message.py       # Message types (enum + dataclasses)
│       │   ├── framing.py       # Length-prefixed TCP framing (JSON header + binary payload)
│       │   └── handshake.py     # Handshake protocol (cipher negotiation + key exchange)
│       ├── server/
│       │   ├── __init__.py
│       │   ├── room.py          # Chat room management
│       │   ├── client_handler.py # Thread-per-client handler
│       │   └── server.py        # Main server (accept loop, room routing)
│       ├── client/
│       │   ├── __init__.py
│       │   ├── client.py        # Client networking + encryption integration
│       │   └── cli.py           # CLI interface (send/receive, cipher selection)
│       └── utils/
│           ├── __init__.py
│           └── math_utils.py    # GCD, modular inverse, matrix ops mod 256
├── tests/
│   ├── __init__.py
│   ├── test_math_utils.py
│   ├── test_caesar.py
│   ├── test_vigenere.py
│   ├── test_hill.py
│   ├── test_columnar.py
│   ├── test_registry.py
│   ├── test_framing.py
│   ├── test_handshake.py
│   └── test_integration.py
├── benchmarks/
│   ├── bench_throughput.py      # Encryption/decryption throughput per cipher
│   ├── bench_latency.py         # Per-message latency under load
│   └── bench_cpu.py             # CPU utilization during concurrent sessions
├── docs/
│   ├── architecture.md          # Architecture diagrams and explanations
│   ├── ciphers.md               # Cipher descriptions, key-space analysis, security implications
│   └── benchmarks.md            # Benchmark methodology and results
├── examples/
│   ├── basic_chat.py            # Simple 2-client chat demo
│   └── multi_cipher.py          # Demo switching between ciphers
├── pyproject.toml               # Project metadata, dependencies, tool config
├── IMPLEMENTATION_PLAN.md       # This file
├── README.md                    # Enterprise-grade dashboard (hybrid template)
├── LICENSE                      # MIT (existing)
└── .gitignore                   # Python template (existing)
```

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────┐
│                     CLIENT                          │
│  ┌─────────┐   ┌──────────┐   ┌─────────────────┐  │
│  │   CLI   │──▶│  Client  │──▶│  CipherRegistry │  │
│  │ (cli.py)│   │(client.py)│  │  + BaseCipher   │  │
│  └─────────┘   └──────────┘   └─────────────────┘  │
│                      │                              │
│                      ▼                              │
│              ┌──────────────┐                       │
│              │   Framing    │                       │
│              │ (framing.py) │                       │
│              └──────────────┘                       │
│                      │ TCP                          │
└──────────────────────┼──────────────────────────────┘
                       │
              ═════════╪═════════  Network
                       │
┌──────────────────────┼──────────────────────────────┐
│                      │ TCP                          │
│              ┌──────────────┐                       │
│              │   Framing    │                       │
│              │ (framing.py) │                       │
│              └──────────────┘                       │
│                      │                              │
│                      ▼                              │
│  ┌───────────────────────────────────────────────┐  │
│  │               SERVER                          │  │
│  │  ┌──────────┐  ┌────────────────┐  ┌───────┐ │  │
│  │  │  Server  │──│ ClientHandler  │──│ Room  │ │  │
│  │  │(server.py)│ │(client_handler)│  │(room) │ │  │
│  │  └──────────┘  └────────────────┘  └───────┘ │  │
│  └───────────────────────────────────────────────┘  │
│                     SERVER                          │
└─────────────────────────────────────────────────────┘
```

**Data flow:** User input → CLI → Client encrypts via selected cipher → Framing (length-prefixed JSON header + encrypted payload) → TCP → Server receives → Framing unpacks → Server broadcasts to room → Each recipient's Client decrypts → CLI displays

---

## Cipher Plugin Architecture

### Base Class (`ciphers/base.py`)

```python
from abc import ABC, abstractmethod

class BaseCipher(ABC):
    """Abstract base for all ciphers. All operate on raw bytes."""

    @abstractmethod
    def encrypt(self, plaintext: bytes, key) -> bytes: ...

    @abstractmethod
    def decrypt(self, ciphertext: bytes, key) -> bytes: ...

    @property
    @abstractmethod
    def name(self) -> str: ...

class CipherRegistry:
    """Registry pattern — maps cipher names to instances."""
    _ciphers: dict[str, BaseCipher] = {}

    @classmethod
    def register(cls, cipher: BaseCipher) -> None: ...

    @classmethod
    def get(cls, name: str) -> BaseCipher: ...

    @classmethod
    def list_ciphers(cls) -> list[str]: ...
```

### Key Dataclasses (`ciphers/keys.py`)

```python
from dataclasses import dataclass

@dataclass(frozen=True)
class CaesarKey:
    shift: int  # 0-255

@dataclass(frozen=True)
class VigenereKey:
    key_bytes: bytes  # variable length

@dataclass(frozen=True)
class HillKey:
    matrix: list[list[int]]  # n×n, invertible mod 256
    size: int

@dataclass(frozen=True)
class ColumnarKey:
    permutation: tuple[int, ...]  # column order
```

### Cipher Implementations

| Cipher | Key Space | Operating Space | Core Algorithm |
|--------|-----------|-----------------|----------------|
| Caesar | shift in [0, 255] | byte-level | `c[i] = (p[i] + shift) % 256` |
| Vigenere | key_bytes (arbitrary length) | byte-level | `c[i] = (p[i] + key[i % len(key)]) % 256` |
| Hill | n x n matrix invertible mod 256 | byte blocks of size n | Matrix multiplication mod 256, padding if needed |
| Columnar | permutation of columns | byte-level with grid | Write row-wise, read column-wise per permutation |

---

## Protocol Design

### Message Types (`protocol/message.py`)

```python
from enum import Enum, auto

class MessageType(Enum):
    HANDSHAKE_INIT = auto()    # Client -> Server: propose cipher + send key
    HANDSHAKE_ACK = auto()     # Server -> Client: confirm cipher
    CHAT = auto()              # Encrypted chat message
    JOIN = auto()              # User joined notification
    LEAVE = auto()             # User left notification
    ERROR = auto()             # Error notification
    LIST_USERS = auto()        # Request/response for online users
```

### Wire Format (`protocol/framing.py`)

```
+──────────────+──────────────────────+───────────────+
| Header Length |     JSON Header      | Binary Payload|
|   (4 bytes)  |  (variable length)   |  (variable)   |
+──────────────+──────────────────────+───────────────+
```

- **Header Length:** 4-byte big-endian unsigned int
- **JSON Header:** `{"type": "CHAT", "sender": "alice", "room": "general", "cipher": "vigenere", "payload_len": 128}`
- **Binary Payload:** Raw encrypted bytes (for CHAT messages) or empty (for control messages)

### Handshake Flow

```
Client                              Server
  |                                    |
  |──HANDSHAKE_INIT───────────────────>|  (cipher="vigenere", key=<bytes>)
  |                                    |  Server stores key for this client
  |<──HANDSHAKE_ACK────────────────────|  (cipher="vigenere", status="ok")
  |                                    |
  |──CHAT (encrypted)─────────────────>|  Server decrypts, re-encrypts per
  |                                    |  recipient, broadcasts to room
  |<──CHAT (encrypted)─────────────────|
```

**Note:** Key exchange is plaintext during handshake — this is an intentional and documented limitation of classical ciphers. The focus is on demonstrating cipher mechanics, not building a production-secure key exchange.

---

## Key Design Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Cipher operating space | Raw `bytes` (mod 256) | Consistent interface; handles any binary data; avoids charset issues |
| Hill matrix math | Manual implementation (no numpy) | Zero external deps for core; demonstrates understanding |
| Hill invertibility | Validate `det(matrix)` is coprime with 256 | Must have `gcd(det, 256) == 1` for inverse to exist |
| Concurrency model | Thread-per-client | Required by spec; `threading` module, no asyncio |
| TCP framing | Length-prefixed | Solves TCP stream boundary problem; JSON header for metadata |
| Key exchange | Plaintext during handshake | Classical ciphers have no secure key exchange; documented limitation |
| External dependencies | Zero for core (stdlib only) | Demonstrates mastery; dev/bench deps allowed |
| Python version | 3.10+ | `match` statements, modern type hints |

---

## Implementation Phases

### Track 1: Core Implementation

| Phase | Module | Description | Depends On |
|-------|--------|-------------|------------|
| 1 | `utils/math_utils.py` | GCD, extended GCD, modular inverse, matrix determinant mod n, matrix inverse mod n, matrix multiply mod n | — |
| 2 | `ciphers/base.py` + `ciphers/keys.py` | `BaseCipher` ABC, `CipherRegistry`, key dataclasses | — |
| 3 | `ciphers/caesar.py` + test | Caesar cipher implementation | Phase 1, 2 |
| 4 | `ciphers/vigenere.py` + test | Vigenere cipher implementation | Phase 2 |
| 5 | `ciphers/columnar.py` + test | Columnar Transposition implementation | Phase 2 |
| 6 | `ciphers/hill.py` + test | Hill cipher (matrix math mod 256, invertibility check) | Phase 1, 2 |
| 7 | `ciphers/__init__.py` | Registry wiring — auto-register all ciphers | Phase 3-6 |
| 8 | `protocol/message.py` | MessageType enum + Message dataclass | — |
| 9 | `protocol/framing.py` + test | `send_message()` / `recv_message()` over TCP socket | Phase 8 |
| 10 | `protocol/handshake.py` + test | Handshake sequence (cipher negotiation + key exchange) | Phase 7, 9 |
| 11 | `server/room.py` | Room class (thread-safe user set, broadcast) | Phase 9 |
| 12 | `server/client_handler.py` | Per-client thread (recv loop, decrypt, broadcast, encrypt) | Phase 7, 10, 11 |
| 13 | `server/server.py` | Accept loop, spawn client_handler threads | Phase 12 |
| 14 | `client/client.py` | Connect, handshake, send/recv with encryption | Phase 7, 10 |
| 15 | `client/cli.py` | CLI interface (cipher selection, chat REPL) | Phase 14 |
| 16 | `tests/test_integration.py` | End-to-end: server + multiple clients, message round-trip | Phase 13, 15 |
| 17 | `benchmarks/` | Throughput, latency, CPU benchmarks | Phase 7, 13 |
| 18 | `docs/` | Architecture docs, cipher analysis, benchmark results | Phase 16, 17 |

### Track 2: README Dashboard (Hybrid Template)

| Step | Description |
|------|-------------|
| A | Build README.md structure (TOC, badges, sections) from Best-README-Template |
| B | Add security-themed hero section (inspired by sniffnet) |
| C | Add architecture diagram section (inspired by ThePhish) |
| D | Add benchmark results section (inspired by fiber) |
| E | Add "How It Works" cryptography section (inspired by FileShotZKE) |
| F | Add installation, usage, contributing, license sections |

---

## Commit Strategy

Every phase is committed and pushed individually. No broken commits — all tests must pass before each commit.

| Commit | Phase | Commit Message |
|--------|-------|----------------|
| 1 | Setup | `feat: initialize project structure and implementation plan` |
| 2 | Phase 1 | `feat: add math utilities (GCD, modular inverse, matrix ops mod 256)` |
| 3 | Phase 2 | `feat: add BaseCipher ABC, CipherRegistry, and key dataclasses` |
| 4 | Phase 3 | `feat: implement Caesar cipher with byte-level shift` |
| 5 | Phase 4 | `feat: implement Vigenere cipher (polyalphabetic, bytes)` |
| 6 | Phase 5 | `feat: implement Columnar Transposition cipher` |
| 7 | Phase 6 | `feat: implement Hill cipher (manual matrix math mod 256)` |
| 8 | Phase 7 | `feat: wire cipher registry with auto-registration` |
| 9 | Phase 8 | `feat: add protocol message types and dataclasses` |
| 10 | Phase 9 | `feat: implement length-prefixed TCP framing` |
| 11 | Phase 10 | `feat: implement handshake protocol (cipher negotiation + key exchange)` |
| 12 | Phase 11 | `feat: add thread-safe chat room management` |
| 13 | Phase 12 | `feat: add thread-per-client handler with encrypt/decrypt` |
| 14 | Phase 13 | `feat: add main server with accept loop and room routing` |
| 15 | Phase 14 | `feat: add client networking with encryption integration` |
| 16 | Phase 15 | `feat: add CLI interface (cipher selection, chat REPL)` |
| 17 | Phase 16 | `test: add end-to-end integration tests` |
| 18 | Phase 17 | `feat: add benchmark suite (throughput, latency, CPU)` |
| 19 | Phase 18 | `docs: add architecture, cipher analysis, and benchmark docs` |
| 20 | Track 2 | `docs: add enterprise-grade README dashboard` |

**Process per commit:**
1. Write code for the phase
2. Run `pytest` — all tests must pass
3. `git add` relevant files
4. `git commit` with descriptive message
5. `git push origin main`
6. Proceed to next phase

---

## Dependencies

### Core Application (zero external deps)

```
Python 3.10+ standard library only:
- socket, threading, struct, json, enum, dataclasses, abc, typing, logging, argparse
```

### Development Dependencies

```
pytest >= 7.0        # Testing
pytest-cov >= 4.0    # Coverage reporting
mypy >= 1.0          # Static type checking
ruff >= 0.1          # Linting and formatting
```

### Benchmark Dependencies

```
psutil >= 5.9        # CPU utilization measurement
rich >= 13.0         # Terminal tables and progress bars
matplotlib >= 3.7    # Chart generation for README
```

---

## Testing Strategy

| Test Level | Scope | Tools |
|------------|-------|-------|
| Unit | Each cipher: encrypt/decrypt round-trip, edge cases (empty input, single byte, large payload), known test vectors | pytest |
| Unit | Math utils: GCD, modular inverse, matrix operations, edge cases (non-invertible matrix) | pytest |
| Unit | Framing: send/recv with mock sockets, malformed headers, truncated data | pytest |
| Unit | Handshake: valid negotiation, unsupported cipher, malformed messages | pytest |
| Integration | Full server + 2+ clients: message round-trip, cipher correctness end-to-end | pytest + threading |
| Integration | Multi-room: clients in different rooms don't receive cross-room messages | pytest + threading |
| Property | Round-trip: `decrypt(encrypt(plaintext, key), key) == plaintext` for all ciphers, random inputs | pytest (parametrize with random data) |

**Target coverage:** >90% line coverage on `src/securechat/`

---

## Benchmarking Design

### Metrics

| Metric | Measurement | Method |
|--------|-------------|--------|
| Throughput | MB/s per cipher | Encrypt/decrypt 1MB, 10MB, 100MB payloads, measure wall-clock time |
| Latency | ms per message | Encrypt + frame + send + recv + unframe + decrypt for 1KB messages, 1000 iterations |
| CPU Utilization | % during concurrent sessions | `psutil.cpu_percent()` during 10-client load test |
| Scalability | Throughput vs. message size | Vary payload from 64B to 10MB, plot throughput curve |

### Output

- Terminal tables via `rich`
- PNG charts via `matplotlib` (embedded in README and `docs/benchmarks.md`)
- Raw CSV data in `benchmarks/results/`

---

## README Dashboard Plan (Hybrid Template)

**Sources combined:**

- **Structure & TOC:** othneildrew/Best-README-Template
- **Hero banner & security aesthetic:** GyulyVGC/sniffnet
- **Architecture diagrams:** emalderson/ThePhish
- **Benchmark charts:** gofiber/fiber
- **Crypto "How It Works":** FileShot/FileShotZKE

**Sections:**

1. Hero banner (custom security/lock themed)
2. Badges (Python version, license, tests passing, coverage %)
3. Table of Contents
4. About the Project (overview, screenshots/demo GIF)
5. Built With (Python, stdlib only)
6. Architecture (diagrams: cipher pipeline, protocol flow, server threading model)
7. Supported Ciphers (table with key-space, security properties)
8. How It Works (cryptographic explanation of each cipher)
9. Benchmark Results (throughput chart, latency chart, CPU chart)
10. Getting Started (prerequisites, installation, usage)
11. Usage Examples (code snippets, CLI demo)
12. Roadmap (future ciphers: AES/RSA, GUI client, etc.)
13. Contributing
14. License
15. Acknowledgments

---

## Estimated Scope

| Category | Files | Lines of Code |
|----------|-------|---------------|
| Source (`src/securechat/`) | ~20 | 2,500-3,500 |
| Tests (`tests/`) | ~10 | 1,500-2,000 |
| Benchmarks (`benchmarks/`) | 3 | 300-500 |
| Documentation (`docs/`) | 3 | 500-800 |
| Config (`pyproject.toml`, etc.) | 1-2 | 50-100 |
| README | 1 | 300-500 |
| **Total** | **~38-40** | **~5,150-7,400** |
