# Architecture

## Overview

SecureChat is a **multi-room TCP chat application** that encrypts all messages using classical cryptography algorithms. The application follows a client-server architecture with a thread-per-client concurrency model.

## System Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                         SecureChat System                           │
├─────────────────────────────┬───────────────────────────────────────┤
│         CLIENT SIDE         │           SERVER SIDE                 │
│                             │                                       │
│  ┌──────────────────────┐   │   ┌──────────────────────────────┐   │
│  │     CLI Interface     │   │   │        ChatServer             │   │
│  │  (client/cli.py)      │   │   │    (server/server.py)        │   │
│  └──────────┬───────────┘   │   │  ┌──────────────────────┐    │   │
│             │               │   │  │    Accept Loop         │    │   │
│  ┌──────────▼───────────┐   │   │  │  (thread: main)       │    │   │
│  │     ChatClient        │   │   │  └──────────┬───────────┘    │   │
│  │  (client/client.py)   │   │   │             │               │   │
│  │  - connect()          │   │   │  ┌──────────▼───────────┐    │   │
│  │  - send_chat()        │   │   │  │  Client Handler       │    │   │
│  │  - recv()             │◄──┼──►│  │  (one thread/client)  │    │   │
│  │  - disconnect()       │   │   │  │  - handshake          │    │   │
│  └──────────┬───────────┘   │   │  │  - recv loop          │    │   │
│             │               │   │  │  - decrypt → broadcast │    │   │
│  ┌──────────▼───────────┐   │   │  └──────────┬───────────┘    │   │
│  │  Cipher (encrypt)     │   │   │             │               │   │
│  │  Framing (send)       │   │   │  ┌──────────▼───────────┐    │   │
│  └──────────────────────┘   │   │  │    RoomManager         │    │   │
│                             │   │  │  ┌─────┐ ┌─────┐      │    │   │
│                             │   │  │  │Room │ │Room │ ...   │    │   │
│                             │   │  │  │  A  │ │  B  │       │    │   │
│                             │   │  │  └─────┘ └─────┘      │    │   │
│                             │   │  └──────────────────────┘    │   │
│                             │   └──────────────────────────────┘   │
└─────────────────────────────┴───────────────────────────────────────┘
```

## Protocol Flow

### Connection Lifecycle

```
Client                                  Server
  │                                        │
  │────── TCP Connect ────────────────────►│
  │                                        │
  │────── HANDSHAKE_INIT ────────────────►│  (cipher, username, room, key)
  │◄───── HANDSHAKE_ACK ─────────────────│  (status: ok/error)
  │                                        │
  │◄───── LIST_USERS ────────────────────│  (current room members)
  │                                        │
  │────── CHAT (encrypted) ──────────────►│  ← server decrypts
  │◄───── CHAT (re-encrypted) ───────────│  ← re-encrypted per recipient
  │                                        │
  │────── LIST_USERS ────────────────────►│  (request)
  │◄───── LIST_USERS ────────────────────│  (response)
  │                                        │
  │────── LEAVE ─────────────────────────►│
  │                                        │
```

### Wire Format

Every message uses **length-prefixed TCP framing**:

```
┌──────────────┬──────────────────────┬───────────────┐
│ Header Length │     JSON Header      │ Binary Payload│
│   (4 bytes)  │  (variable length)   │  (variable)   │
│  big-endian  │     UTF-8 JSON       │  raw bytes    │
└──────────────┴──────────────────────┴───────────────┘
```

## Module Structure

```
src/securechat/
├── __init__.py              # Package root, version
├── ciphers/
│   ├── __init__.py          # Auto-registers all ciphers
│   ├── base.py              # BaseCipher ABC + CipherRegistry
│   ├── keys.py              # Frozen dataclass keys for each cipher
│   ├── caesar.py            # Caesar cipher (byte-level shift mod 256)
│   ├── vigenere.py          # Vigenere cipher (polyalphabetic, bytes)
│   ├── columnar.py          # Columnar Transposition cipher
│   └── hill.py              # Hill cipher (manual matrix math mod 256)
├── protocol/
│   ├── __init__.py
│   ├── message.py           # MessageType enum + Message dataclass
│   ├── framing.py           # Length-prefixed TCP framing
│   └── handshake.py         # Cipher negotiation + key exchange
├── server/
│   ├── __init__.py
│   ├── room.py              # Thread-safe Room + RoomManager
│   ├── client_handler.py    # Per-client handler thread
│   └── server.py            # Main server with accept loop
├── client/
│   ├── __init__.py
│   ├── client.py            # ChatClient networking with encryption
│   └── cli.py               # Interactive CLI interface
└── utils/
    ├── __init__.py
    └── math_utils.py         # GCD, modular inverse, matrix ops
```

## Threading Model

The server uses a **thread-per-client** model:

- **Main thread**: Runs the accept loop, spawning a new thread for each connection.
- **Client handler threads**: One per connected client, handling handshake, message reception, decryption, and broadcasting.
- **Thread safety**: All shared state (rooms, member lists) is protected by `threading.Lock`.

### Why Thread-Per-Client?

This model was chosen for:
1. **Simplicity** — straightforward to implement and reason about
2. **Educational value** — demonstrates core concurrency concepts
3. **Sufficient for classical crypto workloads** — these ciphers are CPU-bound but fast enough for chat

### Limitations

- Does not scale to thousands of concurrent connections (use asyncio for that)
- GIL limits true parallelism of Python threads (but I/O-bound work is fine)

## Encryption Architecture

Each client negotiates its own cipher and key during the handshake. The server:

1. **Receives** encrypted messages from the sender
2. **Decrypts** using the sender's cipher/key
3. **Re-encrypts** the plaintext individually for each recipient using their own cipher/key
4. **Sends** the re-encrypted message to each recipient

This means different clients in the same room can use different ciphers.

### Key Exchange

Key exchange is done in **plaintext** during the handshake. This is an intentional limitation — classical ciphers predate modern key exchange protocols (Diffie-Hellman, etc.), and this project focuses on demonstrating the ciphers themselves rather than secure key distribution.
