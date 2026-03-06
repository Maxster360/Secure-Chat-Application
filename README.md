# Secure Chat Application

Secure Chat Application -- Classical Cryptography | Python, Sockets, TCP/IP

A real-time chat app that encrypts messages using classical ciphers (Caesar, Vigenere, Hill, Columnar Transposition). Built from scratch in Python using only the standard library.

## What This Project Does

- Implements 4 classical ciphers from scratch, all operating on raw bytes (mod 256)
- Multi-room TCP chat server using a thread-per-client model
- Clients in the same room can use different ciphers -- the server handles re-encryption
- Custom length-prefixed protocol with JSON headers and binary payloads
- Hill cipher uses manual matrix math (no numpy)

## Ciphers Implemented

| Cipher | How It Works |
|--------|-------------|
| Caesar | Shifts each byte by a fixed value: `E(x) = (x + k) mod 256` |
| Vigenere | Repeating multi-byte key, polyalphabetic substitution |
| Columnar Transposition | Rearranges byte positions using a column permutation |
| Hill | Matrix multiplication mod 256 on blocks of bytes |

## Prerequisites

- Python 3.10 or higher

## Installation

```bash
git clone https://github.com/Maxster360/Secure-Chat-Application.git
cd Secure-Chat-Application
pip install -e ".[dev]"
```

## How to Run

You need 3 terminals open.

**Terminal 1 -- Start the server:**
```bash
python -m securechat.server.server --host 127.0.0.1 --port 9000
```

**Terminal 2 -- Connect as Alice:**
```bash
python -m securechat.client.cli --host 127.0.0.1 --port 9000 --name Alice --room general --cipher caesar --key 42
```

**Terminal 3 -- Connect as Bob:**
```bash
python -m securechat.client.cli --host 127.0.0.1 --port 9000 --name Bob --room general --cipher vigenere --key "SECRETKEY"
```

Now Alice and Bob can chat. Messages are encrypted on the client side, decrypted by the server, and re-encrypted for each recipient using their own cipher.

### Available Ciphers and Key Formats

| Cipher | `--cipher` flag | `--key` example |
|--------|----------------|-----------------|
| Caesar | `caesar` | `42` (shift value 0-255) |
| Vigenere | `vigenere` | `"SECRETKEY"` (any string) |
| Columnar | `columnar` | `2,0,3,1` (column permutation) |
| Hill | `hill` | `3,2,5,7` (2x2 matrix values) |

### Chat Commands

| Command | What it does |
|---------|-------------|
| *(just type)* | Send a message |
| `/users` | List who's in the room |
| `/quit` | Leave the chat |

## Running the Tests

```bash
python -m pytest tests/ -v
```

There are 229 tests covering all the ciphers, protocol, server, client, and end-to-end integration.

## Project Structure

```
src/securechat/
├── ciphers/          # All 4 cipher implementations + plugin registry
├── protocol/         # Message types, TCP framing, handshake
├── server/           # Chat server, room management, client handler threads
├── client/           # Chat client, CLI interface
└── utils/            # Math utilities (GCD, modular inverse, matrix ops)

tests/                # 229 tests
benchmarks/           # Throughput, latency, CPU benchmarks
docs/                 # Architecture, cipher analysis, benchmark docs
examples/             # Working demo scripts
```

## Built With

- Python 3.10+ (standard library only -- no external dependencies for the core app)
- `socket` and `threading` for networking
- `pytest` for testing

## License

MIT License -- see [LICENSE](LICENSE) for details.

**Author:** Mathew Sabu
