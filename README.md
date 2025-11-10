# ShadowLink

ShadowLink is a decentralized, encrypted messaging network inspired by Bitmessage, redesigning its core ideas for scalability, security, and efficiency using modern cryptographic techniques. This project is implemented in Rust, leveraging its safety guarantees and performance.

---

## Overview

Nodes and clients form a peer-to-peer network in which messages are encrypted, stored, and routed based on address prefixes using a Distributed Hash Table (DHT). Proof-of-Work/Memory mechanisms prevent spam and ensure resource commitment.

### Key Features

* **End-to-End Encryption**: Curve25519 (X25519) for key exchange and AES-GCM for payload encryption; Ed25519 for authentication.
* **Prefix-Based Routing**: Addresses encode routing prefixes; DHT-based lookup locates nearest nodes.
* **Spam Resistance**: Argon2id-based Proof-of-Work (PoW) enforces memory-hard commitments.
* **Modular Operation**: Runs in **node mode** for relaying/storage or **client mode** for sending/receiving.

---

## Project Layout

```plaintext
.gitignore
Cargo.toml
LICENSE.md
README.md
DEV_ROADMAP.md
TODO.md

bin/
├── client.rs      # Client application entry point
└── node.rs        # Node application entry point

src/
├── config.rs      # Configuration parsing and defaults
├── lib.rs         # Library entry point (modules export)
├── utils.rs       # Shared helper functions
├── crypto/        # Encryption, authentication, PoW logic
│   ├── authentication.rs
│   ├── encryption.rs
│   └── pow.rs
├── network/       # Networking logic (node, client, DHT, routing)
│   ├── client.rs
│   ├── dht.rs
│   ├── node.rs
│   └── routing/
│       ├── api.rs
│       └── mod.rs
└── types/         # Core types (addresses, packets, messages, prefixes)
    ├── address.rs
    ├── argon2_params.rs
    ├── message.rs
    ├── node_info.rs
    ├── packet.rs
    ├── routing_prefix.rs
    └── mod.rs

tests/
├── integration_tests.rs
└── unit_tests.rs
```

---

## Getting Started

### Prerequisites

* **Rust & Cargo**: Install via `rustup`:

  ```bash
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
  ```

### Clone & Build

```bash
git clone https://github.com/razor389/shadow-link.git
cd shadow-link
cargo build --release
```

### Run Tests

```bash
cargo test
```

---

## Usage

ShadowLink supports two binaries: **node** and **client**.

### Node Mode

Start a node to store and forward packets:

```bash
cargo run --release --bin node -- \
  --address 127.0.0.1:8000 \
  --prefix FF \
  --bootstrap 127.0.0.1:8001,127.0.0.1:8002
```

Optional flags:

* `--pow-difficulty`: PoW difficulty (default: 10)
* `--max-ttl`: Max time-to-live (default: 86400)
* `--min-m-cost`, `--min-t-cost`, `--min-p-cost`: Argon2 parameters
* `--cleanup-interval`, `--blacklist-duration`, `--discovery-interval`

### Client Mode

Send and receive messages:

```bash
cargo run --release --bin client -- \
  --bootstrap 127.0.0.1:8000 \
  --prefix FF --length 8
```

Optional flags mirror node settings for parameter matching and prefix search.

---

## Known Issues & Risks

- `src/network/node.rs:235` – Client handshakes remain unauthenticated; any peer can subscribe or inject packets after sending `Message::ClientHandshake`, leaving the DHT vulnerable to spoofed clients.
- `src/network/node.rs:370` – Packet forwarding enforces only the local node’s PoW threshold; relays ignore each peer’s advertised difficulty, so underpowered packets can still be propagated toward lax neighbors.
- `src/network/node.rs:364` – Subscription fan-out serializes stored packets to every subscriber without backpressure; one slow client can block the broadcast loop and exhaust resources.
- `src/network/client.rs:331` – The subscription loop warns on unexpected frames but never closes the stream, so malformed traffic can trigger infinite logging and leaked tasks.
- `tests/integration_tests.rs:57` – Integration tests always run with `min_pow_difficulty = 0`, leaving the new PoW floor untested; regressions could slip through unnoticed.

---

## Development Roadmap

See [TODO.md](TODO.md) or the more detailed [DEV\_ROADMAP.md](DEV_ROADMAP.md) for planned features and milestones.

---

## License

Licensed under the MIT License. See [LICENSE.md](LICENSE.md).
