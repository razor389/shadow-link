# ShadowLink

ShadowLink is a decentralized, encrypted messaging network inspired by Bitmessage, but redesigned for scalability, security, and efficiency using modern cryptographic techniques and blockchain-based incentives. This project is implemented in Rust, leveraging its safety guarantees and performance.

## Overview

ShadowLink builds on the core ideas of Bitmessage but introduces key improvements for scalability and robustness, incorporating a blockchain to incentivize honest node behavior and ensure reliable message propagation. Nodes and clients form the backbone of the network, providing both storage and communication capabilities.

### Key Features

- **Encrypted Messaging**: End-to-end encryption using X25519 for key exchange and Ed25519 for authentication.
- **Blockchain for Incentives**: Proof of Stake and Proof of Retrievability mechanisms ensure fair payment for nodes hosting and forwarding messages.
- **Scalable Architecture**: Address-prefix-based routing using a Distributed Hash Table (DHT) ensures efficient message handling while preserving anonymity.
- **Spam Prevention**: Proof of Memory (PoM) using Argon2id to prevent network abuse.
- **Flexible Operation Modes**: Operates in either client or node mode.

---

## Project Structure

The project is organized to separate concerns, providing a modular and maintainable codebase:

- **`/bin/client.rs`**: The client binary for sending and receiving messages.
- **`/bin/node.rs`**: The node binary for participating in the network, storing, and forwarding messages.
- **`/src/types`**: Core types used across the application, such as `ShadowAddress`, `Packet`, and proofs for blockchain interactions.
- **`/src/network`**: Networking code, including peer-to-peer communication and gossip protocols.
- **`/src/storage`**: Message storage, proof verification, and message relay handling.
- **`/src/crypto`**: Encryption and authentication functionality.
- **`/src/utils`**: Helper functions and utilities shared across modules.

---

## Blockchain-Based Incentives

ShadowLink uses a blockchain to maintain a fair and robust incentive structure:

- **Proof of Stake (PoS)**: Nodes stake tokens to participate in the network and earn hosting and relay rewards proportional to their stake and uptime. Slashing penalties discourage dishonest behavior.
- **Proof of Retrievability (PoR)**: Nodes must submit cryptographic proofs showing they are hosting messages to receive incremental payments.
- **Proof of Relay (PoRelay)**: Nodes must provide acknowledgments from subscribers to confirm message forwarding and claim subscription fees.

---

## Getting Started

### Prerequisites

- Install [Rust](https://www.rust-lang.org/) and its toolchain.
- Clone the repository:

  ```bash
  git clone https://github.com/razor389/shadow-link.git
  cd shadow-link
  ```

### Building the Project

1. Compile the project:

   ```bash
   cargo build --release
   ```

2. Run tests to verify functionality:

   ```bash
   cargo test
   ```

---

## Usage

ShadowLink can operate in either **node mode** or **client mode**, depending on your use case.

### Running as a Node

Nodes form the backbone of the network, handling message storage, routing, and distribution.

1. Start a node:

   ```bash
   cargo run --release --bin node -- --address "127.0.0.1:12345" --connect "127.0.0.1:12346"
   ```

   - `--address`: The node’s IP and port.
   - `--connect`: (Optional) Connect to other nodes by providing their addresses.

2. Nodes automatically begin gossiping with peers and handling messages for assigned prefixes.

### Running as a Client

Clients interact with the network by sending and receiving encrypted messages.

1. Start a client:

   ```bash
   cargo run --release --bin client -- --address "127.0.0.1:12345"
   ```

   - `--address`: The IP and port of the node to connect to.

2. The client can send and receive encrypted messages.

---

## Logging

Configure logging levels using the `RUST_LOG` environment variable:

- **Bash**:

  ```bash
  export RUST_LOG=info
  ```

- **PowerShell**:

  ```powershell
  $env:RUST_LOG="info"
  ```

Use `--nocapture` to view logs during test runs:

```bash
cargo test -- --nocapture
```

---

## References

1. **Dwork, Cynthia, Andrew Goldberg, and Moni Naor.** *On Memory-Bound Functions for Fighting Spam*. Advances in Cryptology - CRYPTO 2003. Springer, Berlin, Heidelberg, 2003.  
   [DOI: 10.1007/978-3-540-45146-4_25](https://doi.org/10.1007/978-3-540-45146-4_25)

2. **Zola Gonano.** *A Very Technical Look at Bitmessage*. 2023.  
   [Link](https://zolagonano.github.io/blog/posts/a-very-technical-look-at-bitmessage)

3. **Jonathan Warren.** *Bitmessage: A Peer-to-Peer Message Authentication and Delivery System*. Bitmessage, 2012.  
   [Link](https://bitmessage.org/bitmessage.pdf)

4. **Martin Kleppmann.** *Implementing Curve25519/X25519: A Tutorial on Elliptic Curve Cryptography*. 2022.  
   [DOI: 10.1145/nnnnnnn.nnnnnnn](https://doi.org/10.1145/nnnnnnn.nnnnnnn)

5. **Daniel J. Bernstein et al.** *High-speed high-security signatures*. Journal of Cryptographic Engineering, 2012.  
   [Link](https://cr.yp.to/papers.html#ed25519)

6. **Alex Biryukov et al.** *Argon2: The Memory-Hard Function for Password Hashing and Other Applications*. University of Luxembourg, 2016.  
   [Link](https://www.cryptolux.org/index.php/Argon2)

---

## License

ShadowLink is licensed under the MIT License. See the [`LICENSE`](./LICENSE) file for details.

---
