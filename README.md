# ShadowLink

ShadowLink is a decentralized, encrypted messaging network inspired by Bitmessage, but redesigned for scalability, security, and efficiency using modern cryptographic techniques. This project is implemented in Rust, leveraging its safety guarantees and performance.

## Overview

ShadowLink builds on the core ideas of Bitmessage but introduces key improvements for scalability, robustness, and improved anonymity. Nodes and clients form the backbone of the network, providing both storage and communication capabilities.

### Key Features

- **Encrypted Messaging**: End-to-end encryption using Curve25519 for key exchange and Ed25519 for authentication.
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

## Getting Started

### Prerequisites

1. **Install Rust and Cargo**

   ShadowLink is implemented in Rust. Ensure you have Rust and Cargo installed. You can install them using the following command:

   ```bash
   curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
   ```

   For more details, visit the [official Rust website](https://www.rust-lang.org/).

2. **Clone the Repository**

   ```bash
   git clone https://github.com/razor389/shadow-link.git
   cd shadow-link
   ```

### Building the Project

1. **Compile the Project**

   Build the project in release mode for optimal performance:

   ```bash
   cargo build --release
   ```

2. **Run Tests**

   Verify the functionality by running the test suite:

   ```bash
   cargo test
   ```

---

## Usage

ShadowLink can operate in either **node mode** or **client mode**, depending on your use case.

### Running a Node

Nodes form the backbone of the network, handling message storage, routing, and distribution.

1. **Basic Node Startup**

   ```bash
   cargo run --release --bin node -- \
       --address 127.0.0.1:8000 \
       --prefix FF \
       --bootstrap 127.0.0.1:8001,127.0.0.1:8002
   ```

2. **Full Options Example**

   ```bash
   cargo run --release --bin node -- \
       --address 127.0.0.1:8000 \
       --prefix FF \
       --bootstrap 127.0.0.1:8001 \
       --pow-difficulty 10 \
       --max-ttl 86400 \
       --min-m-cost 8 \
       --min-t-cost 1 \
       --min-p-cost 1 \
       --cleanup-interval 300 \
       --blacklist-duration 600 \
       --discovery-interval 3600
   ```

#### Node Command-Line Arguments

- `--address`: **(Required)** Socket address for the node (e.g., `127.0.0.1:8000`).
- `--prefix`: **(Required)** Routing prefix in hexadecimal.
- `--bootstrap`: Comma-separated list of bootstrap node addresses to connect with.
- `--pow-difficulty`: Proof of Work difficulty level (default: `10`).
- `--max-ttl`: Maximum Time-To-Live for messages in seconds (default: `86400`).
- `--min-m-cost`: Minimum Argon2 memory cost (default: `8`).
- `--min-t-cost`: Minimum Argon2 time cost (default: `1`).
- `--min-p-cost`: Minimum Argon2 parallelism cost (default: `1`).
- `--cleanup-interval`: Interval in seconds for cleaning expired packets (default: `300`).
- `--blacklist-duration`: Duration in seconds for IP blacklisting (default: `600`).
- `--discovery-interval`: Node discovery interval in seconds (default: `3600`).

### Running a Client

Clients interact with the network by sending and receiving encrypted messages.

1. **Basic Client Usage**

   ```bash
   cargo run --release --bin client -- \
       --bootstrap 127.0.0.1:8000 \
       --prefix FF \
       --length 8
   ```

2. **Full Options Example**

   ```bash
   cargo run --release --bin client -- \
       --bootstrap 127.0.0.1:8000 \
       --prefix FF \
       --length 8 \
       --max-prefix 64 \
       --min-m-cost 8 \
       --min-t-cost 1 \
       --min-p-cost 1 \
       --exact-argon2
   ```

#### Client Command-Line Arguments

- `--bootstrap`: **(Required)** Bootstrap node address to connect to (e.g., `127.0.0.1:8000`).
- `--prefix`: Desired routing prefix in hexadecimal (optional).
- `--length`: Bit length for generated prefix (optional).
- `--max-prefix`: Maximum prefix length to search for (default: `64`).
- `--min-m-cost`: Minimum Argon2 memory cost.
- `--min-t-cost`: Minimum Argon2 time cost.
- `--min-p-cost`: Minimum Argon2 parallelism cost.
- `--exact-argon2`: Use exact Argon2 parameters for PoM.

---

## Logging

Configure logging levels using the `RUST_LOG` environment variable to control the verbosity of logs.

- **Bash**

  ```bash
  export RUST_LOG=info
  ```

- **PowerShell**

  ```powershell
  $env:RUST_LOG="info"
  ```

- **Viewing Logs During Test Runs**

Use the `--nocapture` flag to view logs while running tests:

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
