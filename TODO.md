# TODO

Introduce a DHT / routing‐prefix abstraction layer
Why: Lays the groundwork for safely evolving the network API (including routing‐prefix changes) without breaking client/node code.

Improve routing‐prefix & DHT structure (compact “101…” → 101000…0)
Why: Directly tied to the DHT abstraction above; once the interface is in place we can swap in a more efficient prefix representation.

Bound node concurrency (limit number of open sockets)
Why: Prevents resource exhaustion under load—critical for a robust test suite and real‐world runs.

Implement periodic “honesty” testing for nodes & clients
Why: Strengthens network health and lays the foundation for penalizing misbehavior.

Add address_book.rs for client contact management
Why: Important for UX and for keeping client code organized, but orthogonal to core routing.

Evaluate using Tower
Why: Could simplify middleware & backpressure but comes after nailing down our own abstractions.

Support for group messages
Why: A nice‐to‐have on top of the existing point‐to‐point messaging flow.

## Overview

This project is structured into directories and modules, each responsible for a specific part of the system’s functionality. The main components are cryptographic operations, network logic, type definitions, utilities, and configuration handling. The `bin/` directory contains binaries that can run as either a client or a node, while `tests/` houses both unit and integration tests.

### Directory Structure

```plaintext
bin/
├── client.rs 
├── node.rs
src/
├── lib.rs                  // Shared library entry point    
├── crypto/
│   ├── mod.rs              // Crypto module entry point
│   ├── authentication.rs   // Key and signature authentication utilities
│   ├── encryption.rs       // Message encryption/decryption logic
│   ├── pow.rs              // Proof-of-Work/Memory (Argon2) logic
├── network/
│   ├── mod.rs              // Network module entry point
│   ├── node.rs             // Node logic (message hosting, relaying, routing)
│   ├── dht.rs              // Distributed Hash Table for node lookups
│   ├── client.rs           // Client logic (connect, subscribe, send messages)
├── types/
│   ├── mod.rs              // Shared type definitions entry point
│   ├── address.rs          // PrivateAddress, PublicAddress and routing prefix logic
│   ├── message.rs          // Message type definitions
│   ├── packet.rs           // Packet structure (encrypted payloads, PoW data)
│   ├── node_info.rs        // NodeInfo and NodeInfoExtended
│   ├── routing_prefix.rs   // RoutingPrefix type for address-based routing
│   ├── argon2_params.rs    // Argon2 parameters for PoW/PoMemory
├── utils.rs                // Shared utilities (hashing, serialization, etc.)
├── config.rs               // Configuration parsing and defaults
tests/
├── unit/
│   ├── test_node.rs        // Unit tests for node logic
│   ├── test_encryption.rs  // Unit tests for encryption logic
├── integration.rs           // Integration tests
```

---

## Responsibilities and Next Steps

### `bin/`

- **client.rs**:  
  Provides a command-line interface for client operations such as:
  - Connecting to bootstrap nodes
  - Finding and subscribing to serving nodes
  - Sending messages to Base58-encoded addresses (to be implemented)

- **node.rs**:  
  Provides a command-line interface for running a node that:
  - Accepts subscriptions from clients
  - Relays messages based on routing prefixes
  - Integrates with DHT for prefix-based routing

### `src/`

#### `crypto/`

- **authentication.rs**: Handle key generation, signatures, and signature verification.
- **encryption.rs**: Centralize all encryption-related logic.
- **pow.rs**: Implement proof-of-work or memory-hard functions (like Argon2) to prevent spam and ensure resource commitment.

#### `network/`

- **node.rs**: Core node functionality:
  - Host messages
  - Manage subscriptions and unsubscribes
  - Relay messages to nodes serving specific routing prefixes
- **client.rs**: Core client functionality:
  - Discover and connect to nodes
  - Subscribe/unsubscribe to message feeds
  - Send messages upstream through connected nodes
- **dht.rs**: Distributed Hash Table for:
  - Storing and retrieving node information
  - Looking up nodes serving particular routing prefixes

#### `types/`

- **address.rs**:  
  Define `PrivateAddress` and `PublicAddress` and handle routing prefix generation logic.  
- **message.rs**:  
  Define the `Message` enum or struct to represent all protocol-level messages.
- **packet.rs**:  
  Define `Packet` structures for encapsulating messages with encryption, TTL, and PoW.
- **node_info.rs**:  
  Store and share node capability data (like supported Argon2 params, POW difficulty).
- **routing_prefix.rs**:  
  Define `RoutingPrefix` for determining which nodes serve which addresses.
- **argon2_params.rs**:  
  Define Argon2 parameter sets for configuring memory-hard proofs.

#### `utils.rs`

- Utility functions for hashing, serialization, and randomness that are shared across modules.

#### `config.rs`

- Load and validate configuration (e.g., from files or environment variables).
- Provide defaults and ensure node/client behavior is customizable.

### `tests/`

- **unit/test_node.rs**: Unit tests for node logic (subscription, message forwarding, handling TTL).
- **unit/test_encryption.rs**: Unit tests for encryption logic (integrity, correct encryption/decryption, handling of invalid keys).
- **integration.rs**: Integration tests that simulate multiple nodes and clients interacting, ensuring end-to-end functionality.

---

## Testing and Future Work

- Add tests for client logic (once new address generation and Base58-encoded messaging is implemented).
- Improve DHT tests to ensure correct node lookups.
- Periodically test node honesty and consider a mechanism to detect or penalize dishonest nodes.
- Evaluate adding group messaging functionality.

---
