# TODO

1. **Bound Node Concurrency (limit open sockets)**
   *Why:* Prevent resource exhaustion under high load; ensures stability in both test environments and real-world deployments.

2. **Persistent & Multiplexed Connections**
   *Why:* Amortize TCP/QUIC handshakes, reduce latency, and enable NAT traversal for global-scale mesh networks.

3. **Adaptive PoW Parameter Tuning & Lightweight Filtering**
   *Why:* Balance spam prevention with throughput; reject invalid packets before performing expensive crypto.

4. **Rate Limiting & Backpressure**
   *Why:* Protect nodes from flash crowds and DoS by throttling forwards and subscription broadcasts.

5. **Disk‑Backed Packet Store & Node State Persistence**
   *Why:* Ensure message durability across restarts, bound memory usage, and support offline delivery.

6. **DHT Bucket Maintenance & Parallel Lookups**
   *Why:* Maintain routing table health under churn and accelerate lookups in large-scale networks.

7. **Periodic Honesty Testing for Nodes & Clients**
   *Why:* Monitor protocol compliance, detect misbehavior, and lay groundwork for reputation or penalty mechanisms.

8. **Pluggable Transports & Traffic Obfuscation**
   *Why:* Evade DPI and active probing; disguise traffic to look like standard HTTPS, Shadowsocks, or other innocuous protocols.

   * **Onion Routing Option:** Integrate layered encryption hops (e.g. Tor-style circuits) over the transport to prevent intermediate peers from linking source and destination and further resist traffic analysis.

9. **Bridge & Rendezvous Node Integration**
   *Why:* Provide out-of-band bootstrap paths when direct DHT is censored; leverage social trust for first contacts.

10. **Cover Traffic & Mixing**
    *Why:* Even with shadow addressing and broadcast dissemination, passive observers can still profile the network by monitoring message timing, volume, and relay patterns. Without cover traffic, an attacker can:

    * **Timing Correlation:** Observe when a new packet appears in the network and correlate it with a client’s send event to infer sender identity.
    * **Volume Analysis:** Track spikes in overall traffic or per-prefix message counts to detect communication bursts or identify high-activity users.
    * **Sequence Patterns:** Follow the propagation order of packets across nodes; if certain nodes consistently relay specific messages sooner, they can be linked to origin or destination.
    * **Intersection Attacks:** Over multiple rounds, intersect sets of active prefixes or subscribers to narrow down which clients are communicating.

    *Mitigation:* Inject dummy packets at randomized intervals, batch real messages into fixed-size windows, and add random delays before forwarding. This masks real traffic patterns and breaks direct timing/volume correlations.

11. **Address Book & UX Enhancements (address\_book.rs)**
    *Why:* Simplify key management, contact workflows, and improve user adoption.

12. **Support for Group Messaging**
    *Why:* Extend beyond one-to-one; valuable once core routing and privacy features are stable.

13. **Evaluate Using Tower**
    *Why:* Consider after establishing custom backpressure abstractions to simplify middleware and service composition.

14. **CLI → GUI / Mobile Client Wrappers**
    *Why:* Lower barrier for non-technical users, especially in adversarial environments.

15. **Security Audit & Formal Verification**
    *Why:* Validate cryptographic and protocol correctness before large-scale deployment.

16. **Operational Monitoring & Governance Tools**
    *Why:* Detect misbehaving nodes, monitor network health, and enable long-term maintenance.

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

* **client.rs**:  
  Provides a command-line interface for client operations such as:
  * Connecting to bootstrap nodes
  * Finding and subscribing to serving nodes
  * Sending messages to Base58-encoded addresses (to be implemented)

* **node.rs**:  
  Provides a command-line interface for running a node that:
  * Accepts subscriptions from clients
  * Relays messages based on routing prefixes
  * Integrates with DHT for prefix-based routing

### `src/`

#### `crypto/`

* **authentication.rs**: Handle key generation, signatures, and signature verification.
* **encryption.rs**: Centralize all encryption-related logic.
* **pow.rs**: Implement proof-of-work or memory-hard functions (like Argon2) to prevent spam and ensure resource commitment.

#### `network/`

* **node.rs**: Core node functionality:
  * Host messages
  * Manage subscriptions and unsubscribes
  * Relay messages to nodes serving specific routing prefixes
* **client.rs**: Core client functionality:
  * Discover and connect to nodes
  * Subscribe/unsubscribe to message feeds
  * Send messages upstream through connected nodes
* **dht.rs**: Distributed Hash Table for:
  * Storing and retrieving node information
  * Looking up nodes serving particular routing prefixes

#### `types/`

* **address.rs**:  
  Define `PrivateAddress` and `PublicAddress` and handle routing prefix generation logic.  
* **message.rs**:  
  Define the `Message` enum or struct to represent all protocol-level messages.
* **packet.rs**:  
  Define `Packet` structures for encapsulating messages with encryption, TTL, and PoW.
* **node_info.rs**:  
  Store and share node capability data (like supported Argon2 params, POW difficulty).
* **routing_prefix.rs**:  
  Define `RoutingPrefix` for determining which nodes serve which addresses.
* **argon2_params.rs**:  
  Define Argon2 parameter sets for configuring memory-hard proofs.

#### `utils.rs`

* Utility functions for hashing, serialization, and randomness that are shared across modules.

#### `config.rs`

* Load and validate configuration (e.g., from files or environment variables).
* Provide defaults and ensure node/client behavior is customizable.

### `tests/`

* **unit/test_node.rs**: Unit tests for node logic (subscription, message forwarding, handling TTL).
* **unit/test_encryption.rs**: Unit tests for encryption logic (integrity, correct encryption/decryption, handling of invalid keys).
* **integration.rs**: Integration tests that simulate multiple nodes and clients interacting, ensuring end-to-end functionality.

---

## Testing and Future Work

* Add tests for client logic (once new address generation and Base58-encoded messaging is implemented).
* Improve DHT tests to ensure correct node lookups.
* Periodically test node honesty and consider a mechanism to detect or penalize dishonest nodes.
* Evaluate adding group messaging functionality.

---
