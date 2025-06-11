# Development Roadmap

This roadmap breaks down our prioritized TODO list into concrete development phases, milestones, and tasks. Timeline estimates assume a small dedicated team.

---

## Phase 1: Core Scalability & Stability (Months 1–3)

### Milestone 1.1: Limit Resources & Protect Under Load

* **Task 1.1.1:** Implement connection semaphores to cap concurrent TCP sockets per node (e.g., `tokio::sync::Semaphore`).
* **Task 1.1.2:** Write integration tests simulating high-volume opens to validate caps.

### Milestone 1.2: Long‑Lived, Multiplexed Connections

* **Task 1.2.1:** Introduce a framed protocol (e.g., `tokio-util::codec::LengthDelimitedCodec`) over persistent connections.
* **Task 1.2.2:** Replace per-message `TcpStream::connect` calls with a connection pool or single multiplexed channel.
* **Task 1.2.3:** Benchmark handshake latency vs. throughput improvements.

### Milestone 1.3: Adaptive PoW & Pre‑Filter

* **Task 1.3.1:** Add lightweight pre-checks: verify packet header, TTL, and argon2\_params before full PoW.
* **Task 1.3.2:** Implement dynamic difficulty adjustment based on moving average inbound rates.
* **Task 1.3.3:** Unit tests for edge cases: zero TTL, malformed headers, overly large payloads.

### Milestone 1.4: Rate Limiting & Backpressure

* **Task 1.4.1:** Integrate a per-peer token bucket or leaky-bucket rate limiter.
* **Task 1.4.2:** Propagate backpressure signals upstream to clients (e.g., `Message::Busy` response).
* **Task 1.4.3:** Expose Prometheus metrics for queue lengths and drop counts.

---

## Phase 2: Persistence & DHT Resilience (Months 3–6)

### Milestone 2.1: Disk‑Backed Packet Store

* **Task 2.1.1:** Integrate RocksDB or sled for on-disk storage of packets (keyed by `pow_hash`).
* **Task 2.1.2:** Migrate in-memory `HashMap` into a hybrid LRU+persistent cache.
* **Task 2.1.3:** Graceful shutdown/load on startup logic.

### Milestone 2.2: DHT Bucket Maintenance

* **Task 2.2.1:** Implement Kademlia-style bucket refresh (parallel α-lookups every `kBucketRefreshInterval`).
* **Task 2.2.2:** Add node eviction policies based on age and health checks.
* **Task 2.2.3:** Simulate churn scenarios to verify routing table robustness.

### Milestone 2.3: Periodic Honesty Tests

* **Task 2.3.1:** Define challenge protocols (ping + proof requests) for random peers.
* **Task 2.3.2:** Record successes/failures, compute peer reputation scores.
* **Task 2.3.3:** Blacklist or deprioritize nodes below a reputation threshold.

---

## Phase 3: Censorship Resistance (Months 6–9)

### Milestone 3.1: Pluggable Transports

* **Task 3.1.1:** Abstract `TcpStream` to a `Transport` trait.
* **Task 3.1.2:** Provide built-in transports: TLS+WebSocket, Shadowsocks, obfs4.
* **Task 3.1.3:** CLI flags to select transport at runtime.

### Milestone 3.2: Bridge & Rendezvous

* **Task 3.2.1:** Extend bootstrap logic to accept OOB lists (email, SMS, QR imports).
* **Task 3.2.2:** Implement TOFU (trust-on-first-use) key pinning in `config.rs`.
* **Task 3.2.3:** Write tutorials for offline bridge distribution.

### Milestone 3.3: Cover Traffic & Mixing

* **Task 3.3.1:** Implement periodic dummy packet injection at randomized intervals.
* **Task 3.3.2:** Batch real packets into fixed-size windows with random delays.
* **Task 3.3.3:** Measure metadata leakage reduction via simulated adversary.

---

## Phase 4: UX, Group Features & Hardening (Months 9–12)

### Milestone 4.1: Address Book & UX

* **Task 4.1.1:** Create `address_book.rs` API for CRUD on named addresses.
* **Task 4.1.2:** Extend CLI: `shadowlink address add/list/remove` commands.
* **Task 4.1.3:** Validate and unit-test persistence format (e.g., JSON/TOML).

### Milestone 4.2: Group Messaging

* **Task 4.2.1:** Design group prefix conventions (e.g., `G<number>` bits).
* **Task 4.2.2:** Extend `Packet` and `Message` types for multicast routing.
* **Task 4.2.3:** Add PoW/authentication metadata to prevent forgery.

### Milestone 4.3: Tower Evaluation

* **Task 4.3.1:** Prototype DHT RPC endpoints as Tower `Service`s.
* **Task 4.3.2:** Compare with existing code for maintainability and performance.
* **Task 4.3.3:** Decide integration vs. custom middleware.

### Milestone 4.4: GUI/Mobile Clients

* **Task 4.4.1:** Define JSON-RPC or WebSocket APIs for external UIs.
* **Task 4.4.2:** Prototype minimal Electron or React Native client for messaging.
* **Task 4.4.3:** Ensure key storage and TLS/transport choices are exposed.

### Milestone 4.5: Security Audit & Formal Verification

* **Task 4.5.1:** Engage an external security firm for code review.
* **Task 4.5.2:** Formalize routing invariants and consider TLA+/Rust verification.

### Milestone 4.6: Monitoring & Governance

* **Task 4.6.1:** Instrument Prometheus metrics across core modules.
* **Task 4.6.2:** Build Grafana dashboards with alerting for misbehavior or partitions.
* **Task 4.6.3:** Define governance policies for reputation, blacklisting, and node promotion.
