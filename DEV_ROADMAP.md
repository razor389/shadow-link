# Development Roadmap

This roadmap breaks down our prioritized TODO list into concrete development phases, milestones, and tasks
---

## Phase 1: Core Scalability & Stability (Months 1–3)

### Milestone 1.1: Limit Resources & Protect Under Load

* **Task 1.1.1:** Implement connection semaphores to cap concurrent TCP sockets per node (`tokio::sync::Semaphore`).
* **Task 1.1.2:** Write integration tests simulating high-volume opens to validate caps.

### Milestone 1.2: Long-Lived, Multiplexed Connections

* **Task 1.2.1:** Introduce a framed protocol (`tokio-util::codec::LengthDelimitedCodec`) over persistent connections.
* **Task 1.2.2:** Replace per-message `TcpStream::connect` calls with a connection pool or single multiplexed channel.
* **Task 1.2.3:** Benchmark handshake latency vs. throughput improvements.

### Milestone 1.3: Adaptive PoW & Pre-Filter

* **Task 1.3.1:** Add lightweight pre-checks: verify packet header, TTL, and Argon2 parameters before full PoW.
* **Task 1.3.2:** Implement dynamic difficulty adjustment based on moving-average inbound rates.
* **Task 1.3.3:** Unit tests for edge cases: zero TTL, malformed headers, oversized payloads.

### Milestone 1.4: Rate Limiting & Backpressure

* **Task 1.4.1:** Integrate a per-peer token-bucket or leaky-bucket rate limiter.
* **Task 1.4.2:** Propagate backpressure signals upstream to clients (e.g., `Message::Busy`).
* **Task 1.4.3:** Expose Prometheus metrics for queue lengths and drop counts.

**Testing & Documentation**

* **Testing:** Unit, integration, adversarial, and performance tests for all Phase 1 milestones.
* **Documentation:** Initial threat model, security guidelines, and user-facing deployment notes.

---

## Phase 2: Persistence, DHT Resilience & Security (Months 3–8)

### Milestone 2.1: Disk-Backed Packet Store

* **Task 2.1.1:** Integrate RocksDB or sled for on-disk packet storage (keyed by `pow_hash`).
* **Task 2.1.2:** Migrate in-memory `HashMap` into a hybrid LRU + persistent cache.
* **Task 2.1.3:** Graceful shutdown/load on startup logic.

### Milestone 2.2: DHT Bucket Maintenance

* **Task 2.2.1:** Implement Kademlia-style bucket refresh (parallel α-lookups every `kBucketRefreshInterval`).
* **Task 2.2.2:** Add node eviction policies based on age and health checks.
* **Task 2.2.3:** Simulate churn scenarios to verify routing-table robustness.

### Milestone 2.3: Periodic Honesty Tests

* **Task 2.3.1:** Define challenge protocols (ping + proof requests) for random peers.
* **Task 2.3.2:** Record successes/failures; compute peer reputation scores.
* **Task 2.3.3:** Blacklist or deprioritize nodes below a reputation threshold.

### Milestone 2.4: Storage Economics

* **Task 2.4.1:** Define storage quotas per node and enforce them.
* **Task 2.4.2:** Automatic pruning of old messages beyond configured retention.
* **Task 2.4.3:** Implement proof-of-storage challenges to verify disk holding.
* **Task 2.4.4:** Collect bandwidth and storage usage metrics.

### Milestone 2.5: Core Security Hardening

* **Task 2.5.1:** Enforce perfect forward secrecy on all connections.
* **Task 2.5.2:** Add key-rotation mechanisms and secure key deletion.
* **Task 2.5.3:** Introduce duress/panic-button codes for emergency scenarios.

### Milestone 2.6: Operational Security

* **Task 2.6.1:** Implement secure data wipe procedures and hidden volumes.
* **Task 2.6.2:** Support duress passwords triggering safe-mode.
* **Task 2.6.3:** Define emergency response protocols:

  * Network partition handling
  * Compromise detection and response
  * Secure shutdown procedures
  * Data recovery from hidden volumes

### Milestone 2.7: Sybil Resistance

* **Task 2.7.1:** Tie node ID generation to PoW to increase identity cost.
* **Task 2.7.2:** Develop distributed admission protocols (peer voting for new nodes).
* **Task 2.7.3:** Introduce optional staking mechanism for node identities.

**Testing & Documentation**

* **Testing:** Unit, integration, adversarial, and performance tests for all Phase 2 milestones.
* **Documentation:** Update threat model, security documentation, and deployment guides.

---

## Phase 3: Censorship Resistance & Resilience (Months 8–15)

### Pre-Milestone 3.0: Transport Evaluation & Partnerships

* **Task 3.0.1:** Evaluate existing transport libraries (Tor PT, Lantern).
* **Task 3.0.2:** Define integration interfaces for pluggable transports.
* **Task 3.0.3:** Establish collaboration framework with transport projects.

### Milestone 3.1: Pluggable Transports

* **Task 3.1.1:** Abstract `TcpStream` to a `Transport` trait.
* **Task 3.1.2:** Provide built-in transports: TLS+WebSocket, Shadowsocks, obfs4.
* **Task 3.1.3:** CLI flags to select transport at runtime.
* **Task 3.1.4:** Integrate onion-routing support (multi-hop encryption layers).

### Milestone 3.2: Bridge & Rendezvous

* **Task 3.2.1:** Accept out-of-band bootstrap lists (email, SMS, QR imports).
* **Task 3.2.2:** Implement TOFU (trust-on-first-use) key pinning.
* **Task 3.2.3:** Publish tutorials for offline bridge distribution.

### Milestone 3.3: Cover Traffic & Mixing

* **Task 3.3.1:** Periodic dummy-packet injection at random intervals.
* **Task 3.3.2:** Batch real packets into fixed-size windows with random delays.
* **Task 3.3.3:** Measure metadata leakage reduction via simulated adversary.

### Milestone 3.4: Advanced Circumvention

* **Task 3.4.1:** Implement domain-fronting transport.
* **Task 3.4.2:** Add traffic morphing to mimic HTTPS/video streams.
* **Task 3.4.3:** Integrate with CDN infrastructure for obfuscation.
* **Task 3.4.4:** Introduce decoy traffic patterns matching popular services.

### Milestone 3.5: DTN & Mesh Networking

* **Task 3.5.1:** Enable Delay-Tolerant Networking (DTN) mode.
* **Task 3.5.2:** Support sneakernet (USB message bundles).
* **Task 3.5.3:** Provide mesh-network fallback (peer-to-peer over LAN).

### Milestone 3.6: Advanced Metadata Protection

* **Task 3.6.1:** Implement constant-rate traffic shaping.
* **Task 3.6.2:** Add fixed-size message padding.
* **Task 3.6.3:** Support receiver anonymity sets to obscure recipients.

**Testing & Documentation**

* **Testing:** Unit, integration, adversarial, and performance tests for all Phase 3 milestones.
* **Documentation:** Update threat model, security documentation, and deployment guides.

---

## Phase 4: UX, Group Features & Governance (Months 15–18)

### Milestone 4.1: Address Book & UX

* **Task 4.1.1:** Develop `address_book.rs` API for CRUD on named addresses.
* **Task 4.1.2:** Extend CLI: `shadowlink address add/list/remove`.
* **Task 4.1.3:** Unit-test persistence format (JSON/TOML).

### Milestone 4.2: Group Messaging (Experimental)

* **Task 4.2.1:** Design group-prefix conventions (e.g., `G<number>` bits).
* **Task 4.2.2:** Extend `Packet` and `Message` for multicast routing (feature-flagged).
* **Task 4.2.3:** Add PoW/auth metadata to prevent forgery.

### Milestone 4.3: Tower Integration

* **Task 4.3.1:** Prototype DHT RPC endpoints as Tower `Service`s.
* **Task 4.3.2:** Compare maintainability and performance against custom code.
* **Task 4.3.3:** Choose middleware vs. custom solution.

### Milestone 4.4: Monitoring & Governance

* **Task 4.4.1:** Instrument Prometheus metrics across core modules.
* **Task 4.4.2:** Build Grafana dashboards with alerting for misbehavior.
* **Task 4.4.3:** Define governance policies: reputation, blacklisting, node promotion.

**Testing & Documentation**

* **Testing:** Unit, integration, adversarial, and performance tests for all Phase 4 milestones.
* **Documentation:** Update API docs, user guides, and deployment checklists.

---

## Phase 5: Formal Verification & Adversarial Testing (Months 19–23)

### Milestone 5.1: Security Audit & Formal Verification

* **Task 5.1.1:** Engage external security firm for code review.
* **Task 5.1.2:** Formalize routing invariants; explore TLA+ and Rust verification.
* **Task 5.1.3:** Conduct red-team adversarial testing.
* **Task 5.1.4:** Benchmark under hostile network conditions.

**Testing & Documentation**

* **Testing:** Continuous adversarial testing and performance benchmarking.
* **Documentation:** Publish security audit findings and full threat model.

---

## Phase 6: GUI/Mobile Clients & Ecosystem (Months 24–30)

### Milestone 6.1: GUI/Mobile Clients

* **Task 6.1.1:** Define JSON-RPC or WebSocket APIs for external UIs.
* **Task 6.1.2:** Prototype minimal Electron or React Native client (feature-flagged).
* **Task 6.1.3:** Expose key storage and transport settings securely.

### Milestone 6.2: Ecosystem & Community

* **Task 6.2.1:** Launch bounty programs for security research.
* **Task 6.2.2:** Open public project board (GitHub Projects) for transparency.
* **Task 6.2.3:** Establish partnerships with transport and mesh-network projects.

**Testing & Documentation**

* **Testing:** UX testing, mobile performance, and security reviews.
* **Documentation:** End-user guides, mobile deployment manuals, and developer SDK docs.

---

**Timeline Note:** This extended plan spans \~30 months to ensure a resilient, secure, and user-friendly system. Continuous testing, documentation updates, and community involvement occur at every phase.
