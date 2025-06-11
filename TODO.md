# TODO

This TODO list summarizes key development milestones aligned with the full Development Roadmap phases.

## Phase 1: Core Scalability & Stability (Months 1–3)

1. **Limit Resources & Protect Under Load**

   * Implement connection semaphores (`tokio::sync::Semaphore`).
   * Integration tests for high-volume socket caps.
2. **Persistent & Multiplexed Connections**

   * Framed protocol (`LengthDelimitedCodec`) over persistent channels.
   * Connection pool or multiplexed channel for `TcpStream`.
   * Benchmark handshake vs. throughput.
3. **Adaptive PoW & Pre-Filter**

   * Header/TTL/Argon2 pre-checks.
   * Dynamic difficulty adjustment.
   * Edge-case unit tests.
4. **Rate Limiting & Backpressure**

   * Per-peer token/leaky bucket.
   * Backpressure signals (e.g., `Message::Busy`).
   * Prometheus metrics for queue lengths.

## Phase 2: Persistence, DHT Resilience & Security (Months 3–8)

5. **Disk‑Backed Packet Store**

   * Integrate RocksDB/sled.
   * Hybrid LRU + persistent cache.
   * Graceful shutdown and startup load.
6. **DHT Bucket Maintenance**

   * Kademlia bucket refresh.
   * Eviction policies and churn simulation.
7. **Periodic Honesty Tests**

   * Ping + proof challenge protocols.
   * Reputation scoring and penalties.
8. **Storage Economics**

   * Enforce quotas and automatic pruning.
   * Proof-of-storage checks.
   * Bandwidth/storage metrics.
9. **Core Security Hardening**

   * Perfect forward secrecy and key rotation.
   * Secure key deletion.
   * Duress/panic-button codes.
10. **Operational Security**

    * Secure wipe and hidden volumes.
    * Duress passwords and safe-mode.
    * Emergency protocols for partitioning and compromise.
11. **Sybil Resistance**

    * PoW‑tied node IDs.
    * Distributed admission protocols.
    * Optional staking for identity.

## Phase 3: Censorship Resistance & Resilience (Months 8–15)

12. **Transport Evaluation & Partnerships**

    * Assess Tor PT, Lantern.
    * Define transport interfaces.
    * Establish collaboration framework.
13. **Pluggable Transports**

    * Abstract `Transport` trait.
    * TLS+WebSocket, Shadowsocks, obfs4.
    * Onion-routing integration.
14. **Bridge & Rendezvous**

    * Out-of-band bootstrap (email/SMS/QR).
    * TOFU key pinning.
    * Offline bridge tutorials.
15. **Cover Traffic & Mixing**

    * Dummy-packet injection.
    * Batch + random delays.
    * Adversarial leakage analysis.
16. **Advanced Circumvention**

    * Domain-fronting.
    * Traffic morphing (HTTPS/video).
    * CDN-based obfuscation.
    * Decoy patterns.
17. **DTN & Mesh Networking**

    * Delay-Tolerant Networking.
    * Sneakernet (USB bundles).
    * LAN mesh fallback.
18. **Advanced Metadata Protection**

    * Constant-rate shaping.
    * Fixed-size padding.
    * Receiver anonymity sets.

## Phase 4: UX, Group Features & Governance (Months 15–18)

19. **Address Book & UX**

    * `address_book.rs` API.
    * CLI commands: add/list/remove.
    * Persistence format tests.
20. **Group Messaging (Experimental)**

    * Group-prefix conventions.
    * Multicast routing (feature-flagged).
    * PoW/auth metadata.
21. **Tower Integration**

    * DHT RPC as Tower `Service`.
    * Middleware vs. custom comparison.
22. **Monitoring & Governance**

    * Prometheus & Grafana.
    * Governance policy definitions.

## Phase 5 & 6: Formal Verification, Adversarial Testing & Ecosystem (Months 19–30)

23. **Security Audit & Formal Verification**

    * External firm review.
    * TLA+/Rust invariants.
    * Red‑team testing.
24. **GUI/Mobile Clients & Ecosystem**

    * JSON‑RPC/WebSocket APIs.
    * Electron/React Native prototypes.
    * Bounty programs & public tracker.
