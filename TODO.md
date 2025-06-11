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
