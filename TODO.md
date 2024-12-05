# TODO

-redo encryption.rs and packet.rs to roll encryption functionality into encryption.rs
-find closest node vs find serving node messages
-unit tests for node.rs and client.rs
-client.rs: private adderss creation in new, send message to base58 encoded address
-address.rs: new private addresses should be given either a routing prefix, a length (for a random prefix). at some point we can target bandwith usage.
-address_book.rs for client to be able to keep contact details
-periodic node honesty testing by client and nodes
-group messages?

```plaintext
bin/
├──client.rs 
├──node.rs
src/
├── lib.rs                  // Shared library entry point    
├── crypto/
|   ├── mod.rs              // Cryptography module
|   ├── authentication.rs   // Authentication utilities
|   ├── encryption.rs       // Encryption-related utilities    
|   ├── pow.rs              // Proof of Work/Memory utilities
├── network/
│   ├── mod.rs              // Network module
│   ├── node.rs             // Node logic (message hosting/relaying)
│   ├── dht.rs              // Distributed Hash Table (DHT) implementation
│   ├── client.rs           // Client logic
├── types/
│   ├── mod.rs              // Shared type definitions
│   ├── address.rs          // PrivateAddress and PublicAddress types
│   ├── message.rs          // Message type  
│   ├── packet.rs           // Packet structure
│   ├── node_info.rs        // NodeInfo and NodeInfoExtended types
│   ├── routing_prefix.rs   // RoutingPrefix type
|   ├── argon2_params.rs    // Argon2 proof of memory paramaters
├── utils.rs                // Shared utilities (hashing, serialization, etc.)
├── config.rs               // Configuration parsing and defaults
tests/
├── unit/
|   ├── test_node.rs
|   ├── test_encryption.rs
├── integration.rs
```

## Overview

### **1. Network Module (`src/network/`):**

**a. `node.rs` (Node Logic):**

- **Responsibilities:**
  - Handle incoming and outgoing messages.
  - Manage connections with other nodes.
  - Implement message hosting and relaying based on the address-prefix routing.
  - Maintain information about subscriptions and peers.

- **Key Functions to Implement:**
  - `connect_to_peer()`: Establish connections with peer nodes.
  - `broadcast_message()`: Send messages to appropriate nodes based on prefixes.
  - `receive_message()`: Handle incoming messages and verify them.
  - `subscribe()`: Manage subscriptions from other nodes or clients.

- **Unit Tests:**
  - Test node's ability to correctly route messages based on prefixes.
  - Verify that messages are relayed properly to subscribed nodes.
  - Ensure that the node handles connections and disconnections gracefully.
  - Test the node's response to invalid or malicious messages.

**b. `relay.rs` (Proof of Relay Logic):**

- **Responsibilities:**
  - Implement the Proof of Relay mechanism.
  - Collect acknowledgments from subscribers after delivering messages.
  - Submit proofs to smart contracts for payment.

- **Key Functions to Implement:**
  - `collect_acknowledgments()`: Gather confirmations from subscribers.
  - `submit_proof_of_relay()`: Interface with the blockchain to submit proofs.
  - `verify_relay()`: Ensure that relayed messages meet protocol requirements.

- **Unit Tests:**
  - Test the collection and validation of acknowledgments.
  - Verify that proofs are correctly formatted and accepted by the smart contract.
  - Simulate failures in relay and ensure proper penalties are applied.

**c. `dht.rs` (Distributed Hash Table Implementation):**

- **Responsibilities:**
  - Maintain a decentralized index of nodes and their address prefixes.
  - Enable efficient lookup of nodes responsible for specific prefixes.
  - Support dynamic prefix assignment for load balancing.

- **Key Functions to Implement:**
  - `store_node_info()`: Keep track of nodes and their prefixes.
  - `lookup_prefix()`: Find nodes responsible for a given address prefix.
  - `update_prefixes()`: Adjust prefix assignments based on network conditions.

- **Unit Tests:**
  - Test insertion and retrieval of node information.
  - Verify correct lookup results for given prefixes.
  - Ensure that dynamic updates to prefixes propagate correctly.

**d. `routing.rs` (Address-Prefix-Based Routing):**

- **Responsibilities:**
  - Determine the routing paths for messages based on address prefixes.
  - Balance load while preserving anonymity.
  - Integrate with the DHT for efficient routing decisions.

- **Key Functions to Implement:**
  - `calculate_route()`: Compute the next hop(s) for a message.
  - `adjust_routing_table()`: Update routing paths as the network changes.
  - `maintain_anonymity()`: Ensure that routing decisions do not compromise user privacy.

- **Unit Tests:**
  - Test routing decisions for various address prefixes.
  - Verify that load balancing adjusts routes appropriately.
  - Ensure that routing maintains anonymity under different scenarios.

### **2. Storage Module (`src/storage/`):**

**a. `storage.rs` (Message Storage Logic):**

- **Responsibilities:**
  - Store messages temporarily based on their TTL (Time to Live).
  - Provide access to messages for retrieval proofs.
  - Handle storage quotas and cleanup expired messages.

- **Key Functions to Implement:**
  - `store_message()`: Save incoming messages with metadata.
  - `retrieve_message()`: Access messages for delivery or proof generation.
  - `cleanup_expired_messages()`: Remove messages that have exceeded their TTL.

- **Unit Tests:**
  - Test storing and retrieving messages accurately.
  - Verify that messages expire correctly after TTL.
  - Ensure that storage handles capacity limits gracefully.

**b. `proofs.rs` (Proof of Retrievability Logic):**

- **Responsibilities:**
  - Generate cryptographic proofs that messages are stored.
  - Interact with smart contracts to submit proofs and receive payments.
  - Handle challenges from other nodes or clients requesting proofs.

- **Key Functions to Implement:**
  - `generate_proof()`: Create a proof that a specific message is stored.
  - `submit_proof_of_retrievability()`: Interface with the blockchain.
  - `respond_to_challenge()`: Provide proofs when challenged.

- **Unit Tests:**
  - Test proof generation for stored messages.
  - Verify that invalid proofs are detected.
  - Simulate challenges and ensure correct responses.

### **3. Blockchain Module (`src/blockchain/`):**

**a. `ledger.rs` (Distributed Ledger Implementation):**

- **Responsibilities:**
  - Maintain a record of transactions, stakes, and balances.
  - Support token transfers and staking mechanisms.
  - Provide an interface for querying the ledger state.

- **Key Functions to Implement:**
  - `record_transaction()`: Add new transactions to the ledger.
  - `update_stake()`: Handle staking and unstaking operations.
  - `get_balance()`: Retrieve the token balance of an address.

- **Unit Tests:**
  - Test recording and retrieval of transactions.
  - Verify stake updates and balance calculations.
  - Ensure that ledger maintains consistency after multiple operations.

**b. `smart_contracts.rs` (Smart Contracts for PoR and PoRelay):**

- **Responsibilities:**
  - Define the logic for Proof of Retrievability and Proof of Relay.
  - Automate payments based on successful proofs.
  - Enforce penalties for dishonest behavior.

- **Key Functions to Implement:**
  - `validate_proof_of_retrievability()`: Check submitted proofs and release payments.
  - `validate_proof_of_relay()`: Verify delivery proofs from nodes.
  - `apply_penalties()`: Slash stakes for invalid proofs or failures.

- **Unit Tests:**
  - Test validation of correct and incorrect proofs.
  - Verify that payments are released appropriately.
  - Ensure that penalties are enforced when necessary.

### **4. Types Module (`src/types/`):**

**a. `token.rs` (Token and Staking-Related Types):**

- **Responsibilities:**
  - Define data structures for tokens, stakes, and related transactions.
  - Support serialization and deserialization for network communication.

- **Key Structures to Implement:**
  - `Token`: Representing the unit of currency in the network.
  - `Stake`: Information about a node's staked tokens.
  - `Transaction`: Details of token transfers and staking actions.

- **Unit Tests:**
  - Test creation and manipulation of token amounts.
  - Verify correct serialization/deserialization of types.
  - Ensure that staking logic calculates rewards and penalties accurately.

### **5. Utilities and Configuration:**

**a. `utils.rs` (Shared Utilities):**

- **Responsibilities:**
  - Provide common functions such as hashing, serialization, and random number generation.
  - Implement helpers for network communication and error handling.

- **Key Functions to Implement:**
  - `hash_data()`: Compute cryptographic hashes.
  - `serialize_message()`: Convert data structures to bytes.
  - `generate_random_bytes()`: Produce cryptographically secure random data.

- **Unit Tests:**
  - Test utility functions for correctness.
  - Verify that serialization and deserialization are inverse operations.
  - Ensure that random data meets expected properties.

**b. `config.rs` (Configuration Parsing and Defaults):**

- **Responsibilities:**
  - Load configuration settings from files or environment variables.
  - Provide default values for various parameters.
  - Allow customization of node behavior.

- **Key Functions to Implement:**
  - `load_config()`: Read configuration from predefined locations.
  - `get_setting()`: Retrieve specific configuration values.
  - `validate_config()`: Ensure that configurations are valid and complete.

- **Unit Tests:**
  - Test loading configurations with various settings.
  - Verify that defaults are applied when necessary.
  - Ensure that invalid configurations are detected.

### **6. Writing Unit Tests:**

When writing unit tests, consider the following best practices:

- **Isolation:** Each test should be independent of others. Use mocks or stubs for external dependencies.
- **Coverage:** Aim to cover all critical paths, including edge cases and error conditions.
- **Clarity:** Write tests that are easy to understand, with clear assertions and minimal complexity.
- **Repeatability:** Tests should produce the same results every time they run, regardless of external factors.

**Test Cases:**

1. **Key Generation:**
   - Verify that new instances generate valid key pairs.
   - Ensure that keys are of the correct length and format.

2. **Encryption and Decryption:**
   - Test that encrypting and then decrypting a message returns the original message.
   - Use known keys to verify consistency.

3. **Invalid Key Handling:**
   - Attempt to decrypt with incorrect keys and ensure that it fails securely.
   - Test behavior when keys are malformed or corrupted.

4. **Nonce Usage:**
   - Ensure that nonces are correctly generated and used.
   - Test for nonce reuse vulnerabilities.

5. **Ephemeral Key Exchange:**
   - Verify that ephemeral keys are correctly generated and used in encryption.
   - Ensure that shared secrets are computed accurately.

### **Approach to Filling Out the Code:**

- **Start with Core Functionality:** Focus on implementing the essential features that enable basic communication and proof mechanisms.
- **Incremental Development:** Build and test each module step by step, ensuring stability before moving on.
- **Interface Definitions:** Clearly define the interfaces between modules to facilitate parallel development and integration.
- **Error Handling:** Implement robust error handling to deal with network issues, invalid data, and security threats.
- **Documentation:** Comment your code and write documentation to make it easier to maintain and for others to understand.

### **Additional Considerations:**

- **Security Audits:** Given the sensitive nature of cryptographic applications, consider conducting security reviews or audits of your code.
- **Performance Testing:** Evaluate the performance of your implementation, especially the PoW and networking components, to ensure scalability.
- **Community Feedback:** Engage with the open-source community for feedback and potential contributions.

---
