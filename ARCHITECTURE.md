# Project Architecture – quantum-tunneler

This document outlines the core structure and logic of the `quantum-tunneler` project, including module responsibilities and high-level data flow.

For the latest updates and source code, visit our [GitHub repository](https://github.com/doomhammerhell/quantum-tunneler).

---

## 📁 Core Modules

### `crypto/`
- Implements post-quantum algorithms (Kyber, Falcon)
- Provides interfaces for key exchange and digital signatures
- Uses `no_std`-friendly data structures via `heapless`

### `ike/`
- Handles IKEv2 key negotiation (Phase 1 and 2)
- Establishes initial session agreements using post-quantum primitives
- Interfaces directly with the `crypto` module

### `ipsec/`
- Encapsulates data with IPSec (ESP and AH protocols)
- Manages Security Associations (SAs) and Security Policies
- Provides replay protection and packet encryption/integrity

### `utils.rs`
- Shared utilities: logging, type aliases, error definitions

---

## 🔁 General Connection Flow

1. CLI executes a command such as `connect`
2. CLI invokes IKEv2 negotiation through the `ike` module
3. `ike` handles key exchange using `crypto` module
4. Once SAs are established, `ipsec` starts encrypting traffic
5. Packets are securely transmitted over the tunnel

---

## 🧩 CLI Integration

The CLI serves as an interface to test and manage tunnels using the core library:

- `init`: Initialize default configs
- `connect`: Simulate secure connection
- `status`: Show session state
- `benchmark`: Measure performance and timing

---

## 🔮 Future Extensions

- Real transport integration (UDP/TCP)
- NAT traversal support
- WireGuard compatibility layer
- Server mode with mTLS/PSK
- Secure PACS and VPN applications for healthcare 