# quantum-tunneler

**Quantum-Tunneler** is a pure Rust implementation of a **Quantum-Safe IPSec protocol**, inspired by Aliro Technologies' approach to real-world post-quantum secure networking. The goal is to build a robust and extensible cryptographic stack for VPNs, embedded systems, and critical infrastructure, with native support for post-quantum cryptography.

## 🎯 Goals

- Implement a complete IPSec stack with IKEv2 key negotiation
- Integrate post-quantum cryptography using:
  - **Kyber512** (Key Encapsulation Mechanism)
  - **Falcon512** (Digital Signature Scheme)
  - **Dilithium3** (Digital Signature Scheme)
  - **SPHINCS+** (Digital Signature Scheme)
- Build a developer-friendly CLI for testing, simulation, and tunnel management
- Design for `no_std` compatibility targeting IIoT and embedded systems

## ✨ Technical Highlights

- 100% Rust-based implementation
- Modular architecture using Rust workspaces and crates
- Focused on security, testability, and clear documentation
- Ready for benchmarking, simulation, and audit scenarios
- Multiple post-quantum cryptographic primitives
- Generic cryptographic interfaces for easy algorithm switching

## 💡 Motivation

With the rise of quantum computing, traditional cryptographic methods such as RSA and ECC are becoming vulnerable. This project aims to proactively address this threat by exploring practical and secure quantum-safe networking strategies.

## 📦 Project Structure

```
quantum-tunneler/
├── quantum_ipsec/          # Core library
│   ├── crypto/             # Cryptographic primitives
│   │   ├── kyber.rs        # Kyber512 KEM
│   │   ├── falcon.rs       # Falcon512 signatures
│   │   ├── dilithium.rs    # Dilithium3 signatures
│   │   ├── sphincs.rs      # SPHINCS+ signatures
│   │   └── traits.rs       # Generic crypto interfaces
│   ├── ike/                # IKEv2 implementation
│   ├── ipsec/              # IPSec implementation
│   └── utils/              # Utility functions
├── cli/                    # Command-line interface
└── docs/                   # Technical documentation
```

## 🚀 Getting Started

### Prerequisites

- Rust 2021 edition or later
- Cargo package manager

### Installation

```bash
git clone https://github.com/doomhammerhell/quantum-tunneler.git
cd quantum-tunneler
cargo build
```

### Usage

```bash
# Initialize the system
quantum-ipsec-cli init --security-level 128 --max-sas 1024

# Connect to a remote endpoint
quantum-ipsec-cli connect --remote 192.168.1.1 --local 192.168.1.2

# Check status
quantum-ipsec-cli status

# Run benchmarks
quantum-ipsec-cli benchmark
```

## 🧠 Inspiration

Inspired by the article:  
[Real-World Implementation of Quantum-Safe IPSec – Aliro](https://www.aliroquantum.com/blog/real-world-implementation-of-quantum-safe-ipsec)

## 🔐 Current Status

> Under development — Phase 5: CLI & Monitoring Interface

- ✅ Phase 1: Planning and Architecture
- ✅ Phase 2: Post-Quantum Cryptography Integration
- ✅ Phase 3: IKEv2 Protocol Implementation
- ✅ Phase 4: IPSec ESP Implementation
- ✅ Phase 5: CLI & Monitoring Interface(in progress)

Contributions and feedback are welcome! Please feel free to open issues or submit pull requests on [GitHub](https://github.com/doomhammerhell/quantum-tunneler).

## 📚 Documentation

- [Architecture](ARCHITECTURE.md) - Detailed technical architecture
- [Phases](PHASES.md) - Project roadmap and milestones

## 📝 License

This project is licensed under either of:
- Apache License, Version 2.0
- MIT License 