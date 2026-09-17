# Development phases

Historical completion claims were withdrawn by the forensic audit. Presence of a module or a passing mock round trip is not protocol completion.

| Phase | Work | Status |
|---|---|---|
| 1 | Planning and Architecture | Revised foundation; continuing |
| 2 | Post-Quantum Cryptography | Not implemented; unsafe mocks removed |
| 3 | IKEv2 Foundation | Partial: bounded parser and isolated key-schedule arithmetic |
| 4 | IPsec/ESP Foundation | Partial: AES-GCM packet primitive and local lifecycle; no gateway |
| 5 | CLI and Monitoring | Partial: config, capabilities, laboratory benchmark |
| 6 | Benchmarking and Stress Testing | Partial: ESP benchmarks; no tunnel stress test |
| 6.5 | Protocol Correctness and Cryptographic Hardening | Partial; authenticated IKE and interoperability gates open |
| 7 | Standards-Oriented Hybrid PQ/T IKEv2 | Planned; architecture documented |
| 8 | Quantum Key Infrastructure / QKD Provider | Planned; blocked by Phase 6.5 gates |
| 9 | Hybrid Key Composition and Crypto-Agility | Planned |
| 10 | Quantum-Safe Network Daemon | Planned |
| 11 | Multi-Site Quantum-Safe Fabric | Planned |
| 12 | Hardware QKD Interoperability Lab | Planned |

## Next gates, in order

1. Review packet hardening and perform independent ESP interoperability/vector validation; sustain fuzzing.
2. Implement a small authenticated IKE profile, complete identity/transcript binding, proposal/selector verification, retransmission/SPI/message-ID semantics and CHILD_SA tests against an independent peer.
3. Select and audit standardized ML-KEM/ML-DSA providers; verify known-answer tests, key validation, implicit rejection, error propagation and secret lifetimes. Never alias legacy Kyber/Dilithium implementations as standardized algorithms.
4. Implement RFC 9242/9370 intermediate transcript and sequential key updates, checking the ML-KEM IKE specification status again before coding negotiation.
5. Only then implement QKD provider, emulator, bounded response parser and pools; follow with explicit downgrade policy and transactional QKD-aware rekey.
6. Add runtime ownership, observability, scale tests, then hardware interoperability.

No later phase is complete. QKD and a daemon must not obscure an unauthenticated control plane.
