# Quantum Tunneler

An experimental Rust IPsec protocol-hardening foundation. **This is not a working VPN, an authenticated IKEv2 implementation, or a production-ready quantum-safe stack.**

The forensic audit found simulated cryptography, XOR-based ESP, authentication bypasses and secret serialization. Those implementations have been removed. The supported executable core is now an AES-256-GCM ESP packet primitive with externally provisioned, in-memory, directional SAs; bounded IKE structural parsing; experimental HKDF provisioning; and isolated IKE PRF key-schedule arithmetic.

## Implemented

- ESP AES-256-GCM-16 framing, deterministic salt/counter nonces, encrypted padding/trailer and mandatory tags.
- 64-packet replay window, authenticate-before-commit, hard lifetime/packet/byte limits, checked counters and generation replacement.
- Secret wrappers with zeroization on drop, redacted Debug and no secret serialization or Clone.
- Bounded IKE header/payload/proposal parsing; explicit failure for unavailable negotiation.
- Security property tests, known-answer fixtures, fuzz targets and reproducible ESP benchmarks.

## Unavailable

Authenticated IKE and CHILD_SA negotiation, real ML-KEM/ML-DSA providers, hybrid exchanges, QKD, live tunnel routing, TUN/TAP and a daemon. `connect`, file-based `encrypt`/`decrypt` and `monitor` fail explicitly. `status` reports no connected runtime; it does not invent tunnel statistics. AH and ChaCha20-Poly1305 are not supported.

This workspace **requires std**. The misleading `no_std` feature was removed. A future allocator-capable core/platform split is planned, not implemented.

## Build and verification

```sh
cargo build --workspace --locked
cargo test --workspace --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo fmt --all -- --check
cargo run -p quantum-ipsec-cli -- init
cargo run -p quantum-ipsec-cli -- status --json
cargo run --release -p quantum-ipsec-cli -- benchmark --duration 1 --payload-size 1400
cargo bench -p quantum_ipsec --bench esp
```

The binary is named `quantum-ipsec`. `init` creates configuration only, refuses overwrite, and creates no private key file. Benchmarking uses synthetic laboratory provisioning, not IKE or physical QKD. See [fuzzing instructions](fuzz/README.md).

## Engineering status

Phase 6.5 is **partially completed**: unsafe active paths are contained and packet/parser foundations are tested, but authenticated IKE and interoperability remain release gates. QKD implementation is deliberately deferred until these gates pass. No complete RFC, FIPS validation or ETSI interoperability claim is made.

- [Forensic audit](SECURITY_AUDIT.md)
- [Hardening report](HARDENING_REPORT.md)
- [Final implementation status](IMPLEMENTATION_STATUS.md)
- [Architecture](ARCHITECTURE.md), [roadmap](PHASES.md)
- [Threat model](THREAT_MODEL.md), [standards inventory](STANDARDS.md)
- [Protocol limitations](docs/protocol-limitations.md), [QKD design](QKD_ARCHITECTURE.md)

Licensed under MIT OR Apache-2.0 as declared in the workspace manifest.
