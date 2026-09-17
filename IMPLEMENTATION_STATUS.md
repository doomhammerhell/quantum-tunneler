# Implementation status — audit 2026-09-16, validation 2026-09-17

The requested long-term stack is **not complete**. This delivery implements hardening foundations and removes unsafe success paths. Phase 6.5 is partial; no production or full standards-compliance claim is made.

## Completed

Forensic audit of all baseline code/tests/manifests; replacement of XOR/per-packet KEM/signature ESP with AES-256-GCM; correct protected trailer and AAD; private checked counters; authenticated replay window; directional key ownership; metadata-only provenance; zeroizing secret buffers; hard SA budgets; generation replacement and retirement; bounded IKE structural parsing; invalid crypto mocks and AH removed; unsafe secret CLI persistence removed; honest std requirements; configuration validation; tests, fuzz harnesses, packet benchmarks and revised architecture/roadmap/security documentation.

## Partially Completed

IKE: structural header/payload/proposal parsing and isolated PRF arithmetic only. Local SA rekey: immutable generation replacement and drain behavior, without peer negotiation. Telemetry: in-memory ESP counters and safe SA metadata, without daemon export. CLI: config, disconnected capability status and packet benchmark. Phase 7 and QKD: architecture/specification research only.

## Not Implemented

Authenticated IKE initiator/responder, identity provisioning, SK encryption, transcript AUTH, actual CHILD_SA negotiation, IKE retransmission/cookies, real X25519/ML-KEM/ML-DSA providers, pluggable KeySource implementation, hybrid exchange integration, QkdProvider, emulator, ETSI clients, QKD pool, negotiated crypto-agility policy, QKD-aware rekey, daemon/IPC/TUN/TAP, complete SPD/traffic selectors, ESN, AH, ChaCha20-Poly1305 and no_std core. QKD/KME response fuzzing is deferred because no such parser exists.

QKD was not started because the explicit prerequisite gate remains open: fail-closed IKE containment is not corrected and validated authenticated negotiation.

## Security Risks Remaining

Laboratory provisioning relies on the caller to authenticate peers/context and maintain freshness. Reusing provisioning context after restart repeats keys/nonces. No runtime/persistent anti-rollback design exists. Secret wrappers do not prove erasure of compiler/register copies or dependency-internal PRF state. No rate-limited network control plane, independent IPsec peer interoperability or external audit exists. Short fuzzing does not establish absence of exploitable bugs. See docs/protocol-limitations.md.

## Standards Compliance Status

Only limited packet-profile behavior and isolated arithmetic are implemented. None of IKEv2, hybrid IKE, full IPsec, ETSI QKD or FIPS module validation is claimed compliant. STANDARDS.md contains checked authoritative versions and classifications. The ML-KEM IKE document was revision 09 in RFC Ed Queue; FN-DSA/FIPS 206 remained in development at verification time.

## Tests Added

Executed test and fuzz results are recorded below after validation. Coverage includes known answers, independent wire oracle, malformed/truncated chains, parser resource limits, tampering, authenticated-invalid-padding handling, replay/reordering, forged-high-sequence rejection, exhaustion, directional/context separation, rekey failure atomicity, old-generation draining, CLI fail-closed behavior and nonserializable/noncloneable secret types.

## Benchmarks Added

Criterion ESP seal, open and seal+open at 64/512/1400/9000 bytes, plus a CLI laboratory round-trip benchmark. Measurements exclude real handshake, network I/O and physical QKD. PQ operations, IKE/hybrid handshake, peer rekey, 100 concurrent tunnels and KME performance are unavailable rather than fabricated.

## Breaking API Changes

Removed Kyber512/Dilithium3 mock exports and false Falcon aliases. Removed simulated Initiator/Responder/CryptoAdapter/SAManager and fabricated established sessions. Removed signature AH. SecurityAssociation is now directional, private-key-owning, neither Clone nor serde; no default zero-key constructor or mutable public counter/key fields. ESP APIs take `&mut SecurityAssociation`, emit/consume wire bytes and return typed errors; caller supplies real next-header. SAs cannot be loaded from CLI files. Binary explicitly named `quantum-ipsec`. Removed std/no_std feature switches: std is required. Configuration rejects invalid values. Legacy code paths contain migration notices, not callable insecure compatibility implementations.

## Next Highest-Risk Work

Implement and independently validate an authenticated IKE profile, including identities, exact transcript construction, encrypted payload integrity, request/response correlation, CHILD_SA authorization and peer rekey. Then integrate vetted standardized KE/signature providers and hybrid intermediate authentication. QKD remains gated behind that work.

## Executed verification

- `cargo test --workspace --locked`: **42 passed**, zero failures/ignored.
- `cargo test --workspace --release --locked`: **42 passed**, zero failures/ignored.
- `cargo clippy --workspace --all-targets --locked -- -D warnings`: passed.
- `cargo fmt --all -- --check` and `git diff --check`: passed.
- `cargo audit` on root and fuzz lockfiles: zero advisories and zero warnings; RustSec database commit `f58ccfe51a5954186716998f01360d1079a8a3a5`, updated 2026-09-17.
- Independent Python cryptography 45.0.5 fixture generation and exact ESP-wire comparison: passed.
- Criterion benchmark completed for all 12 seal/open/round-trip size combinations; results and environment are in docs/benchmark-results.md.
- Five libFuzzer targets compile. Native ARM64 unsanitized smoke execution results are recorded below. ASan execution is **not validated**: x86_64 executables raised SIGILL; ARM64 ASan initialization did not reach the fuzz loop and was stopped by the watchdog. No finding-free ASan campaign is claimed.

Host caveat: x86_64 Rust on ARM64 macOS required session-only native compiler/linker/archive and SDK overrides after an Apple tools architecture mismatch. Debug/release checks succeeded with those overrides. The standard library target for ARM64 was added to the installed dated nightly; no global defaults were changed.

Native ARM64 libFuzzer smoke results, without sanitizers (10-second requested budget, 11 seconds reported per target):

| Target | Executions | Seconds | Result |
|---|---:|---:|---|
| ike_header | 11,320,169 | 11 | Passed |
| ike_payload | 10,890,774 | 11 | Passed |
| esp_packet | 12,186,734 | 11 | Passed |
| sa_proposal | 11,851,000 | 11 | Passed |
| ip_packet | 12,890,417 | 11 | Passed |

Total: **59,139,094 executions**, no target failures. This is coverage-guided smoke fuzzing with seeded corpora, not exhaustive verification or ASan coverage. Reproduce with `scripts/fuzz_smoke.py`; local logs are under `target/fuzz-smoke/`. Release validation still requires sustained sanitized campaigns in a working environment.

