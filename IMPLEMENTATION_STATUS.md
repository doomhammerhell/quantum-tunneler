# Implementation status — audit 2026-09-16, CHILD_SA increment 2026-09-19

The requested long-term stack is **not complete**. This delivery implements hardening foundations and removes unsafe success paths. Phase 6.5 is partial; no production or full standards-compliance claim is made.

## Completed

Forensic audit of all baseline code/tests/manifests; replacement of XOR/per-packet KEM/signature ESP with AES-256-GCM; correct protected trailer and AAD; private checked counters; authenticated replay window; directional key ownership; metadata-only provenance; zeroizing secret buffers; hard SA budgets; generation replacement and retirement; bounded IKE structural parsing; invalid crypto mocks and AH removed; unsafe secret CLI persistence removed; honest std requirements; configuration validation; tests, fuzz harnesses, packet benchmarks and revised architecture/roadmap/security documentation.

## Partially Completed

IKE: bounded parsing plus a fixed childless X25519/PSK/AES-GCM handshake, exact transcript authentication, pinned ID_KEY_ID policy, correlated states, cached retransmissions and a bounded single-peer UDP runner. Optional CREATE_CHILD_SA installs one ESP pair with exact IPv4 host authorization. Local SA rekey: immutable generation replacement and drain behavior, without peer negotiation. Telemetry: in-memory ESP counters and safe SA metadata, without daemon export. CLI: config, disconnected capability status, packet benchmark and finite UDP handshake probe. Phase 7 and QKD: architecture/specification research only.

## Not Implemented

Multi-peer IKE daemon, credential storage/provisioning, multiple CHILD_SAs and negotiated rekey, cookies, real ML-KEM/ML-DSA providers, pluggable KeySource implementation, hybrid exchange integration, QkdProvider, emulator, ETSI clients, QKD pool, negotiated crypto-agility policy, QKD-aware rekey, daemon/IPC/TUN/TAP, complete SPD/traffic selectors, ESN, AH, ChaCha20-Poly1305 and no_std core. QKD/KME response fuzzing is deferred because no such parser exists.

QKD was not started because the explicit prerequisite gate remains open: the fixed in-memory handshake has not passed independent IKE interoperability or a network security review.

## Security Risks Remaining

Laboratory provisioning relies on the caller to authenticate peers/context and maintain freshness. Reusing provisioning context after restart repeats keys/nonces. No runtime/persistent anti-rollback design exists. Secret wrappers do not prove erasure of compiler/register copies or dependency-internal PRF state. No rate-limited network control plane, independent IPsec peer interoperability or external audit exists. Short fuzzing does not establish absence of exploitable bugs. See docs/protocol-limitations.md.

## Standards Compliance Status

Only limited packet profiles and a fixed childless IKE handshake are implemented. None of IKEv2, hybrid IKE, full IPsec, ETSI QKD or FIPS module validation is claimed compliant. STANDARDS.md contains checked authoritative versions and classifications. The ML-KEM IKE document was revision 09 in RFC Ed Queue; FN-DSA/FIPS 206 remained in development at verification time.

## Tests Added

Executed test and fuzz results are recorded below after validation. Coverage includes known answers, independent wire oracle, malformed/truncated chains, parser resource limits, tampering, authenticated-invalid-padding handling, replay/reordering, forged-high-sequence rejection, exhaustion, directional/context separation, rekey failure atomicity, old-generation draining, CLI fail-closed behavior and nonserializable/noncloneable secret types.

## Benchmarks Added

Criterion ESP seal, open and seal+open at 64/512/1400/9000 bytes, plus a CLI laboratory round-trip benchmark. Measurements exclude real handshake, network I/O and physical QKD. PQ operations, IKE/hybrid handshake, peer rekey, 100 concurrent tunnels and KME performance are unavailable rather than fabricated.

## Breaking API Changes

Removed Kyber512/Dilithium3 mock exports and false Falcon aliases. Removed simulated Initiator/Responder/CryptoAdapter/SAManager and fabricated established sessions. Removed signature AH. SecurityAssociation is now directional, private-key-owning, neither Clone nor serde; no default zero-key constructor or mutable public counter/key fields. ESP APIs take `&mut SecurityAssociation`, emit/consume wire bytes and return typed errors; caller supplies real next-header. SAs cannot be loaded from CLI files. Binary explicitly named `quantum-ipsec`. Removed std/no_std feature switches: std is required. Configuration rejects invalid values. Legacy code paths contain migration notices, not callable insecure compatibility implementations.

## Next Highest-Risk Work

Independently validate the authenticated childless IKE profile; implement multi-peer admission control, persistent packet routing and peer rekey. Then integrate vetted standardized KE/signature providers and hybrid intermediate authentication. QKD remains gated behind that work.

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

## Small increment — 2026-09-18

Added isolated RFC 7296 PSK AUTH computation and constant-time verification for PRF_HMAC_SHA2_256, with role-specific keys and exact wire transcript binding. Four focused tests cover independently calculated HMAC vectors for both roles, transcript/nonce/identity/key/tag mutations, invalid inputs and continued fail-closed negotiation. This closes only the arithmetic portion of transcript AUTH; authenticated IKE, identity authorization, encrypted exchanges and intermediate transcript accumulation remain unimplemented.

Validation for this increment: `cargo test --workspace --locked` passed all 46 tests; `cargo clippy --workspace --all-targets --locked -- -D warnings`, formatting and diff whitespace checks passed. No new dependencies. Previous release/fuzz evidence above remains historical and was not rerun for this increment.

## Authenticated childless IKE integration — 2026-09-18

The opt-in `IkeProcessor::with_psk` / `PskSession` path now performs fresh X25519 IKE_SA_INIT and encrypted, mutually authenticated PSK IKE_AUTH with pinned ID_KEY_ID identities. Algorithm selection is deliberately restricted to one profile. The responder advertises experimental RFC 6023 support; the initiator requires that capability. State advances only after expected role/SPIs/message ID, GCM, transcript AUTH and identity authorization pass. Exact accepted-message retransmissions return cached ciphertext. Closing or expiring a session drops credentials and keys, and cannot restart it.

Validation: **55 tests passed in debug and release**, including independent Python X25519/HMAC/AES-GCM wire fixtures; Clippy with warnings denied passed. Root and fuzz dependency audits reported no vulnerabilities. Root and fuzz lockfiles include the pinned X25519 dependency graph. No new fuzz campaign or independent IKE-daemon interoperability run is claimed.

This enables the configured library handshake only. The CLI has no network transport or credential store; CHILD_SA negotiation, ESP installation, INFORMATIONAL/rekey, cookies, network admission control and automatic retransmission scheduling remain outside this increment. Default unconfigured and legacy processor entry points remain fail-closed.

## Bounded UDP handshake — 2026-09-19

Added `ike::udp::handshake`: one configured remote endpoint, a consumed bound socket, capped datagram size/count, monotonic deadlines and exponentially backed-off initiator retries. The responder retains cached replies for one timeout interval after authentication so the last AUTH response can be retransmitted. Duplicates and malformed/foreign packets never extend deadlines. Success returns the authenticated session/socket to library callers; failures drop them. NAT-T/UDP 4500 remains explicitly unsupported.

The `ike-handshake` CLI runs this exchange as a finite probe, accepting a hex PSK only on stdin in fixed zeroizing storage. It reports public SPIs and counters and closes the session before exit; it does not claim a tunnel or retain a daemon. Usage is documented in docs/ikev2.md. No new dependency versions were introduced; the CLI now directly uses the already locked zeroize crate.

Validation: **63 tests passed in debug and release**, including two separate CLI processes behind a loss-injecting UDP relay. Coverage includes loss of the first request and final AUTH response, exact retransmission bytes, foreign-source rejection, wrong-PSK/absent-peer timeout, deadlines under continuous malformed traffic, datagram limits and bounded credential decoding. Clippy with warnings denied, formatting and diff whitespace checks passed. Independent IKE-daemon interoperability and new fuzz campaigns remain pending. CHILD_SA/ESP negotiation and tunnel routing are not part of this increment.

## Authenticated CHILD_SA and ESP integration — 2026-09-19

Added one optional CREATE_CHILD_SA exchange after IKE AUTH, at message ID 2, with fresh nonces, an AES-256-GCM-16/non-ESN ESP proposal and exact IPv4 host selectors. Keys use RFC 7296 PRF+ KEYMAT from SK_d and child nonces; metadata distinguishes this derivation from experimental HKDF provisioning. Both directional SAs are constructed privately and installed together inside the authenticated session. Closing/expiring that session disables the pair. IKE encryption now separates AUTH IV zero from reserved CHILD IVs and preserves exact cached retransmissions.

The session packet APIs enforce outbound/inbound host policy; inbound policy is checked after GCM but before replay/counter commit. Duplicate CHILD messages cannot reinstall keys or reset counters. The UDP runner can require CHILD completion, and the CLI exposes paired `--local-inner-ip` / `--peer-inner-ip` options with complementary ESP SPI reports.

Validation: **72 tests passed in debug and release**; Clippy with warnings denied, formatting and diff whitespace checks passed. New evidence includes independent Python CREATE_CHILD_SA/ESP wire fixtures, bidirectional negotiated-key packet protection, tampering and authenticated-invalid-selector rejection, replay/counter preservation, and two CLI processes recovering a lost final CHILD response. No new dependencies. Existing initial AUTH vectors remain unchanged after SK framing reuse.

The profile supports one tunnel-mode host pair, all upper-layer protocols/ports, no additional child DH, no narrowing/rekey/multiple children. SAs remain private to the in-memory session, not the kernel or global SAD. CLI operation is still a finite probe: no ESP network forwarding, persistent tunnel, TUN or routing is claimed. Independent IKE-daemon interoperability and sustained fuzzing of the new state transitions remain pending.
