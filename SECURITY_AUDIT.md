# Forensic audit — 2026-09-16

## Implementation map (recorded before implementation changes)

Reviewed every tracked source, manifest, test and document at baseline. No standalone benchmarks, fuzzing or CI exist. Workspace has a std library and a Tokio/Clap CLI. `crypto/mod.rs` exports mock Kyber512 and Dilithium3; the enc_rust dependency is not used by these exports. Uncompiled `falcon.rs` aliases Dilithium as Falcon, and uncompiled `sphincs.rs` references an absent dependency. Existing AES-GCM helpers are real primitives but do not validate key/nonce lengths.

There are three competing IKE models: `mod.rs` simulation, `exchange.rs` handler, and initiator/responder. None implements authenticated IKE. Two header encoders disagree, and the parser consumes an unrelated format. IKE SA manager and IPsec SAD duplicate lifecycle responsibilities without integration. ESP has a processor and convenience functions with different sequence handling. AH duplicates packet-signing misuse. Policy matching and IP utilities have limited functional pieces. CLI commands create fresh local state rather than managing a tunnel.

## Findings

| ID | Severity | Baseline location | Evidence / consequence |
|---|---|---|---|
| A01 | Critical | crypto/kyber.rs | Deterministic arithmetic mock; encapsulation/decapsulation disagree; debug arithmetic overflow. No KEM security. |
| A02 | Critical | crypto/dilithium.rs | Deterministic mock signatures; mismatched public/private arithmetic; empty message modulo zero; overflow. |
| A03 | High | crypto/falcon.rs, sphincs.rs | Uncompiled misleading algorithm wrappers; Falcon is a Dilithium alias; absent SPHINCS dependency. |
| A04 | Critical | ipsec/esp.rs | Repeated XOR mask from per-packet mock encapsulation; no AEAD; decryption encapsulates again. |
| A05 | Critical | ipsec/esp.rs | Optional authentication permits missing tags; per-packet signatures; regenerated identities; cleartext trailer and wrong padding order. |
| A06 | Critical | ipsec/sa.rs | Public, Clone, Debug, serde secret fields; zero/default secrets; raw signing keys in traffic SA; no zeroization. |
| A07 | Critical | ipsec/sa.rs, esp.rs | Ad hoc SHA256 KDF; random unmatched nonces; no directional or transcript separation. |
| A08 | Critical | ipsec/esp.rs, ah.rs | Counter wrap or reset; no replay window; convenience encrypt uses unadvanced sequence. |
| A09 | Critical | ike/responder.rs, exchange.rs | AUTH always succeeds or missing AUTH skips verification; no identity/transcript binding. |
| A10 | Critical | ike/initiator.rs, mod.rs | Literal auth_data, empty/zero session keys, fresh participants during AUTH; false establishment. |
| A11 | High | ike/exchange.rs, mod.rs, parser.rs | 29-byte encoding vs 28-byte header; split version byte; AUTH=39 instead of 35; response confused with exchange type; Nonce Nr=41 and SK=47 wrong. 28-byte input panics. Length/chains ignored. |
| A12 | High | ike/proposal.rs | Invented transform assignments: KEM as encryption, signature as integrity, incorrect key-length attribute. No parser/negotiation. |
| A13 | High | ike/* | Wrong message ID progression, absent SPI correlation, transcript, retries, bounded state and encrypted payload validation. |
| A14 | High | ipsec/mod.rs | Ignored selected SA; autogenerates unrelated SPI; first arbitrary SA selected regardless of endpoints; plaintext inbound bypasses policy. |
| A15 | High | ipsec/mod.rs, ah.rs | Length subtraction underflows and unchecked slices; fixed 20-byte IPv4 offset and fictitious 1024-byte authentication field. |
| A16 | High | ipsec/ah.rs | Nonstandard public-key AH, no replay protection, signed length changes after signing, invalid wire order/ICV lengths. |
| A17 | High | ipsec/utils.rs | No IPv4 IHL/total length/checksum/fragment validation; incorrect checksum construction; IPv6 unsupported. |
| A18 | Medium | ipsec/policy.rs | Exact addresses mislabeled ranges; tests assume nonexistent CIDR semantics; nondeterministic equal-priority HashMap selection; priority zero never matches; duplicate IDs overwrite; errors discarded. |
| A19 | High | ike/sa_manager.rs, ipsec/sa.rs | In-place cloned key replacement; duplicate SPI overwrite; unbounded IKE maps; unchecked IDs; wall-clock lifetime; no generation/rekey protocol. |
| A20 | High | lib.rs, manifests | Fake no_std feature over std networking, collections and time; top-level processing returns plaintext unchanged. |
| A21 | High | crypto/mod.rs, utils.rs | AEAD slice constructors panic on bad lengths; UTF-8 hex slicing panics; RNG/time expect/unwrap. |
| A22 | High | cli/init, connect, encrypt, decrypt, utils | Raw key file; serialized SAs and debug session keys; bincode instead of ESP wire; no persistent counter ownership; fabricated connection success. |
| A23 | Medium | cli/status, monitor, benchmark | Fresh zero state reported as runtime state; mock handshake metrics; no meaningful throughput results. |
| A24 | Medium | tests, manifests, docs | Baseline tests do not compile (missing IKESession/Role, wrong message fields and optional assert_cmd); ignored command failures; potential hanging TUI test. No official vectors despite claims. Cargo.lock ignored. |
| A25 | High | all secret owners / crypto traits | Debug required for private material, unnecessary clones, long-lived raw Vec secrets, no zeroization; authentication compared with ordinary equality. |
| A26 | Medium | cli/config | Invalid values silently replaced with defaults and unknown setters succeed. |

Functional baseline pieces: checksum helper in top-level utils, hash functions, underlying AES-GCM primitive for correctly sized inputs, basic config parsing, exact address policy predicates, counter overflow check in one unused implementation. These do not constitute a working VPN.

Threat boundary: remote packets, local configuration, key provider outputs and peer identities are untrusted until validated. The current implementation must not be deployed. Baseline `cargo test --workspace` fails compilation; passing historical assertions would not establish cryptographic correctness.

Correction disposition and remaining gates are tracked in HARDENING_REPORT.md. This is a source review, not an independent security audit or certification.

## Review of the replacement — 2026-09-17

R01 (high, corrected before delivery): after explicit retirement zeroized traffic keys, local generation replacement could move the old inbound SA back to Retiring. That would make erased key material eligible for packet opening. Replacement now requires an active, unexpired source; retirement transitions are monotonic. A regression asserts rejected replacement, retained Retired state, and no candidate admission. Outbound retirement also erases its now-unusable key/salt. Active-count metadata excludes retiring SAs.
