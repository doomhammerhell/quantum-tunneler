# Hardening report — 2026-09-16

## Scope and disposition

This change is a controlled replacement of unsafe foundations, not completion of the requested quantum-safe networking stack. Phase 6.5 remains partial because authenticating IKE and an independent interoperable peer are still absent. QKD implementation was not started, respecting the explicit prerequisite gate.

All source files, manifests, tests and baseline documentation were inspected before editing. The implementation map and findings were recorded in SECURITY_AUDIT.md first. No Git commit, publication or deployment was performed. Modules were changed in dependency order and regression tests added before final validation.

| Audit findings | Correction | Remaining work |
|---|---|---|
| A01–A03 | Removed fabricated Kyber/Dilithium, false Falcon alias and uncompiled SPHINCS wrapper; removed enc_rust | Select, audit and integrate actual standardized providers; no ML-KEM/ML-DSA claim |
| A04–A05 | Replaced both ESP implementations with a single AES-GCM wire primitive; mandatory 128-bit tag; encrypted trailer | Independent IPsec peer interoperability and full gateway integration |
| A06–A07 | Owned zeroizing key/salt wrappers, no secret serde/Clone; experimental directional/context-bound HKDF; separate IKE PRF arithmetic | Authenticated establishment; audit dependency-internal transient secret state |
| A08 | Private checked counter and authenticated 64-packet sliding replay window; no counter reset API | ESN and durable runtime restart policy |
| A09–A10 | Removed successful fake AUTH/zero-key establishment; IKE operations fail closed and cannot report Established | Real AUTH, credentials, SK encryption, transcript verification and CHILD_SA |
| A11–A13 | Unified bounded header/payload/proposal parser, packed version/correct codes, SPI/initial ID checks, duplicate/critical/length validation | Stateful message-ID/SPI correlation, complete payload semantics, negotiation and retransmission |
| A14 | Removed implicit SA creation, arbitrary endpoint lookup and plaintext pass-through; explicit SPI dispatch | Authenticated selector-to-SA binding and network policy enforcement |
| A15–A16 | Removed unsafe AH and underflowing packet decoders; bounded ESP parser and explicit unsupported AH | AH deliberately unsupported |
| A17 | Replaced IPv4 helper with strict size/checksum/header validation and explicit rejection of options, fragments and IPv6 | Full outer-IP stack and reassembly |
| A18 | Deterministic BTreeMap policy tie-break (lowest ID), priority-zero match, exact-address semantics, duplicate rejection, propagated errors | CIDR/selectors and actual runtime integration |
| A19 | Monotonic lifetime, packet/byte budgets, immutable per-generation keys, bounded SAD and SPI tombstones | Peer rekey, collisions, timeout recovery, grace timers and crash consistency |
| A20 | Removed fake no_std feature and unsupported pass-through | Real core/platform split planned; entire library currently requires std |
| A21 | Fixed-size AEAD key/nonce API, fallible RNG, UTF-8-safe hex parsing, no wall-clock unwrap | Broader adversarial integration validation |
| A22 | Removed secret key files and serialized SA import/export; unavailable commands fail explicitly | Daemon IPC/credential provisioning |
| A23 | Capability status explicitly disconnected; benchmark actual ESP operations only | Real runtime monitoring and control-plane measurements |
| A24 | Replaced invalid/ignored smoke tests, added properties/vectors/fuzzing; track lockfiles; corrected roadmap/claims | Long fuzz campaigns and complete interoperability suite |
| A25 | Secret Debug redaction, zeroize on drop/retire, zeroizing temporary buffers; deleted secret-Debug trait requirements and naive AUTH comparison | Compiler copies, registers, HMAC/HKDF internals, swap/dump hardening remain outside guarantee |
| A26 | Reject invalid/unknown configuration values instead of substituting defaults | Full security policy configuration awaits protocol implementation |

## Design decisions

Each IPsec SA is directional. Traffic keys carry derivation-bound SPI and provenance; SA construction rejects inconsistent metadata. A new generation is admitted before old outbound traffic stops. Failed candidate admission leaves the old SA intact until its existing hard limits. Old inbound replay state remains intact during draining.

Packet sealing reserves sequence before AEAD. Packet opening authenticates and validates padding before replay commit and usage accounting under exclusive mutable ownership. Missing tags and invalid sizes cannot reach decryption. Counter exhaustion and lifetime exhaustion never silently wrap or extend.

The experimental HKDF context includes suite/profile, directional labels, both SPIs, a fresh session identifier, generation and transcript hash. IKE arithmetic is separate and never routes through this experimental KDF. No standardized hybrid combiner or authenticated IKE implementation is claimed.

## Validation

See IMPLEMENTATION_STATUS.md and docs/benchmark-results.md for executed commands, counts, fuzz toolchain details and measured results. Test fixtures include a NIST AES-256-GCM known answer, RFC 5869 HKDF case, independent Python HMAC schedule values and independent Python cryptography ESP wire output. These supplement regression/property tests; they do not constitute an interoperability certification.

## Final lifecycle review

A post-implementation review found and corrected R01: rekeying an already retired SA could reactivate erased inbound traffic material. Source state must now be active and unexpired, retirement is monotonic, and regression coverage prevents reintroduction. Outbound retiring keys are immediately erased; soft lifetime calculation uses integer Duration arithmetic.

## Release gate

Do not deploy as a tunnel. The next highest-risk work is a small real authenticated IKE profile with independently verified AUTH/transcript and CHILD_SA semantics. Complete that gate before adding PQ/hybrid exchange providers and QKD infrastructure.
