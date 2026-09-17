# Architecture

## Current executable boundary

The library requires std and forbids local unsafe code. `crypto/secret.rs` owns secret buffers; `crypto/symmetric.rs` wraps AES-256-GCM; `keying/schedule.rs` derives directional laboratory traffic keys. `ipsec/sa.rs` owns each unidirectional SA, its key/salt, counter, monotonic lifetime, usage budget, provenance and replay state. `ipsec/esp.rs` only seals/opens packets using those keys. No packet operation invokes public-key cryptography or creates an identity.

An SA is unidirectional, as required by the IPsec architecture. Two traffic directions use different keys and receiver-selected SPIs. The example target containing inbound/outbound keys in one SA is therefore represented by two owned SAs. `TrafficKeys` is a transient derivation result, not the SAD entry. The context's initiator SPI receives responder-to-initiator traffic; the responder SPI receives initiator-to-responder traffic.

`IpSecProcessor` dispatches by explicit SPI, counts nonsecret outcomes, and never creates SAs implicitly. It is a packet laboratory interface, not a policy-enforcing network gateway. The exact-address SPD remains a separate deterministic utility; routing and authenticated selector enforcement are unavailable. No unprotected fallback is performed by the top-level processor.

`ike/parser.rs` borrows bounded wire slices. `ike/proposal.rs` validates nested lengths and chains without assigning invented algorithm IDs. `ike/schedule.rs` provides isolated PRF arithmetic. `IkeProcessor` cannot enter an authenticated or established state: negotiation fails explicitly. Former initiator/responder, mock crypto adapter, packet-signing AH and duplicate SA implementations are removed, with small migration notices at their old paths.

The CLI writes nonsecret config, reports capabilities and runs real ESP microbenchmarks. It neither loads traffic keys from files nor pretends to control a daemon. This prevents restarting the CLI from resetting a live GCM nonce counter.

## Ownership and failure containment

All packet mutation takes exclusive `&mut SecurityAssociation`. Nonce reservation happens before seal. Inbound replay precheck does not mutate state; authentication, padding validation and replay commit occur within the same exclusive borrow. Key objects have no Clone or serde implementation. Public metadata is separate and safe to serialize. Keys are bound to their derivation SPI and provenance before admission.

The SAD uses bounded lifetime admissions and SPI tombstones to reject reinstallation. A replacement generation is validated and admitted before the old generation retires. Outbound retiring SAs stop immediately; inbound retiring SAs may drain until explicit retirement or their original hard lifetime. This is local lifecycle support, not peer-negotiated rekey.

## Planned control plane

```text
X25519 → initial IKE keys
           ↓ encrypted IKE_INTERMEDIATE / ML-KEM-768
         sequential RFC 9370 schedule update
           ↓ identity authentication + transcript verification
         IKE SA → CHILD_SA KEYMAT → directional ESP SAs
```

A future `KeySource` interface should return typed, owned, zeroizing contributions tied to exchange context. It must not collapse different KE protocols into an unauthenticated `Vec<u8>` concatenation. A PSK provider is an authentication/key-source policy choice, not an automatic substitute for failed PQC. The experimental HKDF provisioning module must never replace the standardized IKE schedule.

Optional QKD adds a separate provider/KME trust boundary. It is not wired into core IKE or ESP. See [QKD design](QKD_ARCHITECTURE.md) for reservation, consumption and outage semantics. The long-term daemon owns counters, SAs, IKE retransmissions, QKD pools and an authenticated Unix-socket control API. CLI output contains metadata only.

## Operational limits

No crash-safe key/counter restoration, traffic selectors, network I/O, fragmentation/reassembly, NAT traversal or real peer authentication exists. Every process restart needs fresh authenticated key establishment before traffic is allowed. Interoperability with an independent IPsec implementation and dependency-side secret-lifetime review remain required.
