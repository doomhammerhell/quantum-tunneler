# QKD architecture — planned, not implemented

QKD implementation is gated on authenticated IKE, validated ESP/lifecycle and control-plane interoperability. No QKD provider, emulator, key pool, HTTP client or QKD fuzz target currently exists. The project consumes key infrastructure; it does not implement an optical protocol or claim simulated QKD security.

## Boundary and interface

Core IKE should consume protocol-specific, typed key contributions without importing HTTP, vendor SDKs or KME details. A future generic `KeySource` distinguishes Classical, PostQuantum, Qkd, PreShared and Composite sources. Its context includes authenticated peer identity, session, negotiated suite, transcript stage and generation. Obtaining bytes alone must not advance IKE state.

A vendor-neutral `QkdProvider` exposes status, request-new-key(peer,bits), and request-by-id(peer,key-id). Including the peer in by-ID retrieval is intentional: possession of an opaque ID is not authorization. Key objects own zeroizing buffers; IDs, origin, age and generation are separate nonsecret metadata. Provider outputs must match requested bit length, peer, algorithm policy and freshness. Deterministic errors distinguish unreachable service, exhaustion, invalid response, authentication failure and compromise.

ETSI GS QKD 014 defines application key delivery. ETSI GS QKD 020 V1.1.1 defines interoperable KMS operations, including external key transfer, acknowledgment and voiding. They must be separate adapters, not two names for one REST client. See [standards inventory](STANDARDS.md) for authoritative sources and versions.

## Key pool and transaction model

The planned pool tracks available, reserved, consumed and voided bits with checked arithmetic and bounded capacity. States are Healthy, Low, Starved, Unavailable and Compromised; watermarks must satisfy low < high <= capacity. Only physically supplied/provider-authenticated stock counts as available. No refill is inferred from elapsed time without provider confirmation.

A rekey transaction reserves a key ID and proposed generation, communicates the ID inside an authenticated exchange, retrieves matching peer material, derives candidate keys, and installs the new generation only after key confirmation. Consume once on commit. After an ambiguous timeout or partial disclosure, void/burn the reservation instead of returning it to the pool. No key ID can be used for unrelated peers or reused after restart. Peer synchronization and crash recovery require a durable metadata journal that never stores raw QKD keys.

## Policy and outages

QkdRequired fails establishment/rekey when QKD is missing; existing SAs survive only within their original policy/lifetime. QkdPreferred may negotiate PQ fallback only if explicitly configured, authenticated and auditable. Compromised is not equivalent to a temporary outage: quarantine the provider and follow incident policy. PQ failure never automatically enables classical-only operation. Policy changes create new generations and never mutate an active SA's declared provenance.

Rate-limit retries and cap response bodies, key counts, decoded lengths and outstanding reservations. Isolate HTTP/TLS buffers, redact errors, authenticate KME identity and SAE authorization, avoid response-body logging and destroy key buffers after schedule use. The experimental composition profile must have a separate identifier and formal review; do not market it as RFC 9370 QKD support.

## Emulator acceptance criteria

A future two-endpoint emulator uses the same provider interface, shared laboratory key inventory and separate per-endpoint consumption ledgers. It supports synchronized key IDs, bounded pools, exhaustion, delay, disconnect, mismatch, corruption and compromise injection. A seeded deterministic mode is test-only and prominently labeled. It provides no optical-channel or information-theoretic guarantee. Retrieval latency and pool/rekey benchmarks must be labeled simulated and kept separate from hardware measurements.
