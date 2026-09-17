# Protocol limitations

- Not a VPN: no authenticated IKE, identity management, SK processing, CHILD_SA negotiation, real PQ providers, QKD or daemon.
- Experimental externally provisioned HKDF keys are not an IKE or hybrid protocol; caller authenticates context and ensures freshness. Restoring old provisioning context can repeat GCM keys/nonces.
- ESP primitive only: AES-256-GCM-16, no ESN, NAT-T, selector enforcement, IPv6 gateway, TUN/TAP, fragmentation/reassembly, PMTU, IPComp, AH or ChaCha20-Poly1305.
- IKE parsing is structural, capped and intentionally incomplete. Parsing CERT/AUTH/KE is not cryptographic verification. Message-ID correlation and negotiation semantics are unavailable.
- SA generation replacement is local ownership/lifecycle behavior, not an interoperable peer rekey protocol. Inbound retirement grace is bounded only by original lifetime or explicit retirement.
- SAD tombstones bound lifetime admissions, not just concurrent SAs. Once full, admission fails until a fresh runtime with fresh authenticated context; no automatic unsafe tombstone eviction.
- std is required. Memory locking, swap/core-dump hardening and a split no_std core are not implemented.
- Zeroization does not prove all compiler copies or dependency-internal HKDF/HMAC state are erased. Supply-chain, side-channel and independent security audits remain required.
- Tests and short fuzz/benchmark runs are regression evidence, not proof of protocol security or production performance. No full RFC/ETSI conformance or FIPS validation claim.
