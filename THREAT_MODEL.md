# Threat model

## Problem and actors

Protect traffic only after authenticated peers agree on keys, algorithms, direction, session and generation. Current code supplies packet primitives for a trusted laboratory provisioner; it does not solve peer authentication. Actors are the future local runtime, remote peer, administrator, key provider/KME and network adversary.

The adversary can intercept, forge, reorder, duplicate, truncate and flood packets; manipulate unauthenticated proposals and key identifiers; trigger outages; attempt downgrade, replay and state desynchronization; and retain ciphertext for future cryptanalysis. A compromised local OS, runtime or provisioner can read or replace keys and is outside the packet primitive's protection. KME compromise invalidates QKD trust even if the optical link is secure. Supply-chain compromise is a separate risk addressed only partly by lockfiles, restricted dependencies and review.

## Trust boundaries

Wire bytes enter bounded parsers. Parsed syntax is not authentication. Externally provisioned IKM and context cross a laboratory-only trusted boundary; a transcript hash does not prove the transcript was authenticated. Traffic keys remain inside owned SAs. CLI sees only metadata. Future KME transport must authenticate the service and bind requests to local/remote SAE identities; TLS termination and plaintext JSON buffers are secret-bearing components.

## Invariants

A key/nonce pair is never reused within an outbound SA. SAs are not Clone or serializable. Rekey never edits a live traffic key. Incoming unverified packets cannot move the replay window or consume authenticated packet budgets. Zero sequence, reserved SPI, missing tags, expired/retired SAs and unsupported operations fail. Different directions, sessions, transcripts, SPIs and generations affect experimental traffic derivation. No fallback creates a zero key, mock KEM, plaintext tunnel or false established state.

## Failure and exposure limits

Bounded message size and payload counts constrain per-message allocation, not aggregate CPU/network denial of service. Runtime rate limits, handshake quotas and cookies remain absent. Metadata may reveal topology/session timing; key IDs and transcripts require access control even though they are not key bytes. Zeroization covers owned buffers, not all compiler copies, registers, allocator snapshots, core dumps, swap or dependency-internal PRF state.

Post-quantum and hybrid security are not current guarantees. Future ML-KEM must be authenticated against active substitution; future QKD cannot repair unauthenticated negotiation. Conventional AES-GCM is computational authenticated encryption, not an information-theoretic one-time pad. Forward secrecy needs ephemeral authenticated exchanges and destruction of ephemeral state, which the laboratory provisioner does not supply.
