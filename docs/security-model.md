# Security model

The only current key-establishment boundary is a trusted laboratory provisioner. It supplies high-entropy IKM and authenticates both peer identities and the entire derivation context externally. The library cannot verify that assertion. An arbitrary transcript hash is not evidence of authentication.

ESP gives packet confidentiality and integrity under provisioned AES-256-GCM keys, with replay rejection and explicit budgets. Control-plane authentication, PFS, quantum-resistant establishment and downgrade-resistant negotiation are unavailable. The public API deliberately cannot report successful IKE establishment.

Secret owners have no serde or Clone implementations. Debug is redacted or metadata-only. Drop erases owned key/salt arrays; temporary plaintext, decrypted failures and derived material use zeroizing buffers. Retirement clears traffic material. See [threat model](../THREAT_MODEL.md) for memory-copy and dependency-internal limitations.

Acceptance for future secure tunnel operation requires authenticated IKE integration, traffic-selector policy enforcement, independent interoperability, restart rules, deployment rate limits and cryptographic dependency review. No deployment-level security claim is made now.
