# Key schedules

## Experimental laboratory provisioning

`keying::schedule::derive_traffic_keys` consumes a 32-byte secret. HKDF-SHA-256 uses the fresh 32-byte session identifier as extract salt. Expand info is an unambiguous fixed-width context: ASCII profile label `quantum-tunneler/experimental/esp/aes256gcm/v1`, initiator and responder SPIs in network order, generation as big-endian u64, 32-byte transcript hash, then a fixed direction label. Each direction obtains 36 bytes: 32-byte AES key followed by 4-byte salt.

Both peers must independently have the same externally authenticated context. IKM must be high entropy, never a password. Reusing the same IKM/context produces identical keys; fresh session IDs and monotonically increasing generations are the provisioner's responsibility. No crash recovery or persistent nonce restoration is provided. Tests intentionally derive both peer copies; operational code must not duplicate an outbound SA.

Provenance is created by the schedule and bound into each traffic-key object. SA construction verifies matching SPI/provenance. Metadata contains no key bytes and makes no claim that a KEM or QKD source was used. This construction is neither IKE KEYMAT nor a standardized hybrid combiner.

## Isolated IKE arithmetic

`ike::schedule` keeps IKE derivation separate from experimental HKDF. It implements HMAC-SHA-256 PRF expansion, the initial IKE derivation, a sequential additional-exchange update and CHILD KEYMAT for a fixed AEAD profile. AEAD omits integrity keys; directional IKE encryption material includes salt. Inputs have bounded nonces and nonzero SPIs. Independent HMAC fixtures test partitioning and ordering.

These functions are not connected to negotiation or authorization. They do not authenticate transcripts or validate a peer's shared secret. Future implementation must add exchange-specific validation, RFC 9242 transcript accumulation, identity authentication and lifecycle integration. See [standards inventory](../STANDARDS.md); no arbitrary HKDF replacement of standardized IKE derivation is permitted.
