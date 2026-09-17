# IKEv2 foundation

The parser uses the 28-byte header, packed version, correct exchange codes, generic payload chains and a single Nonce type. The response bit is distinct from the exchange type. Initial exchange ID/SPI/role constraints are checked; subsequent IDs require session correlation, which is not implemented. Reserved bits are ignored on receive. Unsupported exchanges and encrypted fragmentation fail explicitly.

Messages are capped at 65,535 bytes and 64 payloads. Certificates and AUTH bodies are capped at 16 KiB, KE at 16 KiB, vendor bodies at 1 KiB, proposals at 16, transforms at 32 per proposal and attributes at 32 per transform. Known singleton duplicates fail. Unknown critical payloads fail; unknown noncritical payloads remain bounded opaque data. SK is terminal in the outer chain, with its inner type preserved but ciphertext never parsed as plaintext.

Proposal syntax validates nesting, lengths, SPI sizes, numbering and transform chains. It is not negotiation; a well-formed numeric transform ID is not evidence of support. Certificate, AUTH, EAP and configuration bodies still need semantic/profile verification. Traffic-selector basic ranges are validated but not authorized against policy.

All operational negotiation fails: no message can transition the processor to authenticated or established. Removed mock AUTH behavior is not replaced by an unauthenticated test handshake. A future implementation needs pinned identity/PSK policy, real KE providers, encrypted SK, exact transcript authentication, request/response correlation, cached retransmissions, timer and resource bounds, and CHILD_SA authorization.

Hybrid architecture follows initial classical KE, encrypted intermediate additional KE, then AUTH with intermediate transcript binding. ML-KEM public key and ciphertext must be role-specific protocol messages, not independently generated per packet. The current draft revision is recorded in [STANDARDS.md](../STANDARDS.md) and must be rechecked before implementation.
