# ESP packet primitive

Supported subset: unicast SPI >= 256, 32-bit sequence without ESN, AES-256-GCM, full 16-byte tag. Wire layout is `SPI(4) | sequence(4) | explicit IV(8) | encrypted body | tag(16)`. The encrypted body is `payload | 1..N padding | pad length | next header`, aligned to four bytes. SPI and sequence are AAD. Nonce is the per-key four-byte salt followed by the explicit IV.

Outbound IV is a zero-extended big-endian sequence. Sequence begins at one, is private, and is reserved before encryption. Counter exhaustion fails; soft thresholds request rekey. A restart never restores an SA or resets a counter with retained keys. Inbound accepts authenticated peer IVs rather than imposing our counter encoding on other implementations.

Replay uses a 64-bit bitmap. Precheck rejects zero, old and duplicate sequences without mutation. AEAD and padding validation precede window commit and accounting, all under exclusive mutable access. This also prevents an unauthenticated high sequence from evicting legitimate packets.

Hard budgets count successful packets and protected plaintext bytes including padding/trailer. Failed inbound authentication does not consume these budgets; it increments processor failure telemetry. Retiring outbound SAs cannot seal; inbound can drain until explicit retirement or hard expiry. No data-path KEM, signature or identity creation remains.

Inputs are capped at 65,535 packet bytes; allocation is bounded. Caller supplies actual next-header value; tunnel versus transport is not represented by a fake TCP protocol constant. The API returns decoded next-header and payload separately. Full IP routing, NAT-T, ESN, PMTU, IPsec selector enforcement and fragmentation are absent. Wire-profile support is not full IPsec compliance.
