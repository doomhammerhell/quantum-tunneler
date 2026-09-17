# Crypto-agility design — planned

Only AES-256-GCM is currently supported by ESP; unsupported negotiation fails instead of substituting algorithms. No configurable hybrid/QKD policy engine is implemented. The experimental key schedule has its own explicit derivation identifier.

Future negotiation evaluates local minimum requirements against authenticated peer capabilities. Classical, PostQuantum, Hybrid and HybridQkd are policy profiles, not trust inferred from peer strings. PqcRequired, QkdRequired and HybridRequired must fail when a required contribution is absent or invalid. QkdPreferred with explicit fallback-pqc may downgrade only through authenticated agreement and a recorded reason. Classical fallback is a separate opt-in and must never follow from a cryptographic error by default.

Each decision records selected algorithms, contribution kinds, profile, generation and downgrade reason without secrets. ML-KEM errors, AUTH failures and transcript mismatch terminate the candidate exchange. Temporary QKD outage or empty pools defer or terminate rekey according to policy; they never extend the old SA's hard expiry. Compromise triggers quarantine, not ordinary availability fallback.

Policy changes and QKD arrivals can schedule a new generation with minimum interval/hysteresis to avoid rekey storms. No policy change edits traffic keys or provenance in place. Cipher suite and source identifiers must be canonical, with exact derivation rules and bounded negotiation state.
