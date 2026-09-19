# Standards inventory

Verified against authoritative publication pages on 2026-09-16. “Arithmetic implemented” and “packet profile implemented” do not imply full protocol conformance, cryptographic module validation, or interoperability certification.

| Document | Verified status | Repository status |
|---|---|---|
| [RFC 7296 / STD 79](https://www.rfc-editor.org/info/rfc7296/) | Internet Standard, with subsequent updates | Fixed PSK handshake plus one CREATE_CHILD_SA with fresh nonces, exact IPv4 selectors and RFC KEYMAT; full conformance not claimed |
| [RFC 5282](https://www.rfc-editor.org/rfc/rfc5282.html) | Standards Track; checked 2026-09-18 | AES-256-GCM IKE encrypted payload, full header AAD, 4-byte salt and 8-byte IV |
| [RFC 8031](https://www.rfc-editor.org/rfc/rfc8031.html) | Standards Track; checked 2026-09-18 | X25519 group 31 via x25519-dalek; noncontributory secrets rejected |
| [RFC 6023](https://www.rfc-editor.org/rfc/rfc6023.html) | Experimental; checked 2026-09-18 | Explicitly opted-in childless IKE SA establishment |
| [RFC 4301](https://www.rfc-editor.org/rfc/rfc4301.html) | IPsec security architecture | Directional SA ownership and exact host selector enforcement; no complete SPD/SAD gateway |
| [RFC 4303](https://www.rfc-editor.org/rfc/rfc4303.html) | ESP specification | Partial packet framing/replay behavior; no ESN or complete IPsec processing |
| [RFC 4106](https://www.rfc-editor.org/rfc/rfc4106.html) | AES-GCM ESP profile | AES-256, 4-byte salt, 8-byte explicit IV, 16-byte tag; independent peer validation pending |
| [RFC 5869](https://www.rfc-editor.org/rfc/rfc5869.html) | HKDF | RustCrypto HKDF with known-answer test; provisioning context is project-specific and experimental |
| [RFC 9242](https://www.rfc-editor.org/rfc/rfc9242.html) | IKE_INTERMEDIATE | Referenced/planned; no IntAuth or encrypted intermediate exchange |
| [RFC 9370](https://www.rfc-editor.org/rfc/rfc9370.html) | Multiple key exchanges | Isolated sequential update arithmetic; negotiation and transcript binding planned |
| [draft-ietf-ipsecme-ikev2-mlkem-09](https://datatracker.ietf.org/doc/draft-ietf-ipsecme-ikev2-mlkem/) | Revision 09, July 5 2026; datatracker showed RFC Ed Queue | Referenced/planned; no published RFC number asserted |
| [FIPS 203](https://csrc.nist.gov/pubs/fips/203/final) | Final Aug 13 2024; errata planning note Nov 17 2025 | ML-KEM planned, no provider currently exported |
| [FIPS 204](https://csrc.nist.gov/pubs/fips/204/final) | Final Aug 13 2024; errata planning note Jul 31 2026 | ML-DSA planned |
| [FIPS 205](https://csrc.nist.gov/pubs/fips/205/final) | Final Aug 13 2024 | SLH-DSA referenced, not implemented |
| [FIPS 206 / FN-DSA](https://csrc.nist.gov/Projects/Post-Quantum-Cryptography/Post_Quantum_Cryptography-Standardization) | NIST lists Falcon selected, FIPS 206 in development | No final-standard claim; false Falcon alias removed |
| [ETSI GS QKD 014 V1.1.1 (2019-02)](https://www.etsi.org/deliver/etsi_gs/QKD/001_099/014/01.01.01_60/gs_QKD014v010101p.pdf) | Published key-delivery API; work programme also lists an unpublished revision | Referenced/planned; no adapter |
| [ETSI GS QKD 020 V1.1.1 (2026-06)](https://www.etsi.org/deliver/etsi_gs/QKD/001_099/020/01.01.01_60/gs_QKD020v010101p.pdf) | Published interoperable KMS API | Referenced/planned; not interchangeable with SAE key delivery |

FIPS algorithm publication does not establish that this crate or a future dependency is FIPS 140 validated. Legacy algorithm names are not aliases for finalized algorithms without a verified implementation. AES-GCM with HMAC-SHA-256 PRF is the fixed experimental session profile, not a production default. X25519 + ML-KEM-768 and ML-DSA-65 remain target choices subject to authentication-profile and interoperability review.
