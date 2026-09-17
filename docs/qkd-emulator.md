# QKD emulator — not implemented

The emulator is a future integration test fixture, not an optical QKD simulator or a source of information-theoretic security claims. No `quantum-qkd-emulator` command currently exists.

Acceptance requires synchronized peer key IDs, separate endpoint consumption ledgers, bounded pool accounting, reserve/commit/void semantics, exhaustion and health states. Fault injection must cover provider disconnection, delayed retrieval, duplicate IDs, wrong peer, mismatched bytes, malformed responses and compromise. After an ambiguous failure, consumed or disclosed material must never return to availability.

Seeded deterministic operation is test-only; other operation uses an established OS CSPRNG. Neither mode creates physical QKD guarantees. Measurements report simulated retrieval, consumption and local rekey overhead separately from hardware experiments. Implementation and QKD response-parser fuzzing wait for the Phase 6.5 gate. See [QKD architecture](../QKD_ARCHITECTURE.md).
