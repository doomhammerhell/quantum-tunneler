# ESP benchmark observations

Executed 2026-09-16 with Rust 1.95.0, Criterion 0.5.1, release optimization, x86_64-apple-darwin binary on an ARM64 macOS host (translation environment). These are local microbenchmarks, not native ARM64 performance, network throughput or tunnel capacity claims. Other validation work ran on the same host; no isolated performance laboratory was used.

Command:

```sh
cargo bench -p quantum_ipsec --bench esp -- --sample-size 10 --warm-up-time 0.2 --measurement-time 0.3
```

Mean time per operation, microseconds, from Criterion estimates:

| Payload bytes | Seal µs | Open µs | Seal + open µs |
|---:|---:|---:|---:|
| 64 | 0.657 | 0.791 | 1.387 |
| 512 | 1.383 | 1.510 | 2.885 |
| 1400 | 2.510 | 2.784 | 5.306 |
| 9000 | 12.826 | 13.585 | 26.380 |

Seal includes packet framing, cipher initialization and allocations. Open includes parsing, AEAD, replay-window update, padding validation and output allocation. Open input preparation seals monotonically increasing packet sequences outside the measured routine using Criterion batched setup. Round trip includes both operations and allocations; setup/provisioning is outside timed iterations. Test keys are public laboratory fixtures and are never network credentials. Session context differs across benchmark sizes.

Only ten samples with short warmup/measurement were taken. Results are smoke-level observations; they must not be used for production sizing. Criterion reports under target/criterion are generated local artifacts. No performance comparison with the removed mock/XOR path is meaningful.

ML-KEM/ML-DSA, IKE/hybrid latency, peer rekey, concurrent tunnels and QKD/KME measurements are unavailable because those protocols/providers are not implemented. Physical QKD performance is not simulated or claimed.
