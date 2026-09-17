# Fuzzing

Targets: `ike_header` (also whole message/serialization), `ike_payload`, `esp_packet`, `sa_proposal`, `ip_packet`. No QKD response parser exists, so a fake QKD fuzz target is deliberately not supplied; it is a Phase 8 gate.

```sh
cargo +nightly fuzz build
cargo +nightly fuzz run ike_header -- -max_total_time=60 -max_len=65536
cargo +nightly fuzz run ike_payload -- -max_total_time=60 -max_len=65536
cargo +nightly fuzz run esp_packet -- -max_total_time=60 -max_len=65536
cargo +nightly fuzz run sa_proposal -- -max_total_time=60 -max_len=65536
cargo +nightly fuzz run ip_packet -- -max_total_time=60 -max_len=65536
```

Use a working nightly toolchain and install `cargo-fuzz` if needed. Bounded borrowed parsing prevents allocation based solely on advertised lengths; resource caps are enforced before body handling. Targets must not panic, overflow or exhibit nondeterministic acceptance. Successful structural parsing is not authentication. Sanitized fuzzing covers local Rust and dependency code exercised by each target, not all dependency behavior or deployment DoS.

See [implementation status](../IMPLEMENTATION_STATUS.md) for the exact toolchain and duration actually exercised. Longer seeded campaigns and valid-message mutation corpora are required before release.

## Bounded smoke runner

`scripts/fuzz_smoke.py` copies committed seeds and runs every target with a separate wall-clock watchdog, including compiler/runtime startup. It terminates the process group on timeout. On Unix hosts:

```sh
python3 scripts/fuzz_smoke.py --toolchain nightly --seconds 20 --watchdog 180
```

The 2026-09-17 run used `nightly-2025-11-21`, `--target aarch64-apple-darwin` and `--sanitizer none`. AddressSanitizer startup did not complete in this host environment; x86_64 sanitizer executables raised SIGILL. These are **unsanitized smoke runs**, not successful ASan validation. Default script behavior still requests AddressSanitizer; use a working environment for release validation.

This Mac had x86_64 Rust with ARM64-only Command Line Tools. Session-only overrides used the absolute native `clang`, `clang++`, and `ar` under `/Library/Developer/CommandLineTools/usr/bin`, both Cargo target linker variables, and `SDKROOT=/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk`. Global toolchain/compiler settings were not changed. The ARM64 standard-library target was installed for the existing nightly toolchain.
