use criterion::{
    black_box, criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion, Throughput,
};
use quantum_ipsec::{
    crypto::secret::SecretBytes,
    ipsec::{
        esp::{decrypt_packet, encrypt_packet},
        sa::{Direction, SaLifetime, SecurityAssociation},
    },
    keying::schedule::{derive_traffic_keys, KeyContext},
};
use std::time::Duration;
fn bench(c: &mut Criterion) {
    let mut group = c.benchmark_group("esp_aes256gcm");
    for size in [64, 512, 1400, 9000] {
        group.throughput(Throughput::Bytes(size));
        let mut session_id = [1; 32];
        session_id[..8].copy_from_slice(&size.to_be_bytes());
        let ctx = KeyContext {
            initiator_spi: 256,
            responder_spi: 257,
            session_id,
            transcript_hash: [2; 32],
            generation: 1,
        };
        let limits = SaLifetime {
            max_age: Duration::from_secs(3600),
            max_packets: u32::MAX as u64,
            max_bytes: u64::MAX,
            rekey_after_packets: 1_000_000,
        };
        let (keys, p) = derive_traffic_keys(SecretBytes::new([3; 32]), &ctx).unwrap();
        let mut tx = SecurityAssociation::new(
            257,
            Direction::Outbound,
            keys.initiator_to_responder,
            limits,
            p,
        )
        .unwrap();
        let payload = vec![0; size as usize];
        group.bench_with_input(BenchmarkId::new("seal", size), &payload, |b, input| {
            b.iter(|| black_box(encrypt_packet(&mut tx, black_box(input), 4).unwrap()))
        });
        // Fresh pair for seal+open; distinct session avoids resetting the key/counter.
        session_id[8] = 4;
        let ctx = KeyContext { session_id, ..ctx };
        let (a, pa) = derive_traffic_keys(SecretBytes::new([3; 32]), &ctx).unwrap();
        let (b, pb) = derive_traffic_keys(SecretBytes::new([3; 32]), &ctx).unwrap();
        let mut tx = SecurityAssociation::new(
            257,
            Direction::Outbound,
            a.initiator_to_responder,
            limits,
            pa,
        )
        .unwrap();
        let mut rx = SecurityAssociation::new(
            257,
            Direction::Inbound,
            b.initiator_to_responder,
            limits,
            pb,
        )
        .unwrap();
        group.bench_with_input(BenchmarkId::new("seal_open", size), &payload, |b, input| {
            b.iter(|| {
                let wire = encrypt_packet(&mut tx, black_box(input), 4).unwrap();
                black_box(decrypt_packet(&mut rx, &wire).unwrap());
            })
        });
        // Setup seals increasing sequences outside the measured open operation.
        group.bench_with_input(BenchmarkId::new("open", size), &payload, |b, input| {
            b.iter_batched(
                || encrypt_packet(&mut tx, input, 4).unwrap(),
                |wire| black_box(decrypt_packet(&mut rx, &wire).unwrap()),
                BatchSize::SmallInput,
            )
        });
    }
    group.finish();
}
criterion_group!(benches, bench);
criterion_main!(benches);
