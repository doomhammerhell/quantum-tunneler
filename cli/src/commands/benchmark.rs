use crate::utils::{print_output, CliError};
use clap::Args;
use quantum_ipsec::{
    crypto::secret::SecretBytes,
    ipsec::{
        esp::{decrypt_packet, encrypt_packet, MAX_PLAINTEXT},
        sa::{Direction, SaLifetime, SecurityAssociation},
    },
    keying::schedule::{derive_traffic_keys, KeyContext},
    utils::random_array,
};
use std::time::{Duration, Instant};
#[derive(Args, Debug, Clone)]
pub struct BenchmarkArgs {
    #[arg(long, default_value = "1")]
    pub duration: u64,
    #[arg(long, default_value = "1400")]
    pub payload_size: usize,
}
pub async fn run(args: BenchmarkArgs, global: &crate::Cli) -> Result<(), CliError> {
    if args.duration == 0 || args.duration > 60 || args.payload_size > MAX_PLAINTEXT {
        return Err(CliError::Other(
            "duration must be 1..60 and payload within ESP limit".into(),
        ));
    }
    let context = KeyContext {
        initiator_spi: 256,
        responder_spi: 257,
        session_id: random_array()?,
        transcript_hash: [1; 32],
        generation: 1,
    };
    let master = SecretBytes::new(random_array()?);
    let (a, pa) = derive_traffic_keys(SecretBytes::new(*master.expose()), &context)?;
    let (b, pb) = derive_traffic_keys(SecretBytes::new(*master.expose()), &context)?;
    let limits = SaLifetime {
        max_age: Duration::from_secs(120),
        max_packets: u32::MAX as u64,
        max_bytes: u64::MAX,
        rekey_after_packets: 1_000_000,
    };
    let mut tx = SecurityAssociation::new(
        257,
        Direction::Outbound,
        a.initiator_to_responder,
        limits,
        pa,
    )?;
    let mut rx = SecurityAssociation::new(
        257,
        Direction::Inbound,
        b.initiator_to_responder,
        limits,
        pb,
    )?;
    let payload = vec![0u8; args.payload_size];
    let start = Instant::now();
    let mut packets = 0u64;
    while start.elapsed() < Duration::from_secs(args.duration) {
        let wire = encrypt_packet(&mut tx, &payload, 4)?;
        let opened = decrypt_packet(&mut rx, &wire)?;
        if opened.payload != payload {
            return Err(CliError::Other("round trip mismatch".into()));
        }
        packets += 1;
    }
    let seconds = start.elapsed().as_secs_f64();
    let report = serde_json::json!({"benchmark":"laboratory ESP seal+open including allocation", "packets":packets,"payload_bytes":args.payload_size,"seconds":seconds,"round_trips_per_second":packets as f64/seconds,"payload_mebibytes_per_second":packets as f64*args.payload_size as f64/seconds/1048576.0});
    print_output(&report, &global.output_format, global.verbose);
    Ok(())
}
