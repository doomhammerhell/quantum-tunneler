use clap::Args;
use crate::utils::{CliError, print_output};
use quantum_ipsec::{IkeProcessor, ipsec::esp::encrypt_packet, SecurityAssociation};
use std::time::Instant;

/// Benchmark handshake latency and packet throughput.
#[derive(Args, Debug, Clone)]
pub struct BenchmarkArgs {
    /// Duration in seconds
    #[arg(long, default_value = "10")]
    pub duration: u64,
    /// Payload size in bytes
    #[arg(long, default_value = "1024")]
    pub payload_size: usize,
}

pub async fn run(args: BenchmarkArgs, global: &crate::Cli) -> Result<(), CliError> {
    let start = Instant::now();
    let mut handshakes = 0;
    let mut packets = 0;
    while start.elapsed().as_secs() < args.duration {
        let sa = IkeProcessor::ike_sa_init(true).map_err(CliError::from)?;
        handshakes += 1;
        let dummy_sa = SecurityAssociation::new().map_err(CliError::from)?;
        let payload = vec![0u8; args.payload_size];
        let _ = encrypt_packet(&dummy_sa, &payload);
        packets += 1;
    }
    let elapsed = start.elapsed().as_secs_f64();
    let result = serde_json::json!({
        "handshakes": handshakes,
        "packets": packets,
        "elapsed_sec": elapsed,
        "handshakes_per_sec": handshakes as f64 / elapsed,
        "packets_per_sec": packets as f64 / elapsed,
    });
    print_output(&result, &global.output_format, global.verbose);
    Ok(())
} 