use clap::Args;
use crate::utils::{CliError, print_output};
use quantum_ipsec::{SecurityAssociation, ipsec::esp::{EspPacket, decrypt_packet}};
use std::fs;

/// Decrypt a .pcap or binary blob using an established Security Association (SA).
#[derive(Args, Debug, Clone)]
pub struct DecryptArgs {
    /// Security Association ID (SPI)
    #[arg(long)]
    pub sa: String,
    /// Input file
    #[arg(long)]
    pub input: String,
}

pub async fn run(args: DecryptArgs, global: &crate::Cli) -> Result<(), CliError> {
    let sa_bytes = fs::read(&args.sa)?;
    let sa: SecurityAssociation = bincode::deserialize(&sa_bytes).map_err(|e| CliError::Other(e.to_string()))?;
    let packet_bytes = fs::read(&args.input)?;
    let packet: EspPacket = bincode::deserialize(&packet_bytes).map_err(|e| CliError::Other(e.to_string()))?;
    let plaintext = decrypt_packet(&sa, &packet).map_err(CliError::from)?;
    print_output(&plaintext, &global.output_format, global.verbose);
    Ok(())
} 