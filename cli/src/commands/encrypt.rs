use clap::Args;
use crate::utils::{CliError, print_output};
use quantum_ipsec::{SecurityAssociation, ipsec::esp::encrypt_packet};
use std::fs;

/// Encrypt a payload or file using an established Security Association (SA).
#[derive(Args, Debug, Clone)]
pub struct EncryptArgs {
    /// Security Association ID (SPI)
    #[arg(long)]
    pub sa: String,
    /// Input file
    #[arg(long)]
    pub input: String,
    /// Output file
    #[arg(long)]
    pub output: String,
}

pub async fn run(args: EncryptArgs, global: &crate::Cli) -> Result<(), CliError> {
    let sa_bytes = fs::read(&args.sa)?;
    let sa: SecurityAssociation = bincode::deserialize(&sa_bytes).map_err(|e| CliError::Other(e.to_string()))?;
    let input = fs::read(&args.input)?;
    let packet = encrypt_packet(&sa, &input);
    let packet_bytes = bincode::serialize(&packet).map_err(|e| CliError::Other(e.to_string()))?;
    fs::write(&args.output, &packet_bytes)?;
    print_output(&"Encryption successful", &global.output_format, global.verbose);
    Ok(())
} 