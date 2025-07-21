use clap::Args;
use crate::utils::{CliError, print_output};
use quantum_ipsec::IkeProcessor;

/// Establish a tunnel with a peer using IKEv2 negotiation.
#[derive(Args, Debug, Clone)]
pub struct ConnectArgs {
    /// Peer IP address
    #[arg(long)]
    pub peer: String,
    /// Tunnel mode (tunnel or transport)
    #[arg(long, default_value = "tunnel")]
    pub mode: String,
}

pub async fn run(args: ConnectArgs, global: &crate::Cli) -> Result<(), CliError> {
    // For now, just simulate IKEv2 negotiation
    let sa = IkeProcessor::ike_sa_init(true).map_err(CliError::from)?;
    print_output(&sa, &global.output_format, global.verbose);
    Ok(())
} 