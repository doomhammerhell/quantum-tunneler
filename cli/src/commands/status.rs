use clap::Args;
use crate::utils::{CliError, print_output};
use quantum_ipsec::{IpSecProcessor, QuantumIpsecConfig};

/// Display active Security Associations (SAs) and related info.
#[derive(Args, Debug, Clone)]
pub struct StatusArgs {
    /// Output as JSON
    #[arg(long)]
    pub json: bool,
    /// Verbose output
    #[arg(long)]
    pub verbose: bool,
}

pub async fn run(_args: StatusArgs, global: &crate::Cli) -> Result<(), CliError> {
    let config = QuantumIpsecConfig::default();
    let ipsec = IpSecProcessor::new().map_err(CliError::from)?;
    let stats = ipsec.get_stats();
    print_output(&stats, &global.output_format, global.verbose);
    Ok(())
} 