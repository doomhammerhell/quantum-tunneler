use crate::utils::CliError;
use clap::Args;
#[derive(Args, Debug, Clone)]
pub struct ConnectArgs {
    /// Peer IP address
    #[arg(long)]
    pub peer: String,
    /// Tunnel mode (tunnel or transport)
    #[arg(long, default_value = "tunnel")]
    pub mode: String,
}

pub async fn run(_args: ConnectArgs, _global: &crate::Cli) -> Result<(), CliError> {
    Err(CliError::Other(
        "authenticated IKEv2 negotiation is unavailable".into(),
    ))
}
