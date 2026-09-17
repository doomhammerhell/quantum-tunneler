use crate::utils::CliError;
use clap::Args;
#[derive(Args, Debug, Clone)]
pub struct DecryptArgs {
    /// Security Association ID (SPI)
    #[arg(long)]
    pub sa: String,
    /// Input file
    #[arg(long)]
    pub input: String,
}

pub async fn run(_args: DecryptArgs, _global: &crate::Cli) -> Result<(), CliError> {
    Err(CliError::Other(
        "SA file import is removed; decryption requires an in-memory SA with a replay window"
            .into(),
    ))
}
