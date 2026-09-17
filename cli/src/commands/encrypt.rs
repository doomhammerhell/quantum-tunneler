use crate::utils::CliError;
use clap::Args;
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

pub async fn run(_args: EncryptArgs, _global: &crate::Cli) -> Result<(), CliError> {
    Err(CliError::Other("SA file import is removed; encryption requires an in-memory SA with exclusive counter ownership".into()))
}
