use crate::utils::CliError;
use clap::Args;
#[derive(Args, Debug, Clone)]
pub struct MonitorArgs {
    /// Refresh interval in ms
    #[arg(long, default_value = "1000")]
    pub interval: u64,
}

pub async fn run(_args: MonitorArgs, _global: &crate::Cli) -> Result<(), CliError> {
    Err(CliError::Other(
        "no daemon is running; live monitoring is not implemented".into(),
    ))
}
