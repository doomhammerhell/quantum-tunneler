use crate::utils::{print_output, CliError};
use clap::Args;
use quantum_ipsec::QuantumIpsecConfig;
use std::{fs::OpenOptions, io::Write};
#[derive(Args, Debug, Clone)]
pub struct InitArgs {
    #[arg(long)]
    pub config: Option<String>,
}
pub async fn run(args: InitArgs, global: &crate::Cli) -> Result<(), CliError> {
    let config = QuantumIpsecConfig::default();
    let path = args
        .config
        .as_deref()
        .or(global.config.as_deref())
        .unwrap_or("quantum-ipsec.toml");
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    let text = toml::to_string(&config).map_err(|e| CliError::Other(e.to_string()))?;
    file.write_all(text.as_bytes())?;
    print_output(&config, &global.output_format, global.verbose);
    Ok(())
}
