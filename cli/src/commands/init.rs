use clap::Args;
use crate::utils::{CliError, print_output};
use quantum_ipsec::{CryptoAdapter, DebugLevel, QuantumIpsecConfig};
use std::fs::File;
use std::io::Write;

/// Initialize quantum-ipsec: generate keypair and write default config file.
#[derive(Args, Debug, Clone)]
pub struct InitArgs {
    /// Path to config file
    #[arg(long)]
    pub config: Option<String>,
}

pub async fn run(args: InitArgs, global: &crate::Cli) -> Result<(), CliError> {
    let config = QuantumIpsecConfig::default();
    let adapter = CryptoAdapter::new(DebugLevel::Basic);
    let (pk, sk) = adapter.generate_keypair().map_err(CliError::from)?;
    let path = args.config.as_deref().unwrap_or("quantum-ipsec.toml");
    let config_str = toml::to_string(&config).map_err(|e| CliError::Other(e.to_string()))?;
    let mut file = File::create(path)?;
    file.write_all(config_str.as_bytes())?;
    // Save keypair as well
    let mut keyfile = File::create("quantum-ipsec.keypair")?;
    keyfile.write_all(&pk)?;
    keyfile.write_all(&sk)?;
    print_output(&config, &global.output_format, global.verbose);
    Ok(())
} 