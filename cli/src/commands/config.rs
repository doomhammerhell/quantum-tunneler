use clap::{Args, Subcommand};
use crate::utils::{CliError, print_output};
use quantum_ipsec::QuantumIpsecConfig;
use std::fs;

/// Read or update configuration parameters.
#[derive(Args, Debug, Clone)]
pub struct ConfigArgs {
    #[command(subcommand)]
    pub command: ConfigSubcommand,
}

#[derive(Subcommand, Debug, Clone)]
pub enum ConfigSubcommand {
    /// Get a configuration value
    Get { key: String },
    /// Set a configuration value
    Set { key: String, value: String },
}

pub async fn run(args: ConfigArgs, global: &crate::Cli) -> Result<(), CliError> {
    let path = global.config.as_deref().unwrap_or("quantum-ipsec.toml");
    let config_str = fs::read_to_string(path)?;
    let mut config: QuantumIpsecConfig = toml::from_str(&config_str).map_err(|e| CliError::Other(e.to_string()))?;
    match args.command {
        ConfigSubcommand::Get { key } => {
            let value = match key.as_str() {
                "debug" => config.debug.to_string(),
                "max_sas" => config.max_sas.to_string(),
                "sa_lifetime" => config.sa_lifetime.to_string(),
                _ => "unknown key".to_string(),
            };
            print_output(&value, &global.output_format, global.verbose);
        }
        ConfigSubcommand::Set { key, value } => {
            match key.as_str() {
                "debug" => config.debug = value == "true",
                "max_sas" => config.max_sas = value.parse().unwrap_or(1000),
                "sa_lifetime" => config.sa_lifetime = value.parse().unwrap_or(3600),
                _ => {}
            }
            let config_str = toml::to_string(&config).map_err(|e| CliError::Other(e.to_string()))?;
            fs::write(path, config_str)?;
            print_output(&"Config updated", &global.output_format, global.verbose);
        }
    }
    Ok(())
} 