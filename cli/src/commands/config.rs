use crate::utils::{print_output, CliError};
use clap::{Args, Subcommand};

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
    let mut config = crate::utils::load_config(path)?;
    match args.command {
        ConfigSubcommand::Get { key } => {
            let value = match key.as_str() {
                "debug" => config.debug.to_string(),
                "max_sas" => config.max_sas.to_string(),
                "sa_lifetime" => config.sa_lifetime.to_string(),
                _ => return Err(CliError::Other("unknown configuration key".into())),
            };
            print_output(&value, &global.output_format, global.verbose);
        }
        ConfigSubcommand::Set { key, value } => {
            match key.as_str() {
                "debug" => {
                    config.debug = value
                        .parse()
                        .map_err(|_| CliError::Other("invalid boolean".into()))?
                }
                "max_sas" => {
                    config.max_sas = value
                        .parse()
                        .map_err(|_| CliError::Other("invalid max_sas".into()))?
                }
                "sa_lifetime" => {
                    config.sa_lifetime = value
                        .parse()
                        .map_err(|_| CliError::Other("invalid lifetime".into()))?
                }
                _ => return Err(CliError::Other("unknown configuration key".into())),
            }
            config.validate()?;
            crate::utils::save_config(path, &config)?;
            print_output(&"Config updated", &global.output_format, global.verbose);
        }
    }
    Ok(())
}
