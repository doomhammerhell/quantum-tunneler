use serde::Serialize;
use std::fmt;
use quantum_ipsec::QuantumIpsecError;

#[derive(Debug)]
pub enum CliError {
    QuantumIpsec(QuantumIpsecError),
    Io(std::io::Error),
    Other(String),
}

impl std::error::Error for CliError {}

impl fmt::Display for CliError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CliError::QuantumIpsec(e) => write!(f, "QuantumIpsec error: {}", e),
            CliError::Io(e) => write!(f, "IO error: {}", e),
            CliError::Other(e) => write!(f, "Error: {}", e),
        }
    }
}

impl From<QuantumIpsecError> for CliError {
    fn from(e: QuantumIpsecError) -> Self {
        CliError::QuantumIpsec(e)
    }
}

impl From<std::io::Error> for CliError {
    fn from(e: std::io::Error) -> Self {
        CliError::Io(e)
    }
}

pub fn print_output<T: Serialize + std::fmt::Debug>(data: &T, format: &str, verbose: bool) {
    match format {
        "json" => println!("{}", serde_json::to_string_pretty(data).unwrap()),
        _ => {
            if verbose {
                println!("{:#?}", data);
            } else {
                println!("{:?}", data);
            }
        }
    }
}

// Load config from TOML file
pub fn load_config(path: &str) -> Result<quantum_ipsec::QuantumIpsecConfig, CliError> {
    let config_str = std::fs::read_to_string(path)?;
    let config = toml::from_str(&config_str).map_err(|e| CliError::Other(e.to_string()))?;
    Ok(config)
}

// Save config to TOML file
pub fn save_config(path: &str, config: &quantum_ipsec::QuantumIpsecConfig) -> Result<(), CliError> {
    let config_str = toml::to_string(config).map_err(|e| CliError::Other(e.to_string()))?;
    std::fs::write(path, config_str)?;
    Ok(())
}

// Load SecurityAssociation from file (bincode)
pub fn load_sa(path: &str) -> Result<quantum_ipsec::SecurityAssociation, CliError> {
    let sa_bytes = std::fs::read(path)?;
    let sa = bincode::deserialize(&sa_bytes).map_err(|e| CliError::Other(e.to_string()))?;
    Ok(sa)
}

// Save SecurityAssociation to file (bincode)
pub fn save_sa(path: &str, sa: &quantum_ipsec::SecurityAssociation) -> Result<(), CliError> {
    let sa_bytes = bincode::serialize(sa).map_err(|e| CliError::Other(e.to_string()))?;
    std::fs::write(path, sa_bytes)?;
    Ok(())
} 