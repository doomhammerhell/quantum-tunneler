#![cfg_attr(feature = "no_std", no_std)]

use serde::{Deserialize, Serialize};

pub mod crypto;
pub mod ike;
pub mod ipsec;
pub mod utils;

/// Main error type for the quantum_ipsec crate
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum QuantumIpsecError {
    /// Cryptographic operation failed
    CryptoError(String),
    /// IKE protocol error
    IkeError(String),
    /// IPSec protocol error
    IpsecError(String),
    /// Invalid configuration
    ConfigError(String),
    /// Internal error
    InternalError(String),
}

/// Result type alias for the crate
pub type Result<T> = core::result::Result<T, QuantumIpsecError>;

/// Core configuration for the quantum-safe IPSec implementation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuantumIpsecConfig {
    /// Enable post-quantum cryptography
    pub enable_pqc: bool,
    /// Security level (128, 192, or 256 bits)
    pub security_level: u32,
    /// Maximum number of security associations
    pub max_sas: usize,
}

impl Default for QuantumIpsecConfig {
    fn default() -> Self {
        Self {
            enable_pqc: true,
            security_level: 128,
            max_sas: 1024,
        }
    }
}

/// Initialize the quantum-safe IPSec system
pub fn init(config: QuantumIpsecConfig) -> Result<()> {
    // TODO: Implement initialization logic
    Ok(())
} 