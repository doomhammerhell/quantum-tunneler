//! Experimental protocol-hardening foundation. Requires std; not a working VPN.
#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use thiserror::Error;
pub mod crypto;
pub mod ike;
pub mod ipsec;
pub mod keying;
pub mod utils;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum QuantumIpsecError {
    #[error("invalid configuration: {0}")]
    ConfigError(String),
    #[error("invalid packet: {0}")]
    PacketError(String),
    #[error("authentication failed")]
    Authentication,
    #[error("invalid cryptographic input")]
    Crypto,
    #[error("replay or sequence outside window")]
    Replay,
    #[error("SA expired, retired, or usage exhausted")]
    SaExpired,
    #[error("sequence exhausted; rekey required")]
    SequenceExhausted,
    #[error("unknown or mismatched SA")]
    UnknownSa,
    #[error("duplicate SA or policy identifier")]
    Duplicate,
    #[error("capacity exceeded")]
    Capacity,
    #[error("unsupported: {0}")]
    Unsupported(&'static str),
    #[error(transparent)]
    Parse(#[from] ike::parser::ParseError),
}
pub type Result<T> = std::result::Result<T, QuantumIpsecError>;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QuantumIpsecConfig {
    pub debug: bool,
    pub max_sas: usize,
    pub sa_lifetime: u64,
}
impl Default for QuantumIpsecConfig {
    fn default() -> Self {
        Self {
            debug: false,
            max_sas: 1000,
            sa_lifetime: 3600,
        }
    }
}
impl QuantumIpsecConfig {
    pub fn validate(&self) -> Result<()> {
        if self.max_sas == 0 || self.max_sas > 65536 || self.sa_lifetime == 0 {
            return Err(QuantumIpsecError::ConfigError("invalid SA limits".into()));
        }
        Ok(())
    }
}
pub struct QuantumIpsec {
    pub ike: ike::IkeProcessor,
    pub ipsec: ipsec::IpSecProcessor,
}
impl QuantumIpsec {
    pub fn new(config: QuantumIpsecConfig) -> Result<Self> {
        config.validate()?;
        Ok(Self {
            ike: ike::IkeProcessor::new(),
            ipsec: ipsec::IpSecProcessor::new(config.max_sas),
        })
    }
    pub fn process_packet(&mut self, _packet: &[u8]) -> Result<Vec<u8>> {
        Err(QuantumIpsecError::Unsupported(
            "IP routing and authenticated IKE are not implemented",
        ))
    }
}
pub use ike::IkeProcessor;
pub use ipsec::sa::{SecurityAssociation, SecurityAssociationDatabase};
pub use ipsec::IpSecProcessor;
