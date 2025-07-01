//! Quantum-safe IPSec implementation
//! 
//! This crate provides a post-quantum secure implementation of IPSec
//! using Kyber for key encapsulation and Dilithium for digital signatures.

#![cfg_attr(feature = "no_std", no_std)]

use serde::{Deserialize, Serialize};
use thiserror::Error;
use std::time::Duration;

pub mod crypto;
pub mod ike;
pub mod ipsec;
pub mod utils;

/// Error type for quantum IPSec operations
#[derive(Debug, Error)]
pub enum QuantumIpsecError {
    #[error("Configuration error: {0}")]
    ConfigError(String),
    #[error("Packet processing error: {0}")]
    PacketError(String),
    #[error("Authentication error: {0}")]
    AuthError(String),
    #[error("Crypto error: {0}")]
    CryptoError(String),
    #[error("I/O error: {0}")]
    IoError(String),
}

/// Result type for quantum IPSec operations
pub type Result<T> = std::result::Result<T, QuantumIpsecError>;

/// Configuration for quantum IPSec
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuantumIpsecConfig {
    /// Enable debug logging
    pub debug: bool,
    /// Maximum number of SAs
    pub max_sas: usize,
    /// SA lifetime in seconds
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

/// Main quantum IPSec processor
pub struct QuantumIpsec {
    /// IKE processor
    pub ike: ike::IkeProcessor,
    /// IPSec processor
    pub ipsec: ipsec::IpSecProcessor,
    /// Configuration
    pub config: QuantumIpsecConfig,
}

impl QuantumIpsec {
    /// Creates a new quantum IPSec instance
    pub fn new(config: QuantumIpsecConfig) -> Result<Self> {
        Ok(Self {
            ike: ike::IkeProcessor::new()?,
            ipsec: ipsec::IpSecProcessor::new()?,
            config,
        })
    }
    
    /// Process an incoming packet
    pub fn process_packet(&mut self, packet: &[u8]) -> Result<Vec<u8>> {
        // TODO: Implement packet processing logic
        Ok(packet.to_vec())
    }
}

// Re-export main types
pub use crypto::{
    Kyber512,
    Dilithium3,
    KYBER_PUBLICKEYBYTES,
    KYBER_SECRETKEYBYTES,
    KYBER_CIPHERTEXTBYTES,
    KYBER_SSBYTES,
    DILITHIUM_PUBLICKEYBYTES,
    DILITHIUM_SECRETKEYBYTES,
    DILITHIUM_SIGNATUREBYTES,
};

pub use ike::{
    CryptoAdapter, DebugContext, DebugLevel, ExchangeType, IkeMessage, IkeProcessor,
    Initiator, Responder, SAManager,
};

pub use ipsec::sa::{SecurityAssociation, SecurityAssociationDatabase};
pub use ipsec::policy::{SecurityPolicy, SecurityPolicyDatabase, PolicyAction, PolicyProtocol};
pub use ipsec::utils::{IpHeader};
pub use ipsec::esp::{EspHeader};
pub use ipsec::ah::{AhHeader};
pub use ipsec::IpSecProcessor; 