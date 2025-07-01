//! IKEv2 initiator implementation.
//!
//! This module implements the initiator side of the IKEv2 protocol,
//! handling the IKE_SA_INIT and IKE_AUTH exchanges.

use crate::ike::{
    CryptoAdapter, ExchangeType, SessionState,
};
use crate::crypto::traits::KeyEncapsulation;
use crate::{QuantumIpsecError, Result};
use crate::ike::exchange::IkeMessage;
use crate::ike::proposal::IKEProposal;
use crate::ike::DebugLevel;

/// IKEv2 initiator implementation
pub struct Initiator {
    /// Cryptographic adapter
    crypto: CryptoAdapter,
    /// Current session state
    state: SessionState,
    /// Session ID
    session_id: u64,
    /// Security proposal
    proposal: IKEProposal,
    /// Local key pair
    local_keys: (Vec<u8>, Vec<u8>),
    /// Remote public key
    remote_pubkey: Option<Vec<u8>>,
    /// Shared secret
    shared_secret: Option<Vec<u8>>,
    /// Message ID counter
    message_id: u32,
    /// Initiator SPI
    initiator_spi: u64,
}

impl Initiator {
    /// Create a new initiator
    pub fn new() -> Result<Self> {
        let crypto = CryptoAdapter::new(DebugLevel::Basic);
        let (pk, sk) = crypto.generate_keypair()?;
        
        Ok(Self {
            crypto,
            state: SessionState::None,
            session_id: 0,
            proposal: IKEProposal::default(),
            local_keys: (pk, sk),
            remote_pubkey: None,
            shared_secret: None,
            message_id: 0,
            initiator_spi: rand::random::<u64>(),
        })
    }

    /// Initiate IKE_SA_INIT exchange
    pub fn initiate_sa_init(&mut self) -> Result<IkeMessage> {
        if self.state != SessionState::None {
            return Err(QuantumIpsecError::PacketError("Invalid state for SA_INIT".into()));
        }

        self.message_id += 1;
        let message = IkeMessage::new(
            self.initiator_spi,
            0, // responder_spi
            crate::ike::exchange::ExchangeType::IKE_SA_INIT,
            self.message_id,
        );

        self.state = SessionState::InitCompleted;
        Ok(message)
    }

    /// Handle IKE_SA_INIT response
    pub fn handle_sa_init_response(&mut self, _response: IkeMessage) -> Result<()> {
        if self.state != SessionState::InitCompleted {
            return Err(QuantumIpsecError::PacketError("Invalid state for SA_INIT response".into()));
        }

        // Process response and extract shared secret
        // This is a simplified implementation
        self.state = SessionState::SAInit;
        Ok(())
    }

    /// Initiate IKE_AUTH exchange
    pub fn initiate_auth(&mut self) -> Result<IkeMessage> {
        if self.state != SessionState::InitCompleted {
            return Err(QuantumIpsecError::PacketError("Invalid state for AUTH".into()));
        }

        self.message_id += 1;
        let mut message = IkeMessage::new(
            self.initiator_spi,
            0, // responder_spi
            crate::ike::exchange::ExchangeType::IKE_AUTH,
            self.message_id,
        );

        // Add authentication data
        let auth_data = self.create_auth_data()?;
        message.add_payload(auth_data);

        self.state = SessionState::AuthCompleted;
        Ok(message)
    }

    /// Create authentication data
    fn create_auth_data(&self) -> Result<Vec<u8>> {
        // Simplified authentication data creation
        Ok(b"auth_data".to_vec())
    }

    /// Returns the current session state
    pub fn state(&self) -> SessionState {
        self.state
    }

    /// Returns the session ID
    pub fn session_id(&self) -> u64 {
        self.session_id
    }

    /// Returns the initiator SPI
    pub fn spi(&self) -> u64 {
        self.initiator_spi
    }

    /// Returns the session keys
    pub fn session_keys(&self) -> crate::ike::SessionKeys {
        crate::ike::SessionKeys {
            enc_key: self.shared_secret.clone().unwrap_or_default(),
            auth_key: vec![0u8; 32],
            integrity_key: vec![0u8; 32],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_initiator_creation() {
        let initiator = Initiator::new().unwrap();
        assert_eq!(initiator.state(), SessionState::None);
    }

    #[test]
    fn test_sa_init() {
        let mut initiator = Initiator::new().unwrap();
        let message = initiator.initiate_sa_init().unwrap();
        assert_eq!(message.exchange_type, ExchangeType::IKE_SA_INIT);
        assert_eq!(initiator.state(), SessionState::InitCompleted);
    }
} 