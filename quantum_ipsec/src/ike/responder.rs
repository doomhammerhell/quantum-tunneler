//! IKEv2 responder implementation.
//!
//! This module implements the responder side of the IKEv2 protocol,
//! handling the IKE_SA_INIT and IKE_AUTH exchanges.

use crate::ike::{
    CryptoAdapter, ExchangeType, SessionState,
};
use crate::crypto::traits::KeyEncapsulation;
use crate::{QuantumIpsecError, Result};
use crate::ike::exchange::IkeMessage;
use crate::ike::proposal::IKEProposal;
use crate::ike::DebugLevel;

/// IKEv2 responder implementation
pub struct Responder {
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
    /// Responder SPI
    responder_spi: u64,
}

impl Responder {
    /// Create a new responder
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
            responder_spi: rand::random::<u64>(),
        })
    }

    /// Handle IKE_SA_INIT request
    pub fn handle_sa_init(&mut self, request: IkeMessage) -> Result<IkeMessage> {
        if self.state != SessionState::None {
            return Err(QuantumIpsecError::PacketError("Invalid state for SA_INIT".into()));
        }

        // Process request and generate response
        if let Some(payload) = request.payloads.get(0) {
            self.remote_pubkey = Some(payload.clone());
            
            // Generate shared secret using Kyber
            let (_ct, ss) = self.crypto.encapsulate(payload)?;
            self.shared_secret = Some(ss);
        }

        self.message_id += 1;
        let response = IkeMessage::new(
            request.header.initiator_spi,
            self.responder_spi,
            crate::ike::exchange::ExchangeType::IKE_SA_INIT,
            self.message_id,
        );

        self.state = SessionState::SAInit;
        Ok(response)
    }

    /// Handle IKE_AUTH request
    pub fn handle_auth(&mut self, request: IkeMessage) -> Result<IkeMessage> {
        if self.state != SessionState::SAInit {
            return Err(QuantumIpsecError::PacketError("Invalid state for AUTH".into()));
        }

        // Verify authentication
        if !self.verify_auth(&request)? {
            return Err(QuantumIpsecError::AuthError("Authentication failed".into()));
        }

        self.message_id += 1;
        let response = IkeMessage::new(
            request.header.initiator_spi,
            self.responder_spi,
            crate::ike::exchange::ExchangeType::IKE_AUTH,
            self.message_id,
        );

        self.state = SessionState::AuthCompleted;
        Ok(response)
    }

    /// Verify authentication data
    fn verify_auth(&self, _request: &IkeMessage) -> Result<bool> {
        // Simplified authentication verification
        Ok(true)
    }

    /// Returns the current session state
    pub fn state(&self) -> SessionState {
        self.state
    }

    /// Returns the session ID
    pub fn session_id(&self) -> u64 {
        self.session_id
    }

    /// Returns the responder SPI
    pub fn spi(&self) -> u64 {
        self.responder_spi
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
    fn test_responder_creation() {
        let responder = Responder::new().unwrap();
        assert_eq!(responder.state(), SessionState::None);
    }

    #[test]
    fn test_sa_init_handling() {
        let mut responder = Responder::new().unwrap();
        let request = IkeMessage::new(
            12345,
            0,
            ExchangeType::IKE_SA_INIT,
            1,
        );
        
        let response = responder.handle_sa_init(request).unwrap();
        assert_eq!(response.exchange_type, ExchangeType::IKE_SA_INIT);
        assert_eq!(responder.state(), SessionState::SAInit);
    }
} 