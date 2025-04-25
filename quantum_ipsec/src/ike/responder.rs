//! IKEv2 responder implementation.
//!
//! This module implements the responder side of the IKEv2 protocol,
//! handling the IKE_SA_INIT and IKE_AUTH exchanges.

use super::{
    IKEError, IKEResult, IKEMessage, ExchangeType, SessionState,
    CryptoAdapter, IKEProposal,
};
use crate::crypto::traits::{KeyEncapsulation, DigitalSignature};

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
}

impl Responder {
    /// Creates a new IKEv2 responder
    pub fn new() -> IKEResult<Self> {
        let crypto = CryptoAdapter::new();
        let (pk, sk) = crypto.generate_keypair()?;
        
        Ok(Self {
            crypto,
            state: SessionState::None,
            session_id: 0,
            proposal: IKEProposal::default(),
            local_keys: (pk, sk),
            remote_pubkey: None,
            shared_secret: None,
        })
    }

    /// Handles an IKE_SA_INIT request
    pub fn handle_sa_init(&mut self, request: IKEMessage) -> IKEResult<IKEMessage> {
        if self.state != SessionState::None {
            return Err(IKEError::StateError);
        }

        // Extract remote public key and perform key exchange
        if let Some(remote_pk) = request.encrypted_payload {
            self.remote_pubkey = Some(remote_pk.clone());
            let (ct, ss) = self.crypto.encapsulate(&remote_pk)?;
            self.shared_secret = Some(ss);
        }

        // Create response message
        let mut response = IKEMessage::new(
            1,
            ExchangeType::SAInit,
            self.proposal.clone(),
            [0u8; 32], // TODO: Generate proper nonce
        );
        response.add_encrypted_payload(self.local_keys.0.clone());

        self.state = SessionState::InitCompleted;
        Ok(response)
    }

    /// Handles an IKE_AUTH request
    pub fn handle_auth(&mut self, request: IKEMessage) -> IKEResult<IKEMessage> {
        if self.state != SessionState::InitCompleted {
            return Err(IKEError::StateError);
        }

        // Verify authentication data
        if let Some(auth_data) = request.encrypted_payload {
            self.verify_auth_data(&auth_data)?;
        }

        // Create response message
        let mut response = IKEMessage::new(
            2,
            ExchangeType::Auth,
            self.proposal.clone(),
            [0u8; 32], // TODO: Generate proper nonce
        );
        response.add_encrypted_payload(self.create_auth_data()?);

        self.state = SessionState::AuthCompleted;
        Ok(response)
    }

    /// Verifies authentication data
    fn verify_auth_data(&self, auth_data: &[u8]) -> IKEResult<()> {
        // TODO: Implement proper authentication verification
        Ok(())
    }

    /// Creates authentication data for response
    fn create_auth_data(&self) -> IKEResult<Vec<u8>> {
        // TODO: Implement proper authentication data creation
        Ok(vec![0u8; 32])
    }

    /// Returns the current session state
    pub fn state(&self) -> SessionState {
        self.state
    }

    /// Returns the session ID
    pub fn session_id(&self) -> u64 {
        self.session_id
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
        let request = IKEMessage::new(
            1,
            ExchangeType::SAInit,
            IKEProposal::default(),
            [0u8; 32],
        );
        let response = responder.handle_sa_init(request).unwrap();
        assert_eq!(response.exchange_type, ExchangeType::SAInit);
        assert_eq!(responder.state(), SessionState::InitCompleted);
    }
} 