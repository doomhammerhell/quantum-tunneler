//! IKEv2 initiator implementation.
//!
//! This module implements the initiator side of the IKEv2 protocol,
//! handling the IKE_SA_INIT and IKE_AUTH exchanges.

use super::{
    IKEError, IKEResult, IKEMessage, ExchangeType, SessionState,
    CryptoAdapter, IKEProposal,
};
use crate::crypto::traits::{KeyEncapsulation, DigitalSignature};

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
}

impl Initiator {
    /// Creates a new IKEv2 initiator
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

    /// Initiates the IKE_SA_INIT exchange
    pub fn initiate_sa_init(&mut self) -> IKEResult<IKEMessage> {
        if self.state != SessionState::None {
            return Err(IKEError::StateError);
        }

        // Create IKE_SA_INIT message
        let message = IKEMessage::new(
            1,
            ExchangeType::SAInit,
            self.proposal.clone(),
            [0u8; 32], // TODO: Generate proper nonce
        );

        self.state = SessionState::InitCompleted;
        Ok(message)
    }

    /// Handles the response to IKE_SA_INIT
    pub fn handle_sa_init_response(&mut self, response: IKEMessage) -> IKEResult<()> {
        if self.state != SessionState::InitCompleted {
            return Err(IKEError::StateError);
        }

        // Extract remote public key and perform key exchange
        if let Some(remote_pk) = response.encrypted_payload {
            self.remote_pubkey = Some(remote_pk.clone());
            let (ct, ss) = self.crypto.encapsulate(&remote_pk)?;
            self.shared_secret = Some(ss);
        }

        Ok(())
    }

    /// Initiates the IKE_AUTH exchange
    pub fn initiate_auth(&mut self) -> IKEResult<IKEMessage> {
        if self.state != SessionState::InitCompleted {
            return Err(IKEError::StateError);
        }

        // Create authentication message
        let auth_data = self.create_auth_data()?;
        let mut message = IKEMessage::new(
            2,
            ExchangeType::Auth,
            self.proposal.clone(),
            [0u8; 32], // TODO: Generate proper nonce
        );
        message.add_encrypted_payload(auth_data);

        self.state = SessionState::AuthCompleted;
        Ok(message)
    }

    /// Creates authentication data for IKE_AUTH
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
    fn test_initiator_creation() {
        let initiator = Initiator::new().unwrap();
        assert_eq!(initiator.state(), SessionState::None);
    }

    #[test]
    fn test_sa_init() {
        let mut initiator = Initiator::new().unwrap();
        let message = initiator.initiate_sa_init().unwrap();
        assert_eq!(message.exchange_type, ExchangeType::SAInit);
        assert_eq!(initiator.state(), SessionState::InitCompleted);
    }
} 