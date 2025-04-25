//! IKEv2 message exchange implementation.
//!
//! This module implements the message exchange flows for IKEv2 protocol,
//! including IKE_SA_INIT and IKE_AUTH exchanges.

use super::{IKEError, IKEResult, IKEProposal, SessionState, DebugContext};
use crate::crypto::traits::{KeyEncapsulation, DigitalSignature};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use rand_core::{RngCore, OsRng};

/// Types of IKEv2 exchanges
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ExchangeType {
    /// IKE_SA_INIT exchange
    SAInit,
    /// IKE_AUTH exchange
    Auth,
    /// CHILD_SA negotiation
    ChildSA,
}

/// Represents an IKEv2 message
#[derive(Debug, Clone)]
pub struct IKEMessage {
    /// Message ID
    message_id: u32,
    /// Exchange type
    exchange_type: ExchangeType,
    /// Security proposal
    proposal: IKEProposal,
    /// Nonce
    nonce: [u8; 32],
    /// Encrypted payload
    encrypted_payload: Option<Vec<u8>>,
    /// SA ID (for CHILD_SA exchange)
    sa_id: Option<u32>,
}

impl IKEMessage {
    /// Creates a new IKEv2 message
    pub fn new(
        message_id: u32,
        exchange_type: ExchangeType,
        proposal: IKEProposal,
        nonce: [u8; 32],
    ) -> Self {
        Self {
            message_id,
            exchange_type,
            proposal,
            nonce,
            encrypted_payload: None,
            sa_id: None,
        }
    }

    /// Adds an encrypted payload to the message
    pub fn add_encrypted_payload(&mut self, payload: Vec<u8>) {
        self.encrypted_payload = Some(payload);
    }

    /// Sets the SA ID
    pub fn set_sa_id(&mut self, sa_id: u32) {
        self.sa_id = Some(sa_id);
    }
}

/// Handles IKEv2 message exchanges
pub struct ExchangeHandler {
    /// Current exchange type
    exchange_type: ExchangeType,
    /// Current message ID
    message_id: u32,
    /// Session state
    session_state: SessionState,
    /// Debug context
    debug: DebugContext,
    /// Cryptographic adapter
    crypto: CryptoAdapter,
    /// Shared secret from key exchange
    shared_secret: Option<Vec<u8>>,
    /// Local nonce
    nonce: [u8; 32],
    /// SA manager
    sa_manager: SAManager,
}

impl ExchangeHandler {
    /// Creates a new exchange handler
    pub fn new(debug_level: super::DebugLevel) -> Self {
        Self {
            exchange_type: ExchangeType::SAInit,
            message_id: 0,
            session_state: SessionState::None,
            debug: DebugContext::new(debug_level),
            crypto: CryptoAdapter::new(debug_level),
            shared_secret: None,
            nonce: [0u8; 32],
            sa_manager: SAManager::new(),
        }
    }

    /// Handles an incoming IKEv2 message
    pub fn handle_message(&mut self, message: IKEMessage) -> IKEResult<IKEMessage> {
        self.debug.log_message(&message);
        match message.exchange_type {
            ExchangeType::SAInit => self.handle_sa_init(message),
            ExchangeType::Auth => self.handle_auth(message),
            ExchangeType::ChildSA => self.handle_child_sa(message),
        }
    }

    /// Handles IKE_SA_INIT exchange
    fn handle_sa_init(&mut self, message: IKEMessage) -> IKEResult<IKEMessage> {
        if self.session_state != SessionState::None {
            return Err(IKEError::StateError);
        }

        // Generate nonce
        let nonce = IKESession::generate_nonce();
        
        // Create response message
        let mut response = IKEMessage::new(
            message.message_id + 1,
            ExchangeType::SAInit,
            message.proposal,
            nonce,
        );

        // Add encrypted payload with public key
        if let Some(remote_pk) = message.encrypted_payload {
            let (ct, ss) = self.crypto.encapsulate(&remote_pk)?;
            response.add_encrypted_payload(ct);
            self.shared_secret = Some(ss);
        }

        self.session_state = SessionState::InitCompleted;
        Ok(response)
    }

    /// Handles IKE_AUTH exchange
    fn handle_auth(&mut self, message: IKEMessage) -> IKEResult<IKEMessage> {
        if self.session_state != SessionState::InitCompleted {
            return Err(IKEError::StateError);
        }

        // Verify authentication data
        if let Some(auth_data) = message.encrypted_payload {
            if !self.crypto.verify_auth_data(
                &auth_data,
                self.shared_secret.as_ref().ok_or(IKEError::StateError)?,
                &message.nonce,
                &self.nonce,
            )? {
                return Err(IKEError::ProtocolError);
            }
        }

        // Create response message
        let mut response = IKEMessage::new(
            message.message_id + 1,
            ExchangeType::Auth,
            message.proposal,
            IKESession::generate_nonce(),
        );

        // Add authentication data
        let auth_data = self.crypto.create_auth_data(
            self.shared_secret.as_ref().ok_or(IKEError::StateError)?,
            &message.nonce,
            &self.nonce,
        )?;
        response.add_encrypted_payload(auth_data);

        self.session_state = SessionState::AuthCompleted;
        Ok(response)
    }

    /// Handles CHILD_SA negotiation
    fn handle_child_sa(&mut self, message: IKEMessage) -> IKEResult<IKEMessage> {
        if self.session_state != SessionState::AuthCompleted {
            return Err(IKEError::StateError);
        }

        // Create new CHILD SA
        let child_sa_id = self.sa_manager.create_child_sa(message.proposal.clone());
        
        // Generate new session keys
        let keys = self.crypto.derive_session_keys(
            self.shared_secret.as_ref().ok_or(IKEError::StateError)?,
            &message.nonce,
            &self.nonce,
        )?;

        // Update CHILD SA with new keys
        if let Some(mut sa) = self.sa_manager.get_child_sa(child_sa_id).cloned() {
            sa.update_keys(keys);
            sa.update_state(SessionState::Established);
            self.sa_manager.update_child_sa(child_sa_id, sa)?;
        }

        // Create response message
        let mut response = IKEMessage::new(
            message.message_id + 1,
            ExchangeType::ChildSA,
            message.proposal,
            IKESession::generate_nonce(),
        );
        response.set_sa_id(child_sa_id);

        Ok(response)
    }

    /// Returns the current session state
    pub fn session_state(&self) -> SessionState {
        self.session_state
    }

    /// Returns the SA manager
    pub fn sa_manager(&self) -> &SAManager {
        &self.sa_manager
    }
}

/// Derives session keys from the shared secret
pub fn derive_session_keys(shared_secret: &[u8], nonce_i: &[u8], nonce_r: &[u8]) -> IKEResult<[u8; 32]> {
    let mut key = [0u8; 32];
    let mut mac = Hmac::<Sha256>::new_from_slice(shared_secret)
        .map_err(|_| IKEError::CryptoError)?;
    
    mac.update(nonce_i);
    mac.update(nonce_r);
    
    key.copy_from_slice(&mac.finalize().into_bytes()[..32]);
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_message_creation() {
        let proposal = IKEProposal::default();
        let nonce = [0u8; 32];
        let message = IKEMessage::new(1, ExchangeType::SAInit, proposal, nonce);
        assert_eq!(message.message_id, 1);
        assert_eq!(message.exchange_type, ExchangeType::SAInit);
    }

    #[test]
    fn test_encrypted_payload() {
        let mut message = IKEMessage::new(
            1,
            ExchangeType::SAInit,
            IKEProposal::default(),
            [0u8; 32],
        );
        let payload = vec![1, 2, 3, 4];
        message.add_encrypted_payload(payload.clone());
        assert_eq!(message.encrypted_payload, Some(payload));
    }

    #[test]
    fn test_session_key_derivation() {
        let shared_secret = [1u8; 32];
        let nonce_i = [2u8; 32];
        let nonce_r = [3u8; 32];
        let key = derive_session_keys(&shared_secret, &nonce_i, &nonce_r).unwrap();
        assert_ne!(key, [0u8; 32]);
    }
} 