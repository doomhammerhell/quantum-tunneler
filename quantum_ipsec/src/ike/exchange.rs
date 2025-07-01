//! IKEv2 message exchange implementation.
//!
//! This module implements the message exchange flows for IKEv2 protocol,
//! including IKE_SA_INIT and IKE_AUTH exchanges.

use crate::{QuantumIpsecError, Result};
use crate::ike::proposal::IKEProposal;
use crate::crypto::traits::KeyEncapsulation;
use crate::ike::{
    debug::DebugContext, crypto_adapter::CryptoAdapter, sa_manager::SAManager, SessionState,
};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use rand_core::{RngCore, OsRng};
use serde::{Deserialize, Serialize};

/// IKEv2 exchange types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExchangeType {
    /// IKE_SA_INIT exchange
    IKE_SA_INIT,
    /// IKE_AUTH exchange
    IKE_AUTH,
    /// CREATE_CHILD_SA exchange
    CREATE_CHILD_SA,
    /// INFORMATIONAL exchange
    INFORMATIONAL,
}

/// IKEv2 message types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MessageType {
    /// IKE_SA_INIT request
    IKE_SA_INIT_REQ = 34,
    /// IKE_SA_INIT response
    IKE_SA_INIT_RESP = 35,
    /// IKE_AUTH request
    IKE_AUTH_REQ = 39,
    /// IKE_AUTH response
    IKE_AUTH_RESP = 40,
    /// CREATE_CHILD_SA request
    CREATE_CHILD_SA_REQ = 36,
    /// CREATE_CHILD_SA response
    CREATE_CHILD_SA_RESP = 37,
    /// INFORMATIONAL request
    INFORMATIONAL_REQ = 38,
    /// INFORMATIONAL response
    INFORMATIONAL_RESP = 41,
}

/// IKEv2 message header
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IkeHeader {
    /// Initiator's SPI
    pub initiator_spi: u64,
    /// Responder's SPI
    pub responder_spi: u64,
    /// Next payload type
    pub next_payload: u8,
    /// Major version
    pub major_version: u8,
    /// Minor version
    pub minor_version: u8,
    /// Exchange type
    pub exchange_type: u8,
    /// Flags
    pub flags: u8,
    /// Message ID
    pub message_id: u32,
    /// Message length
    pub length: u32,
}

/// IKEv2 payload types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PayloadType {
    /// Security Association
    SA = 33,
    /// Key Exchange
    KE = 34,
    /// Nonce
    Ni = 40,
    /// Nonce
    Nr = 41,
    /// Certificate
    CERT = 37,
    /// Certificate Request
    CERTREQ = 38,
    /// Authentication
    AUTH = 39,
    /// Notify
    NOTIFY = 42,
    /// Delete
    DELETE = 43,
    /// Vendor ID
    VENDOR = 44,
    /// Traffic Selector - Initiator
    TSi = 45,
    /// Traffic Selector - Responder
    TSr = 46,
    /// Encrypted
    SK = 47,
    /// Configuration
    CP = 48,
    /// Extensible Authentication
    EAP = 50,
}

/// IKEv2 payload header
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PayloadHeader {
    /// Next payload type
    pub next_payload: u8,
    /// Critical bit
    pub critical: bool,
    /// Payload length
    pub length: u16,
}

impl PayloadHeader {
    /// Create a new payload header
    pub fn new(next_payload: PayloadType, length: u16) -> Self {
        Self {
            next_payload: next_payload as u8,
            critical: false,
            length,
        }
    }
}

/// IKEv2 message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IkeMessage {
    /// Message header
    pub header: IkeHeader,
    /// Message payloads
    pub payloads: Vec<Vec<u8>>,
}

impl IkeMessage {
    /// Create a new IKE message
    pub fn new(
        initiator_spi: u64,
        responder_spi: u64,
        exchange_type: ExchangeType,
        message_id: u32,
    ) -> Self {
        Self {
            header: IkeHeader {
                initiator_spi,
                responder_spi,
                next_payload: 0,
                major_version: 2,
                minor_version: 0,
                exchange_type: match exchange_type {
                    ExchangeType::IKE_SA_INIT => 34,
                    ExchangeType::IKE_AUTH => 39,
                    ExchangeType::CREATE_CHILD_SA => 36,
                    ExchangeType::INFORMATIONAL => 37,
                },
                flags: 0,
                message_id,
                length: 0,
            },
            payloads: Vec::new(),
        }
    }

    /// Add a payload to the message
    pub fn add_payload(&mut self, payload: Vec<u8>) {
        self.payloads.push(payload);
    }

    /// Serialize the message to bytes
    pub fn serialize(&self) -> Result<Vec<u8>> {
        let mut buffer = Vec::new();
        
        // Serialize header
        buffer.extend_from_slice(&self.header.initiator_spi.to_be_bytes());
        buffer.extend_from_slice(&self.header.responder_spi.to_be_bytes());
        buffer.push(self.header.next_payload);
        buffer.push(self.header.major_version);
        buffer.push(self.header.minor_version);
        buffer.push(self.header.exchange_type);
        buffer.push(self.header.flags);
        buffer.extend_from_slice(&self.header.message_id.to_be_bytes());
        buffer.extend_from_slice(&self.header.length.to_be_bytes());
        
        // Serialize payloads
        for payload in &self.payloads {
            buffer.extend_from_slice(payload);
        }
        
        Ok(buffer)
    }

    /// Deserialize message from bytes
    pub fn deserialize(data: &[u8]) -> Result<Self> {
        if data.len() < 28 {
            return Err(QuantumIpsecError::PacketError("IKE message too short".into()));
        }
        
        let initiator_spi = u64::from_be_bytes(data[0..8].try_into().unwrap());
        let responder_spi = u64::from_be_bytes(data[8..16].try_into().unwrap());
        let next_payload = data[16];
        let major_version = data[17];
        let minor_version = data[18];
        let exchange_type = data[19];
        let flags = data[20];
        let message_id = u32::from_be_bytes(data[21..25].try_into().unwrap());
        let length = u32::from_be_bytes(data[25..29].try_into().unwrap());
        
        let header = IkeHeader {
            initiator_spi,
            responder_spi,
            next_payload,
            major_version,
            minor_version,
            exchange_type,
            flags,
            message_id,
            length,
        };
        
        let payloads = Vec::new(); // TODO: Parse payloads
        
        Ok(Self { header, payloads })
    }
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
    /// Create a new exchange handler
    pub fn new(debug_level: crate::ike::debug::DebugLevel) -> Self {
        Self {
            exchange_type: ExchangeType::IKE_SA_INIT,
            message_id: 0,
            session_state: SessionState::None,
            debug: DebugContext::new(debug_level),
            crypto: CryptoAdapter::new(debug_level),
            shared_secret: None,
            nonce: generate_nonce(),
            sa_manager: SAManager::new(),
        }
    }

    /// Handles an incoming IKEv2 message
    pub fn handle_message(&mut self, message: IKEMessage) -> Result<IKEMessage> {
        self.debug.log_message(&format!("Handling {:?} message", self.exchange_type));
        match message.exchange_type {
            ExchangeType::IKE_SA_INIT => self.handle_sa_init(message),
            ExchangeType::IKE_AUTH => self.handle_auth(message),
            ExchangeType::CREATE_CHILD_SA => self.handle_child_sa(message),
            ExchangeType::INFORMATIONAL => {
                // Simplified INFORMATIONAL handling
                Ok(message)
            }
        }
    }

    /// Handles IKE_SA_INIT exchange
    fn handle_sa_init(&mut self, message: IKEMessage) -> Result<IKEMessage> {
        if self.session_state != SessionState::None {
            return Err(QuantumIpsecError::PacketError("Estado inválido".into()));
        }

        // Generate nonce
        let nonce = generate_nonce();
        
        // Create response message
        let mut response = IKEMessage::new(
            message.message_id + 1,
            ExchangeType::IKE_SA_INIT,
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
    fn handle_auth(&mut self, message: IKEMessage) -> Result<IKEMessage> {
        if self.session_state != SessionState::InitCompleted {
            return Err(QuantumIpsecError::PacketError("Estado inválido".into()));
        }

        // Verify authentication data
        if let Some(auth_data) = message.encrypted_payload {
            if !self.crypto.verify_auth_data(
                &auth_data,
                self.shared_secret.as_ref().ok_or(QuantumIpsecError::PacketError("Estado inválido".into()))?,
                &message.nonce,
                &self.nonce,
            )? {
                return Err(QuantumIpsecError::PacketError("Erro de protocolo".into()));
            }
        }

        // Create response message
        let mut response = IKEMessage::new(
            message.message_id + 1,
            ExchangeType::IKE_AUTH,
            message.proposal,
            generate_nonce(),
        );

        // Add authentication data
        let auth_data = self.crypto.create_auth_data(
            self.shared_secret.as_ref().ok_or(QuantumIpsecError::PacketError("Estado inválido".into()))?,
            &message.nonce,
            &self.nonce,
        )?;
        response.add_encrypted_payload(auth_data);

        self.session_state = SessionState::AuthCompleted;
        Ok(response)
    }

    /// Handles CHILD_SA negotiation
    fn handle_child_sa(&mut self, message: IKEMessage) -> Result<IKEMessage> {
        if self.session_state != SessionState::AuthCompleted {
            return Err(QuantumIpsecError::PacketError("Estado inválido".into()));
        }

        // Create new CHILD SA
        let child_sa_id = self.sa_manager.create_child_sa(message.proposal.clone());
        
        // Generate new session keys
        let keys = self.crypto.derive_session_keys(
            self.shared_secret.as_ref().ok_or(QuantumIpsecError::PacketError("Estado inválido".into()))?,
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
            ExchangeType::CREATE_CHILD_SA,
            message.proposal,
            generate_nonce(),
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
pub fn derive_session_keys(shared_secret: &[u8], nonce_i: &[u8], nonce_r: &[u8]) -> Result<[u8; 32]> {
    let mut key = [0u8; 32];
    let mut mac = Hmac::<Sha256>::new_from_slice(shared_secret)
        .map_err(|_| QuantumIpsecError::PacketError("Invalid key length".into()))?;
    
    mac.update(nonce_i);
    mac.update(nonce_r);
    key.copy_from_slice(&mac.finalize().into_bytes()[..32]);
    
    Ok(key)
}

/// Generates a secure nonce
fn generate_nonce() -> [u8; 32] {
    let mut nonce = [0u8; 32];
    getrandom::getrandom(&mut nonce).expect("Failed to generate nonce");
    nonce
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_message_creation() {
        let proposal = IKEProposal::default();
        let nonce = [0u8; 32];
        let message = IKEMessage::new(1, ExchangeType::IKE_SA_INIT, proposal, nonce);
        assert_eq!(message.message_id, 1);
        assert_eq!(message.exchange_type, ExchangeType::IKE_SA_INIT);
    }

    #[test]
    fn test_encrypted_payload() {
        let mut message = IKEMessage::new(
            1,
            ExchangeType::IKE_SA_INIT,
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