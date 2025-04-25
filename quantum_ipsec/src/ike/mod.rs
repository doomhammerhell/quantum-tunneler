//! IKEv2 protocol implementation with post-quantum cryptography.
//!
//! This module implements the Internet Key Exchange (IKE) version 2 protocol
//! with post-quantum cryptographic primitives. It replaces classical key
//! exchange methods (DH/ECDH) with Kyber KEM and uses Falcon for digital
//! signatures.
//!
//! The implementation follows RFC 7296 (IKEv2) and is designed to be
//! compatible with existing IKEv2 implementations while providing
//! quantum-resistant security.

#![no_std]

mod proposal;
mod exchange;
mod parser;
mod responder;
mod initiator;
mod crypto_adapter;
mod debug;
mod sa_manager;

pub use proposal::IKEProposal;
pub use exchange::{ExchangeType, IKEMessage, ExchangeHandler};
pub use parser::MessageParser;
pub use responder::Responder;
pub use initiator::Initiator;
pub use crypto_adapter::CryptoAdapter;
pub use debug::{DebugLevel, DebugContext};
pub use sa_manager::{SecurityAssociation, SAManager};

use core::fmt::Debug;
use rand_core::{RngCore, OsRng};

/// Represents the state of an IKEv2 session
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum SessionState {
    /// Initial state, no session established
    None,
    /// IKE_SA_INIT exchange completed
    InitCompleted,
    /// IKE_AUTH exchange completed
    AuthCompleted,
    /// CHILD_SA established
    Established,
    /// Session in error state
    Error,
}

/// Represents the role in an IKEv2 session
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Role {
    /// Initiator of the IKEv2 session
    Initiator,
    /// Responder to the IKEv2 session
    Responder,
}

/// Main structure representing an IKEv2 session
pub struct IKESession {
    /// Current state of the session
    state: SessionState,
    /// Role in the session (initiator or responder)
    role: Role,
    /// Session ID
    session_id: u64,
    /// Security parameters for the session
    security_params: SAParameters,
    /// Debug context
    debug: DebugContext,
}

impl IKESession {
    /// Creates a new IKEv2 session
    pub fn new(role: Role, debug_level: DebugLevel) -> Self {
        Self {
            state: SessionState::None,
            role,
            session_id: 0,
            security_params: SAParameters::default(),
            debug: DebugContext::new(debug_level),
        }
    }

    /// Generates a secure nonce
    pub fn generate_nonce() -> [u8; 32] {
        let mut nonce = [0u8; 32];
        OsRng.fill_bytes(&mut nonce);
        nonce
    }

    /// Returns the current state of the session
    pub fn state(&self) -> SessionState {
        self.state
    }

    /// Returns the role in the session
    pub fn role(&self) -> Role {
        self.role
    }

    /// Returns the session ID
    pub fn session_id(&self) -> u64 {
        self.session_id
    }

    /// Returns the debug context
    pub fn debug_context(&self) -> &DebugContext {
        &self.debug
    }
}

/// Security parameters for an IKEv2 session
#[derive(Debug, Clone)]
pub struct SAParameters {
    /// Selected proposal for the session
    proposal: IKEProposal,
    /// Shared secret key
    shared_secret: [u8; 32],
    /// Session key
    session_key: [u8; 32],
}

impl Default for SAParameters {
    fn default() -> Self {
        Self {
            proposal: IKEProposal::default(),
            shared_secret: [0u8; 32],
            session_key: [0u8; 32],
        }
    }
}

/// Error types for IKEv2 operations
#[derive(Debug)]
pub enum IKEError {
    /// Invalid message format
    InvalidMessage,
    /// Invalid proposal
    InvalidProposal,
    /// Cryptographic operation failed
    CryptoError,
    /// Protocol violation
    ProtocolError,
    /// State machine error
    StateError,
    /// Debug error
    DebugError,
}

/// Result type for IKEv2 operations
pub type IKEResult<T> = Result<T, IKEError>;

/// IKEv2 message types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum IkeMessageType {
    IKE_SA_INIT = 34,
    IKE_AUTH = 35,
    CREATE_CHILD_SA = 36,
    INFORMATIONAL = 37,
}

/// IKEv2 exchange types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExchangeType {
    IKE_SA_INIT,
    IKE_AUTH,
    CREATE_CHILD_SA,
    INFORMATIONAL,
}

/// IKE Security Association
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IkeSa {
    pub initiator_spi: [u8; 8],
    pub responder_spi: [u8; 8],
    pub exchange_type: ExchangeType,
    pub is_initiator: bool,
}

impl IkeSa {
    /// Create a new IKE Security Association
    pub fn new(is_initiator: bool) -> Result<Self> {
        let mut initiator_spi = [0u8; 8];
        let mut responder_spi = [0u8; 8];
        OsRng.fill_bytes(&mut initiator_spi);
        OsRng.fill_bytes(&mut responder_spi);

        Ok(Self {
            initiator_spi,
            responder_spi,
            exchange_type: ExchangeType::IKE_SA_INIT,
            is_initiator,
        })
    }
}

/// IKEv2 protocol implementation
pub mod protocol {
    use super::*;

    /// Perform IKE_SA_INIT exchange
    pub fn ike_sa_init(initiator: bool) -> Result<IkeSa> {
        let mut sa = IkeSa::new(initiator)?;
        sa.exchange_type = ExchangeType::IKE_SA_INIT;
        Ok(sa)
    }

    /// Perform IKE_AUTH exchange
    pub fn ike_auth(sa: &mut IkeSa) -> Result<()> {
        if sa.exchange_type != ExchangeType::IKE_SA_INIT {
            return Err(QuantumIpsecError::IkeError("Invalid exchange type".into()));
        }
        sa.exchange_type = ExchangeType::IKE_AUTH;
        Ok(())
    }

    /// Create a Child SA
    pub fn create_child_sa(sa: &mut IkeSa) -> Result<()> {
        if sa.exchange_type != ExchangeType::IKE_AUTH {
            return Err(QuantumIpsecError::IkeError("Invalid exchange type".into()));
        }
        sa.exchange_type = ExchangeType::CREATE_CHILD_SA;
        Ok(())
    }

    /// Handle informational exchange
    pub fn handle_informational(sa: &mut IkeSa) -> Result<()> {
        sa.exchange_type = ExchangeType::INFORMATIONAL;
        Ok(())
    }
}

/// IKEv2 message handling
pub mod messages {
    use super::*;

    /// IKEv2 message header
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct IkeHeader {
        pub initiator_spi: [u8; 8],
        pub responder_spi: [u8; 8],
        pub next_payload: u8,
        pub version: u8,
        pub exchange_type: u8,
        pub flags: u8,
        pub message_id: u32,
        pub length: u32,
    }

    /// Encode an IKE message
    pub fn encode_message(header: &IkeHeader, payloads: &[u8]) -> Result<Vec<u8>> {
        let mut message = Vec::new();
        
        // Add header fields
        message.extend_from_slice(&header.initiator_spi);
        message.extend_from_slice(&header.responder_spi);
        message.push(header.next_payload);
        message.push(header.version);
        message.push(header.exchange_type);
        message.push(header.flags);
        message.extend_from_slice(&header.message_id.to_be_bytes());
        message.extend_from_slice(&header.length.to_be_bytes());
        
        // Add payloads
        message.extend_from_slice(payloads);
        
        Ok(message)
    }

    /// Decode an IKE message
    pub fn decode_message(data: &[u8]) -> Result<(IkeHeader, Vec<u8>)> {
        if data.len() < 28 { // Minimum header size
            return Err(QuantumIpsecError::IkeError("Message too short".into()));
        }

        let header = IkeHeader {
            initiator_spi: data[0..8].try_into().unwrap(),
            responder_spi: data[8..16].try_into().unwrap(),
            next_payload: data[16],
            version: data[17],
            exchange_type: data[18],
            flags: data[19],
            message_id: u32::from_be_bytes(data[20..24].try_into().unwrap()),
            length: u32::from_be_bytes(data[24..28].try_into().unwrap()),
        };

        let payloads = data[28..].to_vec();
        Ok((header, payloads))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_creation() {
        let session = IKESession::new(Role::Initiator, DebugLevel::Basic);
        assert_eq!(session.state(), SessionState::None);
        assert_eq!(session.role(), Role::Initiator);
    }

    #[test]
    fn test_nonce_generation() {
        let nonce1 = IKESession::generate_nonce();
        let nonce2 = IKESession::generate_nonce();
        assert_ne!(nonce1, nonce2);
    }
} 