//! IKEv2 protocol implementation
//! 
//! This module provides the Internet Key Exchange version 2 (IKEv2) protocol
//! implementation with post-quantum cryptographic primitives.

pub mod crypto_adapter;
pub mod debug;
pub mod exchange;
pub mod initiator;
pub mod parser;
pub mod proposal;
pub mod responder;
pub mod sa_manager;

use crate::{QuantumIpsecError, Result};
use serde::{Deserialize, Serialize};
use std::time::Instant;
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use std::io::Cursor;

/// Session state for IKEv2 negotiations
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum SessionState {
    Initial,
    SAInit,
    Auth,
    Established,
    Failed,
    None,
    InitCompleted,
    AuthCompleted,
}

/// IKEv2 message types
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ExchangeType {
    IKE_SA_INIT,
    IKE_AUTH,
    CREATE_CHILD_SA,
    IKE_SA_INIT_REQ = 34,
    IKE_SA_INIT_RESP = 35,
    CREATE_CHILD_SA_REQ = 36,
    CREATE_CHILD_SA_RESP = 37,
    INFORMATIONAL_REQ = 38,
    IKE_AUTH_REQ = 39,
    IKE_AUTH_RESP = 40,
    INFORMATIONAL_RESP = 41,
}

/// IKEv2 header structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IkeHeader {
    pub initiator_spi: u64,
    pub responder_spi: u64,
    pub next_payload: u8,
    pub major_version: u8,
    pub minor_version: u8,
    pub exchange_type: u8,
    pub flags: u8,
    pub message_id: u32,
    pub length: u32,
}

/// IKEv2 processor
pub struct IkeProcessor {
    /// Session state
    pub state: SessionState,
    /// Debug context
    pub debug: debug::DebugContext,
    /// SA manager
    pub sa_manager: sa_manager::SAManager,
}

impl IkeProcessor {
    /// Create a new IKE processor
    pub fn new() -> Result<Self> {
        Ok(Self {
            state: SessionState::Initial,
            debug: debug::DebugContext::new(debug::DebugLevel::Basic),
            sa_manager: sa_manager::SAManager::new(),
        })
    }
    
    /// Get current session state
    pub fn state(&self) -> SessionState {
        self.state
    }
    
    /// Set session state
    pub fn set_state(&mut self, state: SessionState) {
        self.state = state;
        self.debug.set_session_state(state);
    }
}

/// IKEv2 Security Association
#[derive(Debug, Clone)]
pub struct IkeSa {
    /// Initiator SPI
    pub initiator_spi: u64,
    /// Responder SPI
    pub responder_spi: u64,
    /// Is this the initiator?
    pub is_initiator: bool,
    /// Current state
    pub state: IkeState,
    /// Exchange type
    pub exchange_type: ExchangeType,
    /// Message ID
    pub message_id: u32,
    /// Session keys
    pub session_keys: Option<SessionKeys>,
    /// Creation time
    pub created: Instant,
    /// Last activity
    pub last_activity: Instant,
}

/// IKEv2 states
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum IkeState {
    /// Initial state
    Init,
    /// IKE_SA_INIT completed
    IkeSaInit,
    /// IKE_AUTH completed
    IkeAuth,
    /// CHILD_SA created
    ChildSa,
    /// Established
    Established,
    /// Failed
    Failed,
}

/// Session keys
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionKeys {
    /// Encryption key
    pub enc_key: Vec<u8>,
    /// Authentication key
    pub auth_key: Vec<u8>,
    /// Integrity key
    pub integrity_key: Vec<u8>,
}

impl IkeProcessor {
    /// Handle IKE_SA_INIT exchange
    pub fn ike_sa_init(initiator: bool) -> Result<IkeSa> {
        let mut sa = IkeSa {
            initiator_spi: 0,
            responder_spi: 0,
            is_initiator: initiator,
            state: IkeState::Init,
            exchange_type: ExchangeType::IKE_SA_INIT_REQ,
            message_id: 0,
            session_keys: None,
            created: Instant::now(),
            last_activity: Instant::now(),
        };

        if initiator {
            let mut initiator = Initiator::new()?;
            let mut responder = Responder::new()?;
            
            // IKE_SA_INIT exchange
            let init_request = initiator.initiate_sa_init()?;
            let init_response = responder.handle_sa_init(init_request)?;
            initiator.handle_sa_init_response(init_response)?;
            
            sa.initiator_spi = initiator.spi();
            sa.responder_spi = responder.spi();
            sa.state = IkeState::IkeSaInit;
            sa.exchange_type = ExchangeType::IKE_SA_INIT_RESP;
            sa.message_id = 0;
            sa.session_keys = Some(initiator.session_keys());
        } else {
            let mut responder = Responder::new()?;
            let mut initiator = Initiator::new()?;
            
            // IKE_SA_INIT exchange (responder side)
            let init_request = IkeMessage::new(0, 0, crate::ike::exchange::ExchangeType::IKE_SA_INIT, 1);
            let init_response = responder.handle_sa_init(init_request)?;
            
            sa.initiator_spi = 0;
            sa.responder_spi = 0;
            sa.state = IkeState::IkeSaInit;
            sa.exchange_type = ExchangeType::IKE_SA_INIT_RESP;
            sa.message_id = 0;
            sa.session_keys = Some(SessionKeys {
                enc_key: vec![0u8; 32],
                auth_key: vec![0u8; 32],
                integrity_key: vec![0u8; 32],
            });
        }

        Ok(sa)
    }

    /// Handle IKE_AUTH exchange
    pub fn ike_auth(sa: &mut IkeSa) -> Result<()> {
        sa.exchange_type = ExchangeType::IKE_AUTH_REQ;
        sa.last_activity = Instant::now();

        if sa.is_initiator {
            let mut initiator = Initiator::new()?;
            let mut responder = Responder::new()?;
            
            // IKE_AUTH exchange
            let auth_request = initiator.initiate_auth()?;
            let auth_response = responder.handle_auth(auth_request)?;
            
            sa.state = IkeState::IkeAuth;
            sa.exchange_type = ExchangeType::IKE_AUTH_RESP;
            sa.message_id = 0;
            sa.session_keys = Some(responder.session_keys());
        } else {
            let mut responder = Responder::new()?;
            
            // IKE_AUTH exchange (responder side)
            let auth_request = IkeMessage::new(0, 0, crate::ike::exchange::ExchangeType::IKE_AUTH, 2);
            let auth_response = responder.handle_auth(auth_request)?;
            
            sa.state = IkeState::IkeAuth;
            sa.exchange_type = ExchangeType::IKE_AUTH_RESP;
            sa.message_id = 0;
            sa.session_keys = Some(responder.session_keys());
        }

        Ok(())
    }

    /// Handle CREATE_CHILD_SA exchange
    pub fn create_child_sa(sa: &mut IkeSa) -> Result<()> {
        sa.exchange_type = ExchangeType::CREATE_CHILD_SA_REQ;
        sa.last_activity = Instant::now();

        // Simplified implementation
        Ok(())
    }

    /// Handle INFORMATIONAL exchange
    pub fn handle_informational(sa: &mut IkeSa) -> Result<()> {
        sa.exchange_type = ExchangeType::INFORMATIONAL_REQ;
        sa.last_activity = Instant::now();

        // Simplified implementation
        Ok(())
    }
}

/// IKEv2 message encoding/decoding
pub mod encoding {
    use super::*;
    use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};

    /// Encode IKE message to bytes
    pub fn encode_message(header: &IkeHeader, payloads: &[u8]) -> Result<Vec<u8>> {
        let mut buffer = Vec::new();
        
        buffer.write_u64::<BigEndian>(header.initiator_spi)
            .map_err(|e| QuantumIpsecError::PacketError(format!("IO error: {}", e)))?;
        buffer.write_u64::<BigEndian>(header.responder_spi)
            .map_err(|e| QuantumIpsecError::PacketError(format!("IO error: {}", e)))?;
        buffer.write_u8(header.next_payload)
            .map_err(|e| QuantumIpsecError::PacketError(format!("IO error: {}", e)))?;
        buffer.write_u8(header.major_version)
            .map_err(|e| QuantumIpsecError::PacketError(format!("IO error: {}", e)))?;
        buffer.write_u8(header.minor_version)
            .map_err(|e| QuantumIpsecError::PacketError(format!("IO error: {}", e)))?;
        buffer.write_u8(header.exchange_type)
            .map_err(|e| QuantumIpsecError::PacketError(format!("IO error: {}", e)))?;
        buffer.write_u8(header.flags)
            .map_err(|e| QuantumIpsecError::PacketError(format!("IO error: {}", e)))?;
        buffer.write_u32::<BigEndian>(header.message_id)
            .map_err(|e| QuantumIpsecError::PacketError(format!("IO error: {}", e)))?;
        buffer.write_u32::<BigEndian>(header.length)
            .map_err(|e| QuantumIpsecError::PacketError(format!("IO error: {}", e)))?;
        
        buffer.extend_from_slice(payloads);
        
        Ok(buffer)
    }

    /// Decode IKE message from bytes
    pub fn decode_message(data: &[u8]) -> Result<(IkeHeader, Vec<u8>)> {
        if data.len() < 28 {
            return Err(QuantumIpsecError::PacketError("IKE message too short".into()));
        }
        
        let mut cursor = Cursor::new(data);
        
        // Parse IKE header
        let initiator_spi = cursor.read_u64::<BigEndian>()
            .map_err(|e| QuantumIpsecError::PacketError(format!("IO error: {}", e)))?;
        let responder_spi = cursor.read_u64::<BigEndian>()
            .map_err(|e| QuantumIpsecError::PacketError(format!("IO error: {}", e)))?;
        let next_payload = cursor.read_u8()
            .map_err(|e| QuantumIpsecError::PacketError(format!("IO error: {}", e)))?;
        let version = cursor.read_u8()
            .map_err(|e| QuantumIpsecError::PacketError(format!("IO error: {}", e)))?;
        let exchange_type = cursor.read_u8()
            .map_err(|e| QuantumIpsecError::PacketError(format!("IO error: {}", e)))?;
        let flags = cursor.read_u8()
            .map_err(|e| QuantumIpsecError::PacketError(format!("IO error: {}", e)))?;
        let message_id = cursor.read_u32::<BigEndian>()
            .map_err(|e| QuantumIpsecError::PacketError(format!("IO error: {}", e)))?;
        let length = cursor.read_u32::<BigEndian>()
            .map_err(|e| QuantumIpsecError::PacketError(format!("IO error: {}", e)))?;
        
        let header = IkeHeader {
            initiator_spi,
            responder_spi,
            next_payload,
            major_version: version,
            minor_version: 0,
            exchange_type,
            flags,
            message_id,
            length,
        };
        
        // Extract payload
        let payload = data[28..].to_vec();
        
        Ok((header, payload))
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

// Re-export main types
pub use crypto_adapter::CryptoAdapter;
pub use debug::{DebugContext, DebugLevel};
pub use exchange::{IkeMessage, ExchangeType as ExchangeTypeDetail};
pub use initiator::Initiator;
pub use responder::Responder;
pub use sa_manager::SAManager; 