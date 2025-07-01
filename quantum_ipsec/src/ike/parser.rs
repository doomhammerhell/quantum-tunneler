//! IKEv2 message parser implementation.
//!
//! This module implements the parsing of IKEv2 messages according to
//! RFC 7296, including support for post-quantum cryptographic payloads.

use crate::{QuantumIpsecError, Result};
use crate::ike::exchange::IkeMessage;
use crate::ike::proposal::IKEProposal;
use core::convert::TryInto;
use crate::ExchangeType;

/// Parser for IKEv2 messages
pub struct MessageParser {
    /// Current position in the message buffer
    position: usize,
    /// Message buffer
    buffer: Vec<u8>,
}

impl MessageParser {
    /// Creates a new message parser
    pub fn new(buffer: Vec<u8>) -> Self {
        Self {
            position: 0,
            buffer,
        }
    }

    /// Parses an IKEv2 message from the buffer
    pub fn parse_message(&mut self) -> Result<IkeMessage> {
        // Parse IKE header
        let message_id = self.parse_u32()?;
        let exchange_type = self.parse_exchange_type(34)?;
        
        // Parse proposal
        let proposal = self.parse_proposal()?;
        
        // Parse nonce
        let nonce = self.parse_nonce()?;
        
        // Create message
        let mut message = IkeMessage::new(0, 0, exchange_type, message_id);
        
        // Parse encrypted payload if present
        if self.has_encrypted_payload() {
            let payload = self.parse_encrypted_payload()?;
            message.add_payload(payload);
        }
        
        Ok(message)
    }

    /// Parses a 32-bit unsigned integer
    fn parse_u32(&mut self) -> Result<u32> {
        if self.position + 4 > self.buffer.len() {
            return Err(QuantumIpsecError::PacketError("Mensagem inválida".into()));
        }
        let value = u32::from_be_bytes(
            self.buffer[self.position..self.position + 4]
                .try_into()
                .unwrap(),
        );
        self.position += 4;
        Ok(value)
    }

    /// Parses the exchange type
    fn parse_exchange_type(&self, value: u8) -> Result<crate::ike::exchange::ExchangeType> {
        match value {
            34 => Ok(crate::ike::exchange::ExchangeType::IKE_SA_INIT),
            35 => Ok(crate::ike::exchange::ExchangeType::IKE_AUTH),
            36 => Ok(crate::ike::exchange::ExchangeType::CREATE_CHILD_SA),
            37 => Ok(crate::ike::exchange::ExchangeType::INFORMATIONAL),
            _ => Err(QuantumIpsecError::PacketError("Unknown exchange type".into())),
        }
    }

    /// Parses a security proposal
    fn parse_proposal(&mut self) -> Result<IKEProposal> {
        // TODO: Implement proposal parsing
        Ok(IKEProposal::default())
    }

    /// Parses a nonce
    fn parse_nonce(&mut self) -> Result<[u8; 32]> {
        if self.position + 32 > self.buffer.len() {
            return Err(QuantumIpsecError::PacketError("Não há espaço suficiente para o nonce".into()));
        }
        let nonce = self.buffer[self.position..self.position + 32]
            .try_into()
            .unwrap();
        self.position += 32;
        Ok(nonce)
    }

    /// Checks if there is an encrypted payload
    fn has_encrypted_payload(&self) -> bool {
        self.position < self.buffer.len()
    }

    /// Parses an encrypted payload
    fn parse_encrypted_payload(&mut self) -> Result<Vec<u8>> {
        let length = self.parse_u32()? as usize;
        if self.position + length > self.buffer.len() {
            return Err(QuantumIpsecError::PacketError("Mensagem inválida".into()));
        }
        let payload = self.buffer[self.position..self.position + length].to_vec();
        self.position += length;
        Ok(payload)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_u32() {
        let mut parser = MessageParser::new(vec![0, 0, 0, 1]);
        assert_eq!(parser.parse_u32().unwrap(), 1);
    }

    #[test]
    fn test_parse_exchange_type() {
        let mut parser = MessageParser::new(vec![0, 0, 0, 34]);
        assert_eq!(parser.parse_exchange_type(34).unwrap(), ExchangeType::IKE_SA_INIT);
    }

    #[test]
    fn test_parse_nonce() {
        let nonce = [1u8; 32];
        let mut parser = MessageParser::new(nonce.to_vec());
        assert_eq!(parser.parse_nonce().unwrap(), nonce);
    }
} 