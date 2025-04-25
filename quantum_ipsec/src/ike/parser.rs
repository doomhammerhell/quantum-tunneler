//! IKEv2 message parser implementation.
//!
//! This module implements the parsing of IKEv2 messages according to
//! RFC 7296, including support for post-quantum cryptographic payloads.

use super::{IKEError, IKEResult, IKEMessage, ExchangeType, IKEProposal};
use core::convert::TryInto;

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
    pub fn parse_message(&mut self) -> IKEResult<IKEMessage> {
        // Parse IKE header
        let message_id = self.parse_u32()?;
        let exchange_type = self.parse_exchange_type()?;
        
        // Parse proposal
        let proposal = self.parse_proposal()?;
        
        // Parse nonce
        let nonce = self.parse_nonce()?;
        
        // Create message
        let mut message = IKEMessage::new(message_id, exchange_type, proposal, nonce);
        
        // Parse encrypted payload if present
        if self.has_encrypted_payload() {
            let payload = self.parse_encrypted_payload()?;
            message.add_encrypted_payload(payload);
        }
        
        Ok(message)
    }

    /// Parses a 32-bit unsigned integer
    fn parse_u32(&mut self) -> IKEResult<u32> {
        if self.position + 4 > self.buffer.len() {
            return Err(IKEError::InvalidMessage);
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
    fn parse_exchange_type(&mut self) -> IKEResult<ExchangeType> {
        let value = self.parse_u32()?;
        match value {
            34 => Ok(ExchangeType::SAInit),
            35 => Ok(ExchangeType::Auth),
            _ => Err(IKEError::InvalidMessage),
        }
    }

    /// Parses a security proposal
    fn parse_proposal(&mut self) -> IKEResult<IKEProposal> {
        // TODO: Implement proposal parsing
        Ok(IKEProposal::default())
    }

    /// Parses a nonce
    fn parse_nonce(&mut self) -> IKEResult<[u8; 32]> {
        if self.position + 32 > self.buffer.len() {
            return Err(IKEError::InvalidMessage);
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
    fn parse_encrypted_payload(&mut self) -> IKEResult<Vec<u8>> {
        let length = self.parse_u32()? as usize;
        if self.position + length > self.buffer.len() {
            return Err(IKEError::InvalidMessage);
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
        assert_eq!(parser.parse_exchange_type().unwrap(), ExchangeType::SAInit);
    }

    #[test]
    fn test_parse_nonce() {
        let nonce = [1u8; 32];
        let mut parser = MessageParser::new(nonce.to_vec());
        assert_eq!(parser.parse_nonce().unwrap(), nonce);
    }
} 