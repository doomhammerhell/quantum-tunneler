//! Authentication Header (AH) implementation with post-quantum cryptography.
//!
//! This module provides AH packet processing using Dilithium for authentication.

use crate::{QuantumIpsecError, Result};
use crate::crypto::dilithium::{Dilithium3, DilithiumSignature, DilithiumPublicKey, DILITHIUM_SIGNATUREBYTES};
use crate::crypto::traits::DigitalSignature;
use crate::ipsec::sa::SecurityAssociation;
use crate::ipsec::utils::IpHeader;
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use heapless::Vec as HVec;
use std::io::Cursor;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

/// AH header structure according to RFC 4302
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AhHeader {
    /// Next header protocol
    pub next_header: u8,
    /// Payload length in 32-bit words minus 2
    pub payload_len: u8,
    /// Reserved field (must be zero)
    pub reserved: u16,
    /// Security Parameters Index
    pub spi: u32,
    /// Sequence number for replay protection
    pub sequence: u32,
    pub icv: Option<Vec<u8>>,
}

/// AH packet structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AhPacket {
    /// AH header
    pub header: AhHeader,
    /// Original packet payload
    pub payload: Vec<u8>,
}

/// AH processor for quantum-safe packet authentication
pub struct AhProcessor {
    /// Dilithium key pair for authentication
    dilithium_pk: <Dilithium3 as DigitalSignature>::PublicKey,
    dilithium_sk: <Dilithium3 as DigitalSignature>::SecretKey,
    /// Sequence number counter
    sequence_counter: u32,
}

impl AhProcessor {
    /// Create a new AH processor with fresh Dilithium key pair
    pub fn new() -> Result<Self> {
        let (dilithium_pk, dilithium_sk) = Dilithium3::keygen();
        
        Ok(Self {
            dilithium_pk,
            dilithium_sk,
            sequence_counter: 0,
        })
    }

    /// Create AH processor from existing Dilithium keys
    pub fn from_keys(
        dilithium_pk: <Dilithium3 as DigitalSignature>::PublicKey,
        dilithium_sk: <Dilithium3 as DigitalSignature>::SecretKey,
    ) -> Self {
        Self {
            dilithium_pk,
            dilithium_sk,
            sequence_counter: 0,
        }
    }

    /// Get the public key for verification
    pub fn get_public_key(&self) -> DilithiumPublicKey {
        self.dilithium_pk.clone()
    }

    /// Process outgoing packet with AH authentication
    pub fn process_outgoing(
        &mut self,
        payload: &[u8],
        spi: u32,
        next_header: u8,
    ) -> Result<AhPacket> {
        // Generate sequence number
        self.sequence_counter = self.sequence_counter.wrapping_add(1);
        
        // Create AH header
        let header = AhHeader {
            next_header,
            payload_len: 0, // Will be calculated
            reserved: 0,
            spi,
            sequence: self.sequence_counter,
            icv: None,
        };

        // Create packet
        let mut packet = AhPacket {
            header,
            payload: payload.to_vec(),
        };

        // Calculate payload length (in 32-bit words minus 2)
        let icv = self.compute_icv(&packet)?;
        packet.header.icv = Some(icv.clone());
        packet.header.payload_len = ((icv.len() + 8) / 4 - 2) as u8;

        Ok(packet)
    }

    /// Process incoming packet with AH authentication
    pub fn process_incoming(&self, packet: &AhPacket) -> Result<Vec<u8>> {
        // Verify authentication
        if !self.verify_packet(packet)? {
            return Err(QuantumIpsecError::AuthError("AH packet authentication failed".into()));
        }

        // Return original payload
        Ok(packet.payload.clone())
    }

    /// Serialize AH packet to bytes
    pub fn serialize_packet(&self, packet: &AhPacket) -> Result<Vec<u8>> {
        let mut buffer = Vec::new();
        
        // Write AH header
        buffer.write_u8(packet.header.next_header)
            .map_err(|e| QuantumIpsecError::PacketError(format!("IO error: {}", e)))?;
        buffer.write_u8(packet.header.payload_len)
            .map_err(|e| QuantumIpsecError::PacketError(format!("IO error: {}", e)))?;
        buffer.write_u16::<BigEndian>(packet.header.reserved)
            .map_err(|e| QuantumIpsecError::PacketError(format!("IO error: {}", e)))?;
        buffer.write_u32::<BigEndian>(packet.header.spi)
            .map_err(|e| QuantumIpsecError::PacketError(format!("IO error: {}", e)))?;
        buffer.write_u32::<BigEndian>(packet.header.sequence)
            .map_err(|e| QuantumIpsecError::PacketError(format!("IO error: {}", e)))?;
        
        // Write payload
        buffer.extend_from_slice(&packet.payload);
        
        // Write ICV
        if let Some(icv) = &packet.header.icv {
            buffer.extend_from_slice(icv);
        }
        
        Ok(buffer)
    }

    /// Deserialize AH packet from bytes
    pub fn deserialize_packet(&self, data: &[u8]) -> Result<AhPacket> {
        if data.len() < 12 {
            return Err(QuantumIpsecError::PacketError("AH packet too short".into()));
        }

        // Parse AH header
        let mut cursor = Cursor::new(data);
        let next_header = cursor.read_u8()
            .map_err(|e| QuantumIpsecError::PacketError(format!("IO error: {}", e)))?;
        let payload_len = cursor.read_u8()
            .map_err(|e| QuantumIpsecError::PacketError(format!("IO error: {}", e)))?;
        let reserved = cursor.read_u16::<BigEndian>()
            .map_err(|e| QuantumIpsecError::PacketError(format!("IO error: {}", e)))?;
        let spi = cursor.read_u32::<BigEndian>()
            .map_err(|e| QuantumIpsecError::PacketError(format!("IO error: {}", e)))?;
        let sequence = cursor.read_u32::<BigEndian>()
            .map_err(|e| QuantumIpsecError::PacketError(format!("IO error: {}", e)))?;
        
        let header = AhHeader {
            next_header,
            payload_len,
            reserved,
            spi,
            sequence,
            icv: None,
        };
        
        // Calculate payload size
        let total_len = ((payload_len as usize + 2) * 4) as usize;
        let icv_len = 1024; // ICV size
        let payload_len_actual = total_len - 12 - icv_len; // 12 = header size
        
        if data.len() < total_len {
            return Err(QuantumIpsecError::PacketError("AH packet incomplete".into()));
        }
        
        // Read payload
        let payload_start = 12;
        let payload_end = payload_start + payload_len_actual;
        let payload_data = &data[payload_start..payload_end];
        let payload = payload_data.to_vec();
        
        // Read ICV
        let icv_start = payload_end;
        let icv_end = icv_start + icv_len;
        let icv_data = &data[icv_start..icv_end];
        let icv = icv_data.to_vec();
        
        let mut header_with_icv = header;
        header_with_icv.icv = Some(icv);
        
        Ok(AhPacket {
            header: header_with_icv,
            payload,
        })
    }

    /// Compute ICV (Integrity Check Value) for packet
    fn compute_icv(&self, packet: &AhPacket) -> Result<Vec<u8>> {
        let mut message = Vec::new();
        
        // Include AH header fields (except ICV)
        message.write_u8(packet.header.next_header)
            .map_err(|e| QuantumIpsecError::PacketError(format!("IO error: {}", e)))?;
        message.write_u8(packet.header.payload_len)
            .map_err(|e| QuantumIpsecError::PacketError(format!("IO error: {}", e)))?;
        message.write_u16::<BigEndian>(packet.header.reserved)
            .map_err(|e| QuantumIpsecError::PacketError(format!("IO error: {}", e)))?;
        message.write_u32::<BigEndian>(packet.header.spi)
            .map_err(|e| QuantumIpsecError::PacketError(format!("IO error: {}", e)))?;
        message.write_u32::<BigEndian>(packet.header.sequence)
            .map_err(|e| QuantumIpsecError::PacketError(format!("IO error: {}", e)))?;
        
        // Include payload
        message.extend_from_slice(&packet.payload);
        
        // Sign with Dilithium
        let signature = Dilithium3::sign(&self.dilithium_sk, &message);
        Ok(signature.as_ref().to_vec())
    }

    /// Verify ICV for packet
    fn verify_icv(&self, packet: &AhPacket, icv: &[u8]) -> Result<bool> {
        let mut message = Vec::new();
        
        // Include AH header fields (except ICV)
        message.write_u8(packet.header.next_header)
            .map_err(|e| QuantumIpsecError::PacketError(format!("IO error: {}", e)))?;
        message.write_u8(packet.header.payload_len)
            .map_err(|e| QuantumIpsecError::PacketError(format!("IO error: {}", e)))?;
        message.write_u16::<BigEndian>(packet.header.reserved)
            .map_err(|e| QuantumIpsecError::PacketError(format!("IO error: {}", e)))?;
        message.write_u32::<BigEndian>(packet.header.spi)
            .map_err(|e| QuantumIpsecError::PacketError(format!("IO error: {}", e)))?;
        message.write_u32::<BigEndian>(packet.header.sequence)
            .map_err(|e| QuantumIpsecError::PacketError(format!("IO error: {}", e)))?;
        
        // Include payload
        message.extend_from_slice(&packet.payload);
        
        // Verify signature
        let signature_array: [u8; DILITHIUM_SIGNATUREBYTES] = icv.try_into()
            .map_err(|_| QuantumIpsecError::PacketError("Invalid ICV length".into()))?;
        let signature = DilithiumSignature::from(signature_array);
        
        Ok(Dilithium3::verify(&self.dilithium_pk, &message, &signature))
    }

    /// Verify packet authentication
    pub fn verify_packet(&self, packet: &AhPacket) -> Result<bool> {
        if let Some(icv) = &packet.header.icv {
            self.verify_icv(packet, icv)
        } else {
            Ok(false)
        }
    }

    /// Get current sequence number
    pub fn get_sequence_number(&self) -> u32 {
        self.sequence_counter
    }

    /// Set sequence number (for testing)
    pub fn set_sequence_number(&mut self, sequence: u32) {
        self.sequence_counter = sequence;
    }
}

/// High-level functions for AH packet processing
pub fn compute_auth(sa: &SecurityAssociation, header: &IpHeader, payload: &[u8]) -> Vec<u8> {
    let mut processor = AhProcessor::new().expect("Failed to create AH processor");
    let mut message = Vec::new();
    
    // Include IP header and payload
    match header.source {
        IpAddr::V4(addr) => message.extend_from_slice(&addr.octets()),
        IpAddr::V6(_) => message.extend_from_slice(&[0u8; 4]), // IPv6 not supported
    }
    match header.destination {
        IpAddr::V4(addr) => message.extend_from_slice(&addr.octets()),
        IpAddr::V6(_) => message.extend_from_slice(&[0u8; 4]), // IPv6 not supported
    }
    message.extend_from_slice(payload);
    
    // Sign with Dilithium
    let signature = Dilithium3::sign(&sa.get_auth_secret_key(), &message);
    signature.as_ref().to_vec()
}

pub fn verify_auth(sa: &SecurityAssociation, header: &IpHeader, payload: &[u8], tag: &[u8]) -> bool {
    let mut message = Vec::new();
    
    // Include IP header and payload
    match header.source {
        IpAddr::V4(addr) => message.extend_from_slice(&addr.octets()),
        IpAddr::V6(_) => message.extend_from_slice(&[0u8; 4]), // IPv6 not supported
    }
    match header.destination {
        IpAddr::V4(addr) => message.extend_from_slice(&addr.octets()),
        IpAddr::V6(_) => message.extend_from_slice(&[0u8; 4]), // IPv6 not supported
    }
    message.extend_from_slice(payload);
    
    // Verify signature
    let signature_array: [u8; DILITHIUM_SIGNATUREBYTES] = tag.try_into().unwrap_or([0; DILITHIUM_SIGNATUREBYTES]);
    let signature = DilithiumSignature::from(signature_array);
    
    Dilithium3::verify(&sa.get_auth_public_key(), &message, &signature)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ah_round_trip() {
        let mut processor = AhProcessor::new().unwrap();
        let payload = b"Hello, quantum world!";
        let spi = 12345;

        // Process outgoing
        let packet = processor.process_outgoing(payload, spi, 6).unwrap();

        // Process incoming
        let result = processor.process_incoming(&packet).unwrap();

        assert_eq!(payload, result.as_slice());
    }

    #[test]
    fn test_ah_authentication_failure() {
        let mut processor = AhProcessor::new().unwrap();
        let payload = b"Hello, quantum world!";
        let spi = 12345;

        // Process outgoing
        let mut packet = processor.process_outgoing(payload, spi, 6).unwrap();

        // Tamper with payload
        packet.payload[0] ^= 1;

        // Process incoming should fail
        let result = processor.process_incoming(&packet);
        assert!(result.is_err());
    }
} 