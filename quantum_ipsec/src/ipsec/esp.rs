//! Encapsulating Security Payload (ESP) implementation with post-quantum cryptography.
//!
//! This module provides ESP packet processing using Kyber for key encapsulation
//! and Dilithium for authentication, with optional hybrid mode support.

use crate::{QuantumIpsecError, Result};
use crate::crypto::{
    kyber::Kyber512,
    dilithium::{Dilithium3, DilithiumSignature, DILITHIUM_SIGNATUREBYTES},
};
use crate::crypto::traits::{KeyEncapsulation, DigitalSignature};
use crate::ipsec::sa::SecurityAssociation;
use crate::ipsec::utils::IpHeader;
use byteorder::{BigEndian, WriteBytesExt};
use std::io::Cursor;
use serde::{Deserialize, Serialize};

/// ESP header structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EspHeader {
    pub spi: u32,
    pub sequence: u32,
    pub iv: Option<Vec<u8>>,
}

/// ESP trailer structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EspTrailer {
    pub pad_len: u8,
    pub next_header: u8,
    pub padding: Vec<u8>,
}

/// ESP packet structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EspPacket {
    pub header: EspHeader,
    pub payload: Vec<u8>,
    pub trailer: EspTrailer,
    pub auth_data: Option<Vec<u8>>,
}

/// ESP processor for quantum-safe packet encapsulation
pub struct EspProcessor {
    kyber_pk: <Kyber512 as KeyEncapsulation>::PublicKey,
    kyber_sk: <Kyber512 as KeyEncapsulation>::SecretKey,
    dilithium_pk: <Dilithium3 as DigitalSignature>::PublicKey,
    dilithium_sk: <Dilithium3 as DigitalSignature>::SecretKey,
    sequence_counter: u32,
}

impl EspProcessor {
    pub fn new() -> Result<Self> {
        let (kyber_pk, kyber_sk) = Kyber512::keygen();
        let (dilithium_pk, dilithium_sk) = Dilithium3::keygen();
        
        Ok(Self {
            kyber_pk,
            kyber_sk,
            dilithium_pk,
            dilithium_sk,
            sequence_counter: 0,
        })
    }

    pub fn encapsulate_packet(
        &mut self,
        plaintext: &[u8],
        spi: u32,
        mode: EspMode,
    ) -> Result<EspPacket> {
        self.sequence_counter = self.sequence_counter.wrapping_add(1);
        
        let header = EspHeader {
            spi,
            sequence: self.sequence_counter,
            iv: Some(self.generate_iv()),
        };

        let encrypted_payload = self.encrypt_payload(plaintext)?;
        let trailer = self.create_trailer(plaintext.len(), mode)?;

        let mut packet = EspPacket {
            header,
            payload: encrypted_payload,
            trailer,
            auth_data: None,
        };

        let auth_data = self.sign_packet(&packet)?;
        packet.auth_data = Some(auth_data);

        Ok(packet)
    }

    pub fn decapsulate_packet(
        &self,
        packet: &EspPacket,
        _mode: EspMode,
    ) -> Result<Vec<u8>> {
        if let Some(auth_data) = &packet.auth_data {
            if !self.verify_packet(packet, auth_data)? {
                return Err(QuantumIpsecError::AuthError("ESP packet authentication failed".into()));
            }
        }

        let decrypted_payload = self.decrypt_payload(&packet.payload)?;
        let pad_len = packet.trailer.pad_len as usize;
        
        if pad_len > decrypted_payload.len() {
            return Err(QuantumIpsecError::PacketError("Invalid padding length".into()));
        }

        let plaintext = decrypted_payload[..decrypted_payload.len() - pad_len].to_vec();
        Ok(plaintext)
    }

    fn generate_iv(&self) -> Vec<u8> {
        let mut iv = [0u8; 16];
        getrandom::getrandom(&mut iv).expect("Failed to generate IV");
        iv.to_vec()
    }

    fn encrypt_payload(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let (_, shared_secret) = Kyber512::encapsulate(&self.kyber_pk);
        let key = &shared_secret.as_ref()[..32];
        
        let mut encrypted = Vec::new();
        for (i, &byte) in plaintext.iter().enumerate() {
            encrypted.push(byte ^ key[i % 32]);
        }
        
        Ok(encrypted)
    }

    fn decrypt_payload(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        let (_, shared_secret) = Kyber512::encapsulate(&self.kyber_pk);
        let key = &shared_secret.as_ref()[..32];
        
        let mut decrypted = Vec::new();
        for (i, &byte) in ciphertext.iter().enumerate() {
            decrypted.push(byte ^ key[i % 32]);
        }
        
        Ok(decrypted)
    }

    fn create_trailer(&self, payload_len: usize, mode: EspMode) -> Result<EspTrailer> {
        let block_size = 16;
        let header_size = 8;
        let trailer_size = 2;
        
        let total_size = header_size + payload_len + trailer_size;
        let padding_needed = (block_size - (total_size % block_size)) % block_size;
        
        let mut padding = Vec::new();
        for i in 0..padding_needed {
            padding.push(i as u8);
        }
        
        Ok(EspTrailer {
            pad_len: padding_needed as u8,
            next_header: mode as u8,
            padding,
        })
    }

    fn sign_packet(&self, packet: &EspPacket) -> Result<Vec<u8>> {
        let mut message = Vec::new();
        
        message.write_u32::<BigEndian>(packet.header.spi)
            .map_err(|e| QuantumIpsecError::PacketError(format!("IO error: {}", e)))?;
        message.write_u32::<BigEndian>(packet.header.sequence)
            .map_err(|e| QuantumIpsecError::PacketError(format!("IO error: {}", e)))?;
        if let Some(iv) = &packet.header.iv {
            message.extend_from_slice(iv);
        }
        message.extend_from_slice(&packet.payload);
        message.write_u8(packet.trailer.pad_len)
            .map_err(|e| QuantumIpsecError::PacketError(format!("IO error: {}", e)))?;
        message.write_u8(packet.trailer.next_header)
            .map_err(|e| QuantumIpsecError::PacketError(format!("IO error: {}", e)))?;
        message.extend_from_slice(&packet.trailer.padding);
        
        let signature = Dilithium3::sign(&self.dilithium_sk, &message);
        Ok(signature.as_ref().to_vec())
    }

    fn verify_packet(&self, packet: &EspPacket, auth_data: &[u8]) -> Result<bool> {
        let mut message = Vec::new();
        
        message.write_u32::<BigEndian>(packet.header.spi)
            .map_err(|e| QuantumIpsecError::PacketError(format!("IO error: {}", e)))?;
        message.write_u32::<BigEndian>(packet.header.sequence)
            .map_err(|e| QuantumIpsecError::PacketError(format!("IO error: {}", e)))?;
        if let Some(iv) = &packet.header.iv {
            message.extend_from_slice(iv);
        }
        message.extend_from_slice(&packet.payload);
        message.write_u8(packet.trailer.pad_len)
            .map_err(|e| QuantumIpsecError::PacketError(format!("IO error: {}", e)))?;
        message.write_u8(packet.trailer.next_header)
            .map_err(|e| QuantumIpsecError::PacketError(format!("IO error: {}", e)))?;
        message.extend_from_slice(&packet.trailer.padding);
        
        let signature_array: [u8; DILITHIUM_SIGNATUREBYTES] = auth_data.try_into()
            .map_err(|_| QuantumIpsecError::PacketError("Invalid signature length".into()))?;
        let signature = DilithiumSignature::from(signature_array);
        
        Ok(Dilithium3::verify(&self.dilithium_pk, &message, &signature))
    }
}

/// ESP mode
#[derive(Debug, Clone, Copy)]
pub enum EspMode {
    Tunnel = 4,
    Transport = 6,
}

/// High-level functions for ESP packet processing
pub fn encrypt_packet(sa: &SecurityAssociation, plaintext: &[u8]) -> EspPacket {
    let mut processor = EspProcessor::new().expect("Failed to create ESP processor");
    
    // Create ESP packet
    let mut packet = EspPacket {
        header: EspHeader {
            spi: sa.spi,
            sequence: sa.sequence,
            iv: Some([0u8; 16].to_vec()),
        },
        payload: plaintext.to_vec(),
        trailer: EspTrailer {
            pad_len: 0,
            next_header: 6, // TCP
            padding: Vec::new(),
        },
        auth_data: None,
    };

    // Encrypt payload
    let encrypted = processor.encrypt_payload(plaintext).expect("Encryption failed");
    packet.payload = encrypted;

    // Sign packet
    let signature = processor.sign_packet(&packet).expect("Signing failed");
    packet.auth_data = Some(signature);

    packet
}

pub fn decrypt_packet(sa: &SecurityAssociation, packet: &EspPacket) -> Result<Vec<u8>> {
    let processor = EspProcessor::new()?;
    
    // Verify authentication
    if let Some(auth_data) = &packet.auth_data {
        if !processor.verify_packet(packet, auth_data)? {
            return Err(QuantumIpsecError::AuthError("ESP authentication failed".into()));
        }
    }

    // Decrypt payload
    let decrypted = processor.decrypt_payload(&packet.payload)?;
    Ok(decrypted)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_esp_round_trip() {
        let mut processor = EspProcessor::new().unwrap();
        let plaintext = b"Hello, quantum world!";
        let spi = 12345;

        // Encapsulate
        let packet = processor.encapsulate_packet(plaintext, spi, EspMode::Tunnel).unwrap();

        // Decapsulate
        let decrypted = processor.decapsulate_packet(&packet, EspMode::Tunnel).unwrap();

        assert_eq!(plaintext, decrypted.as_slice());
    }

    #[test]
    fn test_esp_authentication_failure() {
        let mut processor = EspProcessor::new().unwrap();
        let plaintext = b"Hello, quantum world!";
        let spi = 12345;

        // Encapsulate
        let mut packet = processor.encapsulate_packet(plaintext, spi, EspMode::Tunnel).unwrap();

        // Tamper with packet
        if let Some(auth_data) = &mut packet.auth_data {
            auth_data[0] ^= 1; // Flip one bit
        }

        // Decapsulate should fail
        let result = processor.decapsulate_packet(&packet, EspMode::Tunnel);
        assert!(result.is_err());
    }
}
