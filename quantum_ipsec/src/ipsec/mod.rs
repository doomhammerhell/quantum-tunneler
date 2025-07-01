//! Quantum-safe IPSec implementation.
//!
//! This module provides ESP and AH packet processing using post-quantum
//! cryptographic primitives (Kyber and Dilithium).

pub mod esp;
pub mod ah;
pub mod sa;
pub mod policy;
pub mod utils;

use crate::{QuantumIpsecError, Result};
use esp::{EspProcessor, EspPacket, EspMode};
use ah::{AhProcessor, AhPacket};
use sa::SecurityAssociationDatabase;
use policy::{SecurityPolicy, SecurityPolicyDatabase, PolicyAction};
use utils::{parse_ip_header, serialize_ip_header, IpHeader};
use std::net::{IpAddr, Ipv4Addr};
use byteorder::WriteBytesExt;
use rand;

/// Main IPSec processor that coordinates ESP, AH, SA, and policy management
pub struct IpSecProcessor {
    esp_processor: EspProcessor,
    ah_processor: AhProcessor,
    sad: SecurityAssociationDatabase,
    spd: SecurityPolicyDatabase,
    stats: IpSecStats,
}

/// IPSec statistics
#[derive(Debug, Default)]
pub struct IpSecStats {
    pub packets_processed: u64,
    pub esp_packets: u64,
    pub ah_packets: u64,
    pub auth_failures: u64,
    pub crypto_failures: u64,
    pub policy_matches: u64,
}

impl IpSecProcessor {
    /// Create a new IPSec processor
    pub fn new() -> Result<Self> {
        Ok(Self {
            esp_processor: EspProcessor::new()?,
            ah_processor: AhProcessor::new()?,
            sad: SecurityAssociationDatabase::new(1000),
            spd: SecurityPolicyDatabase::new(100),
            stats: IpSecStats::default(),
        })
    }

    /// Process outbound packet (encapsulation)
    pub fn process_outbound(
        &mut self,
        plaintext: &[u8],
        src: IpAddr,
        dst: IpAddr,
        protocol: u8,
        src_port: u16,
        dst_port: u16,
    ) -> Result<Vec<u8>> {
        self.stats.packets_processed += 1;

        // Check policy
        let policy = self.spd.find_matching_policy(src, dst, protocol, src_port, dst_port);
        
        match policy {
            Some(policy) => {
                self.stats.policy_matches += 1;
                match policy.action {
                    PolicyAction::Allow => Ok(plaintext.to_vec()),
                    PolicyAction::Require => self.encapsulate_packet(plaintext, src, dst),
                    PolicyAction::Block => Err(QuantumIpsecError::PacketError("Packet blocked by policy".into())),
                }
            }
            None => Err(QuantumIpsecError::PacketError("No matching policy found".into())),
        }
    }

    /// Process inbound packet (decapsulation)
    pub fn process_inbound(&mut self, packet: &[u8]) -> Result<Vec<u8>> {
        self.stats.packets_processed += 1;

        if packet.len() < 20 {
            return Err(QuantumIpsecError::PacketError("Packet too short".into()));
        }

        // Parse IP header
        let ip_header = parse_ip_header(packet)?;
        
        match ip_header.protocol {
            50 => self.decapsulate_esp_packet(packet), // ESP
            51 => self.decapsulate_ah_packet(packet),  // AH
            _ => Ok(packet.to_vec()), // Pass through
        }
    }

    /// Encapsulate packet with ESP
    fn encapsulate_packet(&mut self, plaintext: &[u8], src: IpAddr, dst: IpAddr) -> Result<Vec<u8>> {
        // Find or create SA
        let spi = self.get_or_create_sa(src, dst)?;
        let _sa = self.sad.get_sa_mut(spi)
            .ok_or_else(|| QuantumIpsecError::PacketError("SA not found".into()))?;

        // Encapsulate with ESP
        let esp_packet = self.esp_processor.encapsulate_packet(
            plaintext,
            spi,
            EspMode::Tunnel,
        )?;

        self.stats.esp_packets += 1;

        // Serialize ESP packet
        self.serialize_esp_packet(&esp_packet, src, dst)
    }

    /// Decapsulate ESP packet
    fn decapsulate_esp_packet(&mut self, packet: &[u8]) -> Result<Vec<u8>> {
        // Parse ESP header to get SPI
        let esp_header = utils::parse_esp_header(&packet[20..])?;
        
        // Find SA
        let _sa = self.sad.get_sa(esp_header.spi)
            .ok_or_else(|| QuantumIpsecError::PacketError("SA not found".into()))?;

        // Parse ESP packet
        let esp_packet = self.parse_esp_packet(packet)?;

        // Decapsulate
        let plaintext = self.esp_processor.decapsulate_packet(&esp_packet, EspMode::Tunnel)?;
        
        self.stats.esp_packets += 1;
        Ok(plaintext)
    }

    /// Decapsulate AH packet
    fn decapsulate_ah_packet(&mut self, packet: &[u8]) -> Result<Vec<u8>> {
        // Parse AH header to get SPI
        let ah_header = utils::parse_ah_header(&packet[20..])?;
        
        // Find SA
        let _sa = self.sad.get_sa(ah_header.spi)
            .ok_or_else(|| QuantumIpsecError::PacketError("SA not found".into()))?;

        // Parse AH packet
        let ah_packet = self.parse_ah_packet(packet)?;

        // Verify authentication
        if !self.ah_processor.verify_packet(&ah_packet)? {
            self.stats.auth_failures += 1;
            return Err(QuantumIpsecError::PacketError("AH authentication failed".into()));
        }

        // Extract payload
        let payload = ah_packet.payload.to_vec();
        
        self.stats.ah_packets += 1;
        Ok(payload)
    }

    /// Get or create Security Association
    fn get_or_create_sa(&mut self, src: IpAddr, dst: IpAddr) -> Result<u32> {
        // Try to find existing SA
        if let Some(sa) = self.sad.find_sa_by_addrs(src, dst, 50) {
            return Ok(sa.spi);
        }

        // Create new SA
        let spi = rand::random::<u32>();
        let sa = SecurityAssociation::new()?;
        self.sad.add_sa(sa)?;
        
        Ok(spi)
    }

    /// Serialize ESP packet to wire format
    fn serialize_esp_packet(&self, esp_packet: &EspPacket, src: IpAddr, dst: IpAddr) -> Result<Vec<u8>> {
        let mut buffer = Vec::new();

        // Create IP header
        let ip_header = IpHeader {
            version: 4,
            ihl: 5,
            tos: 0,
            total_length: (20 + esp_packet.payload.len()) as u16,
            identification: 0,
            flags: 0,
            fragment_offset: 0,
            ttl: 64,
            protocol: 50, // ESP
            checksum: 0,
            source: src,
            destination: dst,
        };

        // Serialize IP header
        let ip_bytes = serialize_ip_header(&ip_header)?;
        buffer.extend_from_slice(&ip_bytes);

        // Serialize ESP header
        buffer.write_u32::<byteorder::BigEndian>(esp_packet.header.spi)
            .map_err(|e| QuantumIpsecError::PacketError(format!("IO error: {}", e)))?;
        buffer.write_u32::<byteorder::BigEndian>(esp_packet.header.sequence)
            .map_err(|e| QuantumIpsecError::PacketError(format!("IO error: {}", e)))?;

        // Add IV if present
        if let Some(iv) = &esp_packet.header.iv {
            buffer.extend_from_slice(iv);
        }

        // Add payload
        buffer.extend_from_slice(&esp_packet.payload);

        // Add trailer
        buffer.push(esp_packet.trailer.pad_len);
        buffer.push(esp_packet.trailer.next_header);
        buffer.extend_from_slice(&esp_packet.trailer.padding);

        // Add authentication data
        if let Some(auth_data) = &esp_packet.auth_data {
            buffer.extend_from_slice(auth_data);
        }

        Ok(buffer)
    }

    /// Parse ESP packet from wire format
    fn parse_esp_packet(&self, data: &[u8]) -> Result<EspPacket> {
        if data.len() < 28 {
            return Err(QuantumIpsecError::PacketError("ESP packet too short".into()));
        }

        // Parse ESP header
        let spi = u32::from_be_bytes([data[20], data[21], data[22], data[23]]);
        let sequence = u32::from_be_bytes([data[24], data[25], data[26], data[27]]);

        // For simplicity, assume fixed sizes
        let iv_size = 16;
        let payload_start = 28 + iv_size;
        let payload_end = data.len() - 2 - 1024; // 2 bytes trailer + 1024 bytes auth

        if payload_end <= payload_start {
            return Err(QuantumIpsecError::PacketError("Invalid ESP packet structure".into()));
        }

        let payload = data[payload_start..payload_end].to_vec();
        let pad_len = data[payload_end];
        let next_header = data[payload_end + 1];

        Ok(EspPacket {
            header: esp::EspHeader {
                spi,
                sequence,
                iv: Some(data[28..28+iv_size].to_vec()),
            },
            payload: payload,
            trailer: esp::EspTrailer {
                pad_len,
                next_header,
                padding: data[payload_end+2..].to_vec(),
            },
            auth_data: Some(data[payload_end+2..].to_vec()),
        })
    }

    /// Parse AH packet from wire format
    fn parse_ah_packet(&self, data: &[u8]) -> Result<AhPacket> {
        if data.len() < 32 {
            return Err(QuantumIpsecError::PacketError("AH packet too short".into()));
        }

        // Parse AH header
        let next_header = data[20];
        let payload_len = data[21];
        let reserved = u16::from_be_bytes([data[22], data[23]]);
        let spi = u32::from_be_bytes([data[24], data[25], data[26], data[27]]);
        let sequence = u32::from_be_bytes([data[28], data[29], data[30], data[31]]);

        let payload_start = 32;
        let payload_end = data.len() - 1024; // 1024 bytes ICV

        if payload_end <= payload_start {
            return Err(QuantumIpsecError::PacketError("Invalid AH packet structure".into()));
        }

        let payload = data[payload_start..payload_end].to_vec();

        Ok(AhPacket {
            header: ah::AhHeader {
                next_header,
                payload_len,
                reserved,
                spi,
                sequence,
                icv: Some(data[payload_end..].to_vec()),
            },
            payload: payload,
        })
    }

    /// Convert IP string to IpAddr
    fn ip_to_addr(&self, ip: &str) -> IpAddr {
        ip.parse().unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED))
    }

    /// Convert IP string to bytes
    fn ip_to_bytes(&self, ip: &str) -> [u8; 4] {
        match self.ip_to_addr(ip) {
            IpAddr::V4(addr) => addr.octets(),
            IpAddr::V6(_) => [0, 0, 0, 0],
        }
    }

    /// Add policy to SPD
    pub fn add_policy(&mut self, policy: SecurityPolicy) -> Result<()> {
        self.spd.add_policy(policy)
    }

    /// Get statistics
    pub fn get_stats(&self) -> &IpSecStats {
        &self.stats
    }

    /// Clean up expired SAs
    pub fn cleanup(&mut self) -> usize {
        self.sad.cleanup_expired()
    }
}

pub use esp::{encrypt_packet, decrypt_packet};
pub use ah::{compute_auth, verify_auth};
pub use sa::new_kem_based;
pub use policy::{example_policy, add_policy};
pub use sa::SecurityAssociation; 