//! Utility functions for IPSec packet processing
//! 
//! This module provides helper functions for binary operations,
//! IP header parsing, and other utilities used by the IPSec modules.

use crate::{QuantumIpsecError, Result};
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use std::io::Cursor;
use std::net::{IpAddr, Ipv4Addr};

/// IP header structure
#[derive(Debug, Clone, PartialEq)]
pub struct IpHeader {
    pub version: u8,
    pub ihl: u8,
    pub tos: u8,
    pub total_length: u16,
    pub identification: u16,
    pub flags: u8,
    pub fragment_offset: u16,
    pub ttl: u8,
    pub protocol: u8,
    pub checksum: u16,
    pub source: IpAddr,
    pub destination: IpAddr,
}

/// Parse IP header from bytes
pub fn parse_ip_header(data: &[u8]) -> Result<IpHeader> {
    if data.len() < 20 {
        return Err(QuantumIpsecError::PacketError("IP header too short".into()));
    }
    
    let version = (data[0] >> 4) & 0x0F;
    let ihl = data[0] & 0x0F;
    let tos = data[1];
    let total_length = u16::from_be_bytes([data[2], data[3]]);
    let identification = u16::from_be_bytes([data[4], data[5]]);
    let flags = (data[6] >> 5) & 0x07;
    let fragment_offset = u16::from_be_bytes([data[6] & 0x1F, data[7]]);
    let ttl = data[8];
    let protocol = data[9];
    let checksum = u16::from_be_bytes([data[10], data[11]]);
    
    let source = if version == 4 {
        let src_bytes = [data[12], data[13], data[14], data[15]];
        IpAddr::V4(Ipv4Addr::from(src_bytes))
    } else {
        return Err(QuantumIpsecError::PacketError("IPv6 not supported".into()));
    };
    
    let destination = if version == 4 {
        let dst_bytes = [data[16], data[17], data[18], data[19]];
        IpAddr::V4(Ipv4Addr::from(dst_bytes))
    } else {
        return Err(QuantumIpsecError::PacketError("IPv6 not supported".into()));
    };
    
    Ok(IpHeader {
        version,
        ihl,
        tos,
        total_length,
        identification,
        flags,
        fragment_offset,
        ttl,
        protocol,
        checksum,
        source,
        destination,
    })
}

/// Serialize IP header to bytes
pub fn serialize_ip_header(header: &IpHeader) -> Result<Vec<u8>> {
    let mut data = Vec::with_capacity(20);
    
    data.push((header.version << 4) | (header.ihl & 0x0F));
    data.push(header.tos);
    data.extend_from_slice(&header.total_length.to_be_bytes());
    data.extend_from_slice(&header.identification.to_be_bytes());
    data.extend_from_slice(&((header.flags as u16) << 13 | header.fragment_offset).to_be_bytes());
    data.push(header.ttl);
    data.push(header.protocol);
    data.extend_from_slice(&header.checksum.to_be_bytes());
    
    match header.source {
        IpAddr::V4(addr) => data.extend_from_slice(&addr.octets()),
        IpAddr::V6(_) => return Err(QuantumIpsecError::PacketError("IPv6 not supported".into())),
    }
    
    match header.destination {
        IpAddr::V4(addr) => data.extend_from_slice(&addr.octets()),
        IpAddr::V6(_) => return Err(QuantumIpsecError::PacketError("IPv6 not supported".into())),
    }
    
    Ok(data)
}

/// Calculate IP header checksum
pub fn calculate_ip_checksum(header: &IpHeader) -> u16 {
    let mut sum = 0u32;
    
    // Add all 16-bit words
    sum += ((header.version << 4) | (header.ihl / 4) as u8) as u32;
    sum += header.tos as u32;
    sum += header.total_length as u32;
    sum += header.identification as u32;
    sum += header.flags as u32;
    sum += header.fragment_offset as u32;
    sum += (header.ttl as u32) << 8;
    sum += header.protocol as u32;
    
    // Add source and destination addresses
    match header.source {
        IpAddr::V4(addr) => {
            for i in 0..4 {
                sum += (addr.octets()[i] as u32) << 8;
            }
        },
        IpAddr::V6(_) => return 0, // IPv6 checksum not implemented
    }
    
    match header.destination {
        IpAddr::V4(addr) => {
            for i in 0..4 {
                sum += (addr.octets()[i] as u32) << 8;
            }
        },
        IpAddr::V6(_) => return 0, // IPv6 checksum not implemented
    }
    
    // Fold 32-bit sum to 16-bit
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    
    !sum as u16
}

/// ESP header structure
#[derive(Debug, Clone)]
pub struct EspHeader {
    pub spi: u32,
    pub sequence: u32,
    pub iv: Option<Vec<u8>>,
}

/// Parse ESP header from bytes
pub fn parse_esp_header(data: &[u8]) -> Result<EspHeader> {
    if data.len() < 8 {
        return Err(QuantumIpsecError::PacketError("ESP header too short".into()));
    }
    
    let mut cursor = Cursor::new(data);
    let spi = cursor.read_u32::<BigEndian>()
        .map_err(|e| QuantumIpsecError::PacketError(format!("IO error: {}", e)))?;
    let sequence = cursor.read_u32::<BigEndian>()
        .map_err(|e| QuantumIpsecError::PacketError(format!("IO error: {}", e)))?;
    
    Ok(EspHeader {
        spi,
        sequence,
        iv: None,
    })
}

/// Serialize ESP header to bytes
pub fn serialize_esp_header(header: &EspHeader) -> Result<Vec<u8>> {
    let mut buffer = Vec::with_capacity(8);
    buffer.write_u32::<BigEndian>(header.spi)
        .map_err(|e| QuantumIpsecError::PacketError(format!("IO error: {}", e)))?;
    buffer.write_u32::<BigEndian>(header.sequence)
        .map_err(|e| QuantumIpsecError::PacketError(format!("IO error: {}", e)))?;
    Ok(buffer)
}

/// AH header structure
#[derive(Debug, Clone)]
pub struct AhHeader {
    pub next_header: u8,
    pub payload_len: u8,
    pub reserved: u16,
    pub spi: u32,
    pub sequence: u32,
    pub icv: Option<Vec<u8>>,
}

/// Parse AH header from bytes
pub fn parse_ah_header(data: &[u8]) -> Result<AhHeader> {
    if data.len() < 12 {
        return Err(QuantumIpsecError::PacketError("AH header too short".into()));
    }
    
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
    
    Ok(AhHeader {
        next_header,
        payload_len,
        reserved,
        spi,
        sequence,
        icv: None,
    })
}

/// Serialize AH header to bytes
pub fn serialize_ah_header(header: &AhHeader) -> Result<Vec<u8>> {
    let mut buffer = Vec::with_capacity(12);
    buffer.write_u8(header.next_header)
        .map_err(|e| QuantumIpsecError::PacketError(format!("IO error: {}", e)))?;
    buffer.write_u8(header.payload_len)
        .map_err(|e| QuantumIpsecError::PacketError(format!("IO error: {}", e)))?;
    buffer.write_u16::<BigEndian>(header.reserved)
        .map_err(|e| QuantumIpsecError::PacketError(format!("IO error: {}", e)))?;
    buffer.write_u32::<BigEndian>(header.spi)
        .map_err(|e| QuantumIpsecError::PacketError(format!("IO error: {}", e)))?;
    buffer.write_u32::<BigEndian>(header.sequence)
        .map_err(|e| QuantumIpsecError::PacketError(format!("IO error: {}", e)))?;
    Ok(buffer)
}

/// Convert bytes to hex string
pub fn bytes_to_hex(bytes: &[u8]) -> String {
    bytes.iter()
        .map(|b| format!("{:02x}", b))
        .collect::<Vec<String>>()
        .join("")
}

/// Convert hex string to bytes
pub fn hex_to_bytes(hex: &str) -> Result<Vec<u8>> {
    if hex.len() % 2 != 0 {
        return Err(QuantumIpsecError::PacketError("Hex string must have even length".into()));
    }
    
    let mut bytes = Vec::with_capacity(hex.len() / 2);
    for i in (0..hex.len()).step_by(2) {
        let byte = u8::from_str_radix(&hex[i..i+2], 16)
            .map_err(|_| QuantumIpsecError::PacketError("Invalid hex string".into()))?;
        bytes.push(byte);
    }
    
    Ok(bytes)
}

/// Generate random bytes
pub fn random_bytes(len: usize) -> Result<Vec<u8>> {
    let mut bytes = vec![0u8; len];
    getrandom::getrandom(&mut bytes)
        .map_err(|_| QuantumIpsecError::PacketError("Failed to generate random bytes".into()))?;
    Ok(bytes)
}

/// XOR two byte arrays
pub fn xor_bytes(a: &[u8], b: &[u8]) -> Vec<u8> {
    a.iter().zip(b.iter()).map(|(x, y)| x ^ y).collect()
}

/// Constant-time comparison of byte arrays
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    
    let mut result = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        result |= x ^ y;
    }
    
    result == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_ip_header() {
        let data = [
            0x45, 0x00, 0x00, 0x28, 0x00, 0x00, 0x40, 0x00,
            0x40, 0x06, 0x00, 0x00, 0xc0, 0xa8, 0x01, 0x01,
            0xc0, 0xa8, 0x01, 0x02
        ];
        
        let header = parse_ip_header(&data).unwrap();
        assert_eq!(header.version, 4);
        assert_eq!(header.protocol, 6); // TCP
        assert_eq!(header.source, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));
        assert_eq!(header.destination, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2)));
    }

    #[test]
    fn test_hex_conversion() {
        let original = vec![0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef];
        let hex = bytes_to_hex(&original);
        let converted = hex_to_bytes(&hex).unwrap();
        
        assert_eq!(original, converted);
    }
} 