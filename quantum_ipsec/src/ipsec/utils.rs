//! Bounded IPv4 datagram inspection only; routing, options and reassembly absent.
use crate::{utils::calculate_checksum, QuantumIpsecError as Error, Result};
use std::net::Ipv4Addr;
#[derive(Debug, PartialEq, Eq)]
pub struct IpHeader {
    pub source: Ipv4Addr,
    pub destination: Ipv4Addr,
    pub protocol: u8,
    pub total_length: u16,
}
pub fn parse_ip_header(data: &[u8]) -> Result<IpHeader> {
    if data.len() < 20 || data.len() > 65535 {
        return Err(Error::PacketError("IPv4 size".into()));
    }
    if data[0] != 0x45 {
        return Err(Error::Unsupported("IPv6 or IPv4 options"));
    }
    let length = u16::from_be_bytes([data[2], data[3]]);
    if usize::from(length) != data.len() || calculate_checksum(&data[..20]) != 0 {
        return Err(Error::PacketError("IPv4 length or checksum".into()));
    }
    let flags_offset = u16::from_be_bytes([data[6], data[7]]);
    if flags_offset & 0xbfff != 0 {
        return Err(Error::Unsupported("IPv4 fragmentation or reserved flag"));
    }
    Ok(IpHeader {
        source: Ipv4Addr::new(data[12], data[13], data[14], data[15]),
        destination: Ipv4Addr::new(data[16], data[17], data[18], data[19]),
        protocol: data[9],
        total_length: length,
    })
}
pub use crate::utils::{bytes_to_hex, hex_to_bytes};
