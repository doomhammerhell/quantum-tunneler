use crate::{QuantumIpsecError as Error, Result};
pub fn bytes_to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
pub fn hex_to_bytes(hex: &str) -> Result<Vec<u8>> {
    if !hex.len().is_multiple_of(2) || !hex.is_ascii() {
        return Err(Error::PacketError("invalid hex".into()));
    }
    hex.as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let hi = (pair[0] as char)
                .to_digit(16)
                .ok_or_else(|| Error::PacketError("invalid hex".into()))?;
            let lo = (pair[1] as char)
                .to_digit(16)
                .ok_or_else(|| Error::PacketError("invalid hex".into()))?;
            Ok((hi * 16 + lo) as u8)
        })
        .collect()
}
pub fn random_array<const N: usize>() -> Result<[u8; N]> {
    let mut out = [0; N];
    getrandom::getrandom(&mut out).map_err(|_| Error::Crypto)?;
    Ok(out)
}
pub fn calculate_checksum(data: &[u8]) -> u16 {
    let mut sum = 0u32;
    for pair in data.chunks(2) {
        let word = (u16::from(pair[0]) << 8) | u16::from(pair.get(1).copied().unwrap_or(0));
        sum += u32::from(word);
        sum = (sum & 0xffff) + (sum >> 16);
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}
