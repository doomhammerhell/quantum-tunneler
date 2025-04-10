use crate::QuantumIpsecError;
use std::time::{SystemTime, UNIX_EPOCH};

/// Get current timestamp in seconds
pub fn get_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// Convert bytes to hex string
pub fn bytes_to_hex(bytes: &[u8]) -> String {
    bytes.iter()
        .map(|b| format!("{:02x}", b))
        .collect()
}

/// Convert hex string to bytes
pub fn hex_to_bytes(hex: &str) -> Result<Vec<u8>, QuantumIpsecError> {
    if hex.len() % 2 != 0 {
        return Err(QuantumIpsecError::InternalError("Invalid hex string length".into()));
    }

    (0..hex.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&hex[i..i + 2], 16)
                .map_err(|_| QuantumIpsecError::InternalError("Invalid hex character".into()))
        })
        .collect()
}

/// Generate a random SPI (Security Parameter Index)
pub fn generate_spi() -> u32 {
    let mut bytes = [0u8; 4];
    getrandom::getrandom(&mut bytes).unwrap();
    u32::from_be_bytes(bytes)
}

/// Calculate packet checksum
pub fn calculate_checksum(data: &[u8]) -> u16 {
    let mut sum = 0u32;
    let mut i = 0;

    while i < data.len() {
        let word = if i + 1 < data.len() {
            ((data[i] as u32) << 8) | (data[i + 1] as u32)
        } else {
            (data[i] as u32) << 8
        };
        sum = sum.wrapping_add(word);
        i += 2;
    }

    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }

    !(sum as u16)
}

/// Validate IP address
pub fn validate_ip_address(addr: &str) -> Result<(), QuantumIpsecError> {
    if addr.parse::<std::net::IpAddr>().is_err() {
        return Err(QuantumIpsecError::ConfigError("Invalid IP address".into()));
    }
    Ok(())
}

/// Validate port number
pub fn validate_port(port: u16) -> Result<(), QuantumIpsecError> {
    if port == 0 {
        return Err(QuantumIpsecError::ConfigError("Invalid port number".into()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bytes_to_hex() {
        let bytes = [0x12, 0x34, 0x56, 0x78];
        assert_eq!(bytes_to_hex(&bytes), "12345678");
    }

    #[test]
    fn test_hex_to_bytes() {
        let hex = "12345678";
        let bytes = hex_to_bytes(hex).unwrap();
        assert_eq!(bytes, vec![0x12, 0x34, 0x56, 0x78]);
    }

    #[test]
    fn test_validate_ip_address() {
        assert!(validate_ip_address("192.168.1.1").is_ok());
        assert!(validate_ip_address("::1").is_ok());
        assert!(validate_ip_address("invalid").is_err());
    }

    #[test]
    fn test_validate_port() {
        assert!(validate_port(80).is_ok());
        assert!(validate_port(0).is_err());
    }
} 