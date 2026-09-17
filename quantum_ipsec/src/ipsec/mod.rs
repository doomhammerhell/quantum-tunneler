//! Explicit SPI dispatch for laboratory ESP. No implicit SA creation or routing.
pub mod esp;
pub mod policy;
pub mod replay;
pub mod sa;
pub mod utils;
use crate::{QuantumIpsecError as Error, Result};
use sa::{SecurityAssociation, SecurityAssociationDatabase};
use serde::Serialize;
#[derive(Debug, Default, Serialize)]
pub struct IpSecStats {
    pub esp_packets: u64,
    pub esp_bytes: u64,
    pub auth_failures: u64,
    pub replay_rejections: u64,
    pub invalid_packets: u64,
}
pub struct IpSecProcessor {
    sad: SecurityAssociationDatabase,
    stats: IpSecStats,
}
impl IpSecProcessor {
    pub fn new(max_sas: usize) -> Self {
        Self {
            sad: SecurityAssociationDatabase::new(max_sas),
            stats: IpSecStats::default(),
        }
    }
    pub fn install_sa(&mut self, sa: SecurityAssociation) -> Result<()> {
        self.sad.add_sa(sa)
    }
    pub fn replace_generation(&mut self, old_spi: u32, sa: SecurityAssociation) -> Result<()> {
        self.sad.replace_generation(old_spi, sa)
    }
    pub fn encrypt(&mut self, spi: u32, payload: &[u8], next_header: u8) -> Result<Vec<u8>> {
        let sa = self.sad.get_sa_mut(spi).ok_or(Error::UnknownSa)?;
        let out = esp::encrypt_packet(sa, payload, next_header)?;
        self.stats.esp_packets = self.stats.esp_packets.saturating_add(1);
        self.stats.esp_bytes = self.stats.esp_bytes.saturating_add(payload.len() as u64);
        Ok(out)
    }
    pub fn decrypt(&mut self, wire: &[u8]) -> Result<esp::Decapsulated> {
        let result = (|| {
            let p = esp::EspPacket::parse(wire)?;
            let sa = self.sad.get_sa_mut(p.header.spi).ok_or(Error::UnknownSa)?;
            esp::decrypt_packet(sa, wire)
        })();
        match &result {
            Ok(packet) => {
                self.stats.esp_packets = self.stats.esp_packets.saturating_add(1);
                self.stats.esp_bytes = self
                    .stats
                    .esp_bytes
                    .saturating_add(packet.payload.len() as u64);
            }
            Err(Error::Authentication) => {
                self.stats.auth_failures = self.stats.auth_failures.saturating_add(1)
            }
            Err(Error::Replay) => {
                self.stats.replay_rejections = self.stats.replay_rejections.saturating_add(1)
            }
            Err(_) => self.stats.invalid_packets = self.stats.invalid_packets.saturating_add(1),
        }
        result
    }
    pub fn get_stats(&self) -> &IpSecStats {
        &self.stats
    }
    pub fn sa_metadata(&self) -> Vec<sa::SaMetadata<'_>> {
        self.sad.metadata()
    }
    pub fn cleanup(&mut self) -> usize {
        self.sad.cleanup_expired()
    }
}
