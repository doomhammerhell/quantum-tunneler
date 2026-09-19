//! Unidirectional RFC 4301-style traffic SAs. Keys cannot be mutated or cloned.
use super::replay::ReplayWindow;
use crate::{
    keying::{provenance::KeyProvenance, schedule::TrafficKey},
    QuantumIpsecError as Error, Result,
};
use serde::Serialize;
use std::{
    collections::{BTreeMap, BTreeSet},
    time::{Duration, Instant},
};
use zeroize::Zeroize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum EspCryptoSuite {
    Aes256Gcm,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum Direction {
    Inbound,
    Outbound,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum SaState {
    Active,
    Retiring,
    Retired,
}
#[derive(Debug, Clone, Copy)]
pub struct SaLifetime {
    pub max_age: Duration,
    pub max_packets: u64,
    pub max_bytes: u64,
    pub rekey_after_packets: u64,
}
impl Default for SaLifetime {
    fn default() -> Self {
        Self {
            max_age: Duration::from_secs(300),
            max_packets: 1_000_000,
            max_bytes: 1 << 30,
            rekey_after_packets: 900_000,
        }
    }
}
#[derive(Debug, Serialize)]
pub struct SaMetadata<'a> {
    pub spi: u32,
    pub direction: Direction,
    pub crypto_suite: EspCryptoSuite,
    pub state: SaState,
    pub provenance: &'a KeyProvenance,
    pub packets: u64,
    pub bytes: u64,
    pub expired: bool,
    pub needs_rekey: bool,
}
pub struct SecurityAssociation {
    spi: u32,
    direction: Direction,
    sequence: u32,
    pub(crate) traffic_key: TrafficKey,
    pub(crate) replay: ReplayWindow,
    lifetime: SaLifetime,
    provenance: KeyProvenance,
    created: Instant,
    state: SaState,
    packets: u64,
    bytes: u64,
}
impl std::fmt::Debug for SecurityAssociation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.metadata().fmt(f)
    }
}
impl SecurityAssociation {
    /// Used internally for authenticated IKE CHILD_SAs; external laboratory
    /// integrations must authenticate their own provisioning context.
    /// Never reinstall identical key material with a reset packet counter.
    pub fn new(
        spi: u32,
        direction: Direction,
        traffic_key: TrafficKey,
        lifetime: SaLifetime,
        provenance: KeyProvenance,
    ) -> Result<Self> {
        if spi != traffic_key.spi
            || provenance != traffic_key.provenance
            || spi < 256
            || lifetime.max_age.is_zero()
            || lifetime.max_packets == 0
            || lifetime.max_packets > u32::MAX as u64
            || lifetime.max_bytes == 0
            || lifetime.rekey_after_packets == 0
            || lifetime.rekey_after_packets > lifetime.max_packets
            || provenance.generation == 0
        {
            return Err(Error::ConfigError("invalid SA parameters".into()));
        }
        Ok(Self {
            spi,
            direction,
            traffic_key,
            lifetime,
            provenance,
            sequence: 0,
            replay: ReplayWindow::default(),
            created: Instant::now(),
            state: SaState::Active,
            packets: 0,
            bytes: 0,
        })
    }
    pub fn spi(&self) -> u32 {
        self.spi
    }
    pub fn generation(&self) -> u64 {
        self.provenance.generation
    }
    pub fn direction(&self) -> Direction {
        self.direction
    }
    pub fn is_expired(&self) -> bool {
        self.state == SaState::Retired
            || self.created.elapsed() >= self.lifetime.max_age
            || self.packets >= self.lifetime.max_packets
            || self.bytes >= self.lifetime.max_bytes
    }
    pub fn needs_rekey(&self) -> bool {
        self.is_expired()
            || self.state != SaState::Active
            || self.packets >= self.lifetime.rekey_after_packets
            || self.sequence >= u32::MAX - 1024
            || self.created.elapsed() >= (self.lifetime.max_age - self.lifetime.max_age / 5)
            || self.bytes >= self.lifetime.max_bytes - self.lifetime.max_bytes / 5
    }
    pub fn retire(&mut self) {
        self.state = SaState::Retired;
        self.traffic_key.key.zeroize();
        self.traffic_key.salt.zeroize();
    }
    pub(crate) fn retiring(&mut self) {
        // Retirement is monotonic. Never reactivate a zeroized SA.
        if self.state == SaState::Active {
            self.state = SaState::Retiring;
            if self.direction == Direction::Outbound {
                self.traffic_key.key.zeroize();
                self.traffic_key.salt.zeroize();
            }
        }
    }
    pub(crate) fn check_use(&self, direction: Direction, bytes: usize) -> Result<()> {
        if self.direction != direction {
            return Err(Error::UnknownSa);
        }
        if self.is_expired()
            || (direction == Direction::Outbound && self.state != SaState::Active)
            || bytes as u64 > self.lifetime.max_bytes.saturating_sub(self.bytes)
        {
            return Err(Error::SaExpired);
        }
        Ok(())
    }
    pub(crate) fn reserve_sequence(&mut self) -> Result<u32> {
        self.sequence = self
            .sequence
            .checked_add(1)
            .ok_or(Error::SequenceExhausted)?;
        Ok(self.sequence)
    }
    pub(crate) fn account(&mut self, bytes: usize) {
        self.packets += 1;
        self.bytes += bytes as u64;
    }
    pub fn metadata(&self) -> SaMetadata<'_> {
        SaMetadata {
            spi: self.spi,
            direction: self.direction,
            crypto_suite: EspCryptoSuite::Aes256Gcm,
            state: self.state,
            provenance: &self.provenance,
            packets: self.packets,
            bytes: self.bytes,
            expired: self.is_expired(),
            needs_rekey: self.needs_rekey(),
        }
    }
}
/// Bounded SA storage. SPI tombstones prevent counter reset by reinstalling an
/// old SPI within this manager lifetime. Capacity is lifetime admissions; rotate
/// the runtime only with fresh keying context, never restore serialized SAs.
pub struct SecurityAssociationDatabase {
    sas: BTreeMap<u32, SecurityAssociation>,
    used_spis: BTreeSet<u32>,
    max_admissions: usize,
}
impl SecurityAssociationDatabase {
    pub fn new(max_admissions: usize) -> Self {
        Self {
            sas: BTreeMap::new(),
            used_spis: BTreeSet::new(),
            max_admissions,
        }
    }
    fn can_add(&self, sa: &SecurityAssociation) -> Result<()> {
        if self.used_spis.contains(&sa.spi) {
            return Err(Error::Duplicate);
        }
        if self.used_spis.len() >= self.max_admissions {
            return Err(Error::Capacity);
        }
        if sa.is_expired() {
            return Err(Error::SaExpired);
        }
        Ok(())
    }
    pub fn add_sa(&mut self, sa: SecurityAssociation) -> Result<()> {
        self.can_add(&sa)?;
        self.used_spis.insert(sa.spi);
        self.sas.insert(sa.spi, sa);
        Ok(())
    }
    /// New generation is admitted before retiring old outbound use. Old inbound
    /// may drain until its hard lifetime or explicit retirement. No key mutation.
    pub fn replace_generation(&mut self, old_spi: u32, new: SecurityAssociation) -> Result<()> {
        let old = self.sas.get(&old_spi).ok_or(Error::UnknownSa)?;
        if old.state != SaState::Active || old.is_expired() {
            return Err(Error::SaExpired);
        }
        if new.generation() <= old.generation()
            || new.direction != old.direction
            || new.provenance.session_id != old.provenance.session_id
        {
            return Err(Error::ConfigError("invalid rekey generation".into()));
        }
        self.can_add(&new)?;
        self.add_sa(new)?;
        if let Some(old) = self.sas.get_mut(&old_spi) {
            old.retiring();
        }
        Ok(())
    }
    pub fn get_sa(&self, spi: u32) -> Option<&SecurityAssociation> {
        self.sas.get(&spi)
    }
    pub fn get_sa_mut(&mut self, spi: u32) -> Option<&mut SecurityAssociation> {
        self.sas.get_mut(&spi)
    }
    pub fn remove_sa(&mut self, spi: u32) -> Option<SecurityAssociation> {
        self.sas.remove(&spi)
    }
    pub fn active_count(&self) -> usize {
        self.sas
            .values()
            .filter(|s| s.state == SaState::Active && !s.is_expired())
            .count()
    }
    pub fn metadata(&self) -> Vec<SaMetadata<'_>> {
        self.sas
            .values()
            .map(SecurityAssociation::metadata)
            .collect()
    }
    pub fn cleanup_expired(&mut self) -> usize {
        let before = self.sas.len();
        self.sas.retain(|_, sa| !sa.is_expired());
        before - self.sas.len()
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::secret::SecretBytes;
    use crate::keying::schedule::{derive_traffic_keys, KeyContext};
    #[test]
    fn no_counter_wrap() {
        let c = KeyContext {
            initiator_spi: 256,
            responder_spi: 257,
            session_id: [1; 32],
            transcript_hash: [2; 32],
            generation: 1,
        };
        let (keys, p) = derive_traffic_keys(SecretBytes::new([3; 32]), &c).unwrap();
        let mut sa = SecurityAssociation::new(
            257,
            Direction::Outbound,
            keys.initiator_to_responder,
            SaLifetime::default(),
            p,
        )
        .unwrap();
        sa.sequence = u32::MAX - 1;
        assert_eq!(sa.reserve_sequence().unwrap(), u32::MAX);
        assert_eq!(sa.reserve_sequence(), Err(Error::SequenceExhausted));
        assert_eq!(sa.sequence, u32::MAX);
    }
}
