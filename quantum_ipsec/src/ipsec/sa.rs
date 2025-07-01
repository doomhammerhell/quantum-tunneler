//! Security Association (SA) management for IPSec
//!
//! This module provides Security Association creation, storage, and management
//! using post-quantum cryptographic primitives.

use crate::{QuantumIpsecError, Result};
use crate::crypto::{
    kyber::{Kyber512, KyberPublicKey, KyberSecretKey, KYBER_SSBYTES},
    dilithium::{Dilithium3, DilithiumPublicKey, DilithiumSecretKey, DilithiumSignature, DILITHIUM_SIGNATUREBYTES},
};
use crate::crypto::traits::DigitalSignature;
use heapless::Vec as HVec;
use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};
use serde::{Deserialize, Serialize};

/// Generate a random SPI (Security Parameters Index)
fn generate_spi() -> u32 {
    use rand_core::RngCore;
    let mut rng = rand_core::OsRng;
    rng.next_u32()
}

/// Sequence counter for replay protection
#[derive(Debug, Clone)]
pub struct SequenceCounter {
    current: u32,
    max_sequence: u32,
}

impl SequenceCounter {
    pub fn new() -> Self {
        Self {
            current: 0,
            max_sequence: u32::MAX,
        }
    }
    
    pub fn next(&mut self) -> Result<u32> {
        if self.current >= self.max_sequence {
            return Err(QuantumIpsecError::PacketError("Sequence number overflow".into()));
        }
        self.current += 1;
        Ok(self.current)
    }
    
    pub fn current(&self) -> u32 {
        self.current
    }
}

/// Security Association parameters
#[derive(Debug, Clone)]
pub struct SaParams {
    pub spi: u32,
    pub src_addr: IpAddr,
    pub dst_addr: IpAddr,
    pub protocol: IpSecProtocol,
    pub mode: SaMode,
    pub security_level: u32,
    pub enable_pqc: bool,
    pub hybrid_mode: bool,
}

/// IPSec protocol types
#[derive(Debug, Clone, Copy)]
pub enum IpSecProtocol {
    ESP = 50,
    AH = 51,
}

/// Security Association mode
#[derive(Debug, Clone, Copy)]
pub enum SaMode {
    Transport,
    Tunnel,
}

/// Security Association state
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityAssociation {
    /// Security Parameter Index
    pub spi: u32,
    /// Sequence number for replay protection
    pub sequence: u32,
    /// Maximum sequence number before rekeying
    pub max_sequence: u32,
    /// Kyber shared secret
    pub shared_secret: [u8; KYBER_SSBYTES],
    /// Authentication public key (Dilithium)
    pub auth_public_key: Vec<u8>,
    /// Authentication secret key (Dilithium)
    pub auth_secret_key: Vec<u8>,
    /// Nonce for symmetric encryption
    pub nonce: Vec<u8>,
    /// SA creation time
    pub created_at: u64,
    /// SA lifetime
    pub lifetime_secs: u64,
    /// Whether SA is active
    pub is_active: bool,
}

impl SecurityAssociation {
    /// Create a new SA with default parameters
    pub fn new() -> Result<Self> {
        let (auth_pk, auth_sk) = Dilithium3::keygen();
        
        Ok(Self {
            spi: generate_spi(),
            auth_public_key: auth_pk.0.to_vec(),
            auth_secret_key: auth_sk.0.to_vec(),
            shared_secret: [0u8; KYBER_SSBYTES],
            sequence: 0,
            created_at: std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs(),
            lifetime_secs: 3600, // 1 hour
            max_sequence: u32::MAX,
            nonce: vec![0u8; 32],
            is_active: true,
        })
    }

    /// Create SA from IKE-negotiated parameters
    pub fn from_ike_negotiation(
        spi: u32,
        shared_secret: [u8; KYBER_SSBYTES],
        auth_pk: Vec<u8>,
        auth_sk: Vec<u8>,
        lifetime_secs: u64,
    ) -> Self {
        let mut nonce = vec![0u8; 16];
        getrandom::getrandom(&mut nonce).expect("Failed to generate nonce");
        
        Self {
            spi,
            sequence: 0,
            max_sequence: u32::MAX,
            shared_secret,
            auth_public_key: auth_pk,
            auth_secret_key: auth_sk,
            nonce,
            created_at: std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs(),
            lifetime_secs,
            is_active: true,
        }
    }

    /// Get next sequence number
    pub fn next_sequence(&mut self) -> Result<u32> {
        if self.sequence >= self.max_sequence {
            return Err(QuantumIpsecError::PacketError("Sequence number overflow".into()));
        }
        self.sequence = self.sequence.wrapping_add(1);
        Ok(self.sequence)
    }

    /// Check if SA is expired
    pub fn is_expired(&self) -> bool {
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
        let diff = now.saturating_sub(self.created_at);
        diff > self.lifetime_secs
    }

    /// Check if SA is valid for use
    pub fn is_valid(&self) -> bool {
        self.is_active && !self.is_expired()
    }

    /// Derive symmetric key from shared secret
    pub fn derive_symmetric_key(&self, purpose: &str) -> Result<Vec<u8>> {
        let mut key_material = Vec::new();
        key_material.extend_from_slice(&self.shared_secret);
        key_material.extend_from_slice(purpose.as_bytes());
        key_material.extend_from_slice(&self.nonce);
        
        Ok(crate::crypto::hash::sha256(&key_material))
    }

    /// Sign data using Dilithium
    pub fn sign(&self, data: &[u8]) -> Result<Vec<u8>> {
        let signature = Dilithium3::sign(&self.get_auth_secret_key(), data);
        Ok(signature.as_ref().to_vec())
    }

    /// Verify signature using Dilithium
    pub fn verify(&self, data: &[u8], signature: &[u8]) -> bool {
        let signature_array: [u8; DILITHIUM_SIGNATUREBYTES] = signature.try_into()
            .unwrap_or([0; DILITHIUM_SIGNATUREBYTES]);
        let signature_obj = DilithiumSignature::from(signature_array);
        Dilithium3::verify(&self.get_auth_public_key(), data, &signature_obj)
    }

    /// Create a new SA using Kyber for key exchange and Dilithium for authentication
    pub fn new_kem_based(
        auth_pk: Vec<u8>,
        auth_sk: Vec<u8>,
        enc_pk: KyberPublicKey,
        _enc_sk: KyberSecretKey,
    ) -> Result<Self> {
        // Generate shared secret using Kyber
        let (_, shared_secret) = Kyber512::encapsulate(&enc_pk);
        let shared_secret_array: [u8; KYBER_SSBYTES] = shared_secret.as_ref().try_into()
            .map_err(|_| QuantumIpsecError::PacketError("Invalid shared secret size".into()))?;
        
        let mut nonce = vec![0u8; 16];
        getrandom::getrandom(&mut nonce).expect("Failed to generate nonce");
        
        Ok(Self {
            spi: generate_spi(),
            sequence: 0,
            max_sequence: u32::MAX,
            shared_secret: shared_secret_array,
            auth_public_key: auth_pk,
            auth_secret_key: auth_sk,
            nonce,
            created_at: std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs(),
            lifetime_secs: 3600,
            is_active: true,
        })
    }

    /// Get authentication public key
    pub fn get_auth_public_key(&self) -> <Dilithium3 as DigitalSignature>::PublicKey {
        use crate::crypto::dilithium::DilithiumPublicKey;
        DilithiumPublicKey(self.auth_public_key.as_slice().try_into().unwrap())
    }

    /// Get authentication secret key
    pub fn get_auth_secret_key(&self) -> <Dilithium3 as DigitalSignature>::SecretKey {
        use crate::crypto::dilithium::DilithiumSecretKey;
        DilithiumSecretKey(self.auth_secret_key.as_slice().try_into().unwrap())
    }

    /// Get SA creation time
    pub fn get_created_at(&self) -> std::time::Instant {
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
        let diff = now.saturating_sub(self.created_at);
        std::time::Instant::now() - std::time::Duration::from_secs(diff)
    }

    /// Get SA lifetime
    pub fn get_lifetime(&self) -> std::time::Duration {
        std::time::Duration::from_secs(self.lifetime_secs)
    }
}

/// SA statistics
#[derive(Debug, Clone)]
pub struct SaStats {
    pub spi: u32,
    pub protocol: IpSecProtocol,
    pub mode: SaMode,
    pub packets_processed: u64,
    pub auth_failures: u32,
    pub age_seconds: u64,
    pub last_used_seconds: u64,
    pub is_expired: bool,
    pub needs_rekeying: bool,
}

/// Security Association Database
pub struct SecurityAssociationDatabase {
    /// Map of SPI to SA
    sas: HashMap<u32, SecurityAssociation>,
    /// Maximum number of SAs
    max_sas: usize,
}

impl SecurityAssociationDatabase {
    /// Create a new SAD
    pub fn new(max_sas: usize) -> Self {
        Self {
            sas: HashMap::new(),
            max_sas,
        }
    }

    /// Add SA to database
    pub fn add_sa(&mut self, sa: SecurityAssociation) -> Result<()> {
        if self.sas.len() >= self.max_sas {
            return Err(QuantumIpsecError::PacketError("SAD full".into()));
        }
        
        self.sas.insert(sa.spi, sa);
        Ok(())
    }

    /// Get SA by SPI
    pub fn get_sa(&self, spi: u32) -> Option<&SecurityAssociation> {
        self.sas.get(&spi)
    }

    /// Get mutable SA by SPI
    pub fn get_sa_mut(&mut self, spi: u32) -> Option<&mut SecurityAssociation> {
        self.sas.get_mut(&spi)
    }

    /// Remove SA by SPI
    pub fn remove_sa(&mut self, spi: u32) -> Option<SecurityAssociation> {
        self.sas.remove(&spi)
    }

    /// Clean up expired SAs
    pub fn cleanup_expired(&mut self) -> usize {
        let mut expired = Vec::new();
        
        for (spi, sa) in &self.sas {
            if sa.is_expired() {
                expired.push(*spi);
            }
        }
        
        let count = expired.len();
        for spi in expired {
            self.sas.remove(&spi);
        }
        
        count
    }

    /// Get number of active SAs
    pub fn active_count(&self) -> usize {
        self.sas.values().filter(|sa| sa.is_valid()).count()
    }

    /// Get total number of SAs
    pub fn total_count(&self) -> usize {
        self.sas.len()
    }

    /// Find SA by addresses and protocol
    pub fn find_sa_by_addrs(
        &self,
        _src: IpAddr,
        _dst: IpAddr,
        _protocol: u8,
    ) -> Option<&SecurityAssociation> {
        // For now, return the first valid SA
        self.sas.values().find(|sa| sa.is_valid())
    }

    /// Get statistics for all SAs
    pub fn get_all_stats(&self) -> Vec<String> {
        self.sas.values().map(|sa| {
            format!("SPI: {}, Active: {}, Age: {}s", 
                sa.spi, 
                sa.is_valid(), 
                sa.get_created_at().elapsed().as_secs())
        }).collect()
    }
}

/// Create a new SA from shared secret
pub fn new_kem_based(shared_secret: Vec<u8>) -> SecurityAssociation {
    let (auth_pk, auth_sk) = Dilithium3::keygen();
    let mut shared_secret_array = [0u8; KYBER_SSBYTES];
    let copy_len = std::cmp::min(shared_secret.len(), KYBER_SSBYTES);
    shared_secret_array[..copy_len].copy_from_slice(&shared_secret[..copy_len]);
    
    SecurityAssociation {
        spi: generate_spi(),
        sequence: 0,
        max_sequence: u32::MAX,
        shared_secret: shared_secret_array,
        auth_public_key: auth_pk.0.to_vec(),
        auth_secret_key: auth_sk.0.to_vec(),
        nonce: vec![0u8; 32],
        created_at: std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs(),
        lifetime_secs: 3600,
        is_active: true,
    }
}
