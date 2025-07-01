//! Post-quantum cryptography primitives for quantum-tunneler
//! 
//! This module provides implementations of post-quantum cryptographic
//! primitives including key encapsulation mechanisms (KEM) and digital
//! signature schemes.

pub mod traits;
pub mod kyber;
pub mod dilithium;

pub use traits::{KeyEncapsulation, DigitalSignature};
pub use kyber::{Kyber512, KyberPublicKey, KyberSecretKey, KyberCiphertext, KyberSharedSecret};
pub use dilithium::{Dilithium3, DilithiumPublicKey, DilithiumSecretKey, DilithiumSignature};

// Re-export constants for convenience
pub use kyber::{
    KYBER_PUBLICKEYBYTES,
    KYBER_SECRETKEYBYTES,
    KYBER_CIPHERTEXTBYTES,
    KYBER_SSBYTES,
};

pub use dilithium::{
    DILITHIUM_PUBLICKEYBYTES,
    DILITHIUM_SECRETKEYBYTES,
    DILITHIUM_SIGNATUREBYTES,
};

/// Symmetric encryption primitives
pub mod symmetric {
    use crate::QuantumIpsecError;
    use aes_gcm::{Aes256Gcm, Key, KeyInit, Nonce};
    use aes_gcm::aead::{Aead, Payload};

    /// Encrypt data using AES-GCM
    pub fn encrypt(key: &[u8], nonce: &[u8], plaintext: &[u8], aad: &[u8]) -> std::result::Result<Vec<u8>, QuantumIpsecError> {
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
        let nonce = Nonce::from_slice(nonce);
        let payload = Payload {
            msg: plaintext,
            aad,
        };
        
        cipher.encrypt(nonce, payload)
            .map_err(|e| QuantumIpsecError::CryptoError(format!("AES-GCM encryption failed: {}", e)))
    }

    /// Decrypt data using AES-GCM
    pub fn decrypt(key: &[u8], nonce: &[u8], ciphertext: &[u8], aad: &[u8]) -> std::result::Result<Vec<u8>, QuantumIpsecError> {
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
        let nonce = Nonce::from_slice(nonce);
        let payload = Payload {
            msg: ciphertext,
            aad,
        };
        
        cipher.decrypt(nonce, payload)
            .map_err(|e| QuantumIpsecError::CryptoError(format!("AES-GCM decryption failed: {}", e)))
    }
}

/// Hash functions
pub mod hash {
    use sha2::{Sha256, Sha384, Digest};

    /// Compute SHA-256 hash
    pub fn sha256(data: &[u8]) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(data);
        hasher.finalize().to_vec()
    }

    /// Compute SHA-384 hash
    pub fn sha384(data: &[u8]) -> Vec<u8> {
        let mut hasher = Sha384::new();
        hasher.update(data);
        hasher.finalize().to_vec()
    }
}

/// Random number generation
pub mod rng {
    use rand_core::{RngCore, CryptoRng};

    /// Generate random bytes
    pub fn random_bytes<R: RngCore + CryptoRng>(rng: &mut R, len: usize) -> Vec<u8> {
        let mut bytes = vec![0u8; len];
        rng.fill_bytes(&mut bytes);
        bytes
    }
} 