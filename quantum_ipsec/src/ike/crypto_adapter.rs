//! Cryptographic adapter for IKEv2 protocol.
//!
//! This module provides an adapter between the IKEv2 protocol and the
//! post-quantum cryptographic primitives (Kyber and Falcon).

use crate::crypto::{
    traits::{KeyEncapsulation, DigitalSignature},
    kyber::Kyber512,
    falcon::Falcon512,
};
use super::{IKEError, DebugContext};
use hmac::{Hmac, Mac};
use sha2::Sha256;

/// Adapter for cryptographic operations in IKEv2
pub struct CryptoAdapter {
    /// Kyber KEM instance
    kem: Kyber512,
    /// Falcon signature instance
    sig: Falcon512,
    /// Debug context
    debug: DebugContext,
}

impl CryptoAdapter {
    /// Creates a new cryptographic adapter
    pub fn new(debug_level: super::DebugLevel) -> Self {
        Self {
            kem: Kyber512,
            sig: Falcon512,
            debug: DebugContext::new(debug_level),
        }
    }

    /// Generates a key pair for the specified role
    pub fn generate_keypair(&self) -> Result<(Vec<u8>, Vec<u8>), IKEError> {
        let (pk, sk) = self.kem.keygen();
        self.debug.log_message(&format!("Generated key pair: pk_len={}, sk_len={}", pk.len(), sk.len()));
        Ok((pk.to_vec(), sk.to_vec()))
    }

    /// Encapsulates a shared secret using the given public key
    pub fn encapsulate(&self, pk: &[u8]) -> Result<(Vec<u8>, Vec<u8>), IKEError> {
        let pk_array = pk.try_into().map_err(|_| IKEError::CryptoError)?;
        let (ct, ss) = self.kem.encapsulate(&pk_array);
        self.debug.log_message(&format!("Encapsulated shared secret: ct_len={}, ss_len={}", ct.len(), ss.len()));
        Ok((ct.to_vec(), ss.to_vec()))
    }

    /// Decapsulates a shared secret using the given secret key and ciphertext
    pub fn decapsulate(&self, sk: &[u8], ct: &[u8]) -> Result<Vec<u8>, IKEError> {
        let sk_array = sk.try_into().map_err(|_| IKEError::CryptoError)?;
        let ct_array = ct.try_into().map_err(|_| IKEError::CryptoError)?;
        let ss = self.kem.decapsulate(&sk_array, &ct_array);
        self.debug.log_message(&format!("Decapsulated shared secret: ss_len={}", ss.len()));
        Ok(ss.to_vec())
    }

    /// Signs a message using the given secret key
    pub fn sign(&self, sk: &[u8], msg: &[u8]) -> Result<Vec<u8>, IKEError> {
        let sk_array = sk.try_into().map_err(|_| IKEError::CryptoError)?;
        let sig = self.sig.sign(&sk_array, msg);
        self.debug.log_message(&format!("Signed message: msg_len={}, sig_len={}", msg.len(), sig.len()));
        Ok(sig.to_vec())
    }

    /// Verifies a signature for a message using the given public key
    pub fn verify(&self, pk: &[u8], msg: &[u8], sig: &[u8]) -> Result<bool, IKEError> {
        let pk_array = pk.try_into().map_err(|_| IKEError::CryptoError)?;
        let sig_array = sig.try_into().map_err(|_| IKEError::CryptoError)?;
        let result = self.sig.verify(&pk_array, msg, &sig_array);
        self.debug.log_message(&format!("Verified signature: result={}", result));
        Ok(result)
    }

    /// Derives session keys from the shared secret
    pub fn derive_session_keys(&self, shared_secret: &[u8], nonce_i: &[u8], nonce_r: &[u8]) -> Result<Vec<u8>, IKEError> {
        let mut key = [0u8; 32];
        let mut mac = Hmac::<Sha256>::new_from_slice(shared_secret)
            .map_err(|_| IKEError::CryptoError)?;
        
        mac.update(nonce_i);
        mac.update(nonce_r);
        
        key.copy_from_slice(&mac.finalize().into_bytes()[..32]);
        self.debug.log_message(&format!("Derived session key: key_len={}", key.len()));
        Ok(key.to_vec())
    }

    /// Verifies authentication data
    pub fn verify_auth_data(&self, auth_data: &[u8], shared_secret: &[u8], nonce_i: &[u8], nonce_r: &[u8]) -> Result<bool, IKEError> {
        let mut mac = Hmac::<Sha256>::new_from_slice(shared_secret)
            .map_err(|_| IKEError::CryptoError)?;
        
        mac.update(nonce_i);
        mac.update(nonce_r);
        
        let expected = mac.finalize().into_bytes();
        let result = auth_data == expected.as_slice();
        self.debug.log_message(&format!("Verified auth data: result={}", result));
        Ok(result)
    }

    /// Creates authentication data for IKE_AUTH
    pub fn create_auth_data(&self, shared_secret: &[u8], nonce_i: &[u8], nonce_r: &[u8]) -> Result<Vec<u8>, IKEError> {
        let mut mac = Hmac::<Sha256>::new_from_slice(shared_secret)
            .map_err(|_| IKEError::CryptoError)?;
        
        mac.update(nonce_i);
        mac.update(nonce_r);
        
        let auth_data = mac.finalize().into_bytes();
        self.debug.log_message(&format!("Created auth data: len={}", auth_data.len()));
        Ok(auth_data.to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keypair_generation() {
        let adapter = CryptoAdapter::new(super::DebugLevel::Basic);
        let (pk, sk) = adapter.generate_keypair().unwrap();
        assert!(!pk.is_empty());
        assert!(!sk.is_empty());
    }

    #[test]
    fn test_encapsulation_decapsulation() {
        let adapter = CryptoAdapter::new(super::DebugLevel::Basic);
        let (pk, sk) = adapter.generate_keypair().unwrap();
        let (ct, ss1) = adapter.encapsulate(&pk).unwrap();
        let ss2 = adapter.decapsulate(&sk, &ct).unwrap();
        assert_eq!(ss1, ss2);
    }

    #[test]
    fn test_signature_verification() {
        let adapter = CryptoAdapter::new(super::DebugLevel::Basic);
        let (pk, sk) = adapter.generate_keypair().unwrap();
        let msg = b"test message";
        let sig = adapter.sign(&sk, msg).unwrap();
        assert!(adapter.verify(&pk, msg, &sig).unwrap());
    }

    #[test]
    fn test_auth_data_verification() {
        let adapter = CryptoAdapter::new(super::DebugLevel::Basic);
        let shared_secret = [1u8; 32];
        let nonce_i = [2u8; 32];
        let nonce_r = [3u8; 32];
        let auth_data = adapter.derive_session_keys(&shared_secret, &nonce_i, &nonce_r).unwrap();
        assert!(adapter.verify_auth_data(&auth_data, &shared_secret, &nonce_i, &nonce_r).unwrap());
    }
} 