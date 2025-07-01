//! Cryptographic adapter for IKEv2 operations using post-quantum primitives
//!
//! This module provides cryptographic operations for IKEv2 including
//! post-quantum cryptographic primitives (Kyber and Dilithium).

use crate::{QuantumIpsecError, Result};
use crate::crypto::{
    traits::{KeyEncapsulation, DigitalSignature},
    kyber::{Kyber512, KyberPublicKey, KyberSecretKey, KyberCiphertext, KYBER_PUBLICKEYBYTES, KYBER_SECRETKEYBYTES, KYBER_CIPHERTEXTBYTES},
    dilithium::{Dilithium3, DilithiumPublicKey, DilithiumSecretKey, DilithiumSignature, DILITHIUM_PUBLICKEYBYTES, DILITHIUM_SECRETKEYBYTES, DILITHIUM_SIGNATUREBYTES},
};
use crate::ike::debug::{DebugLevel, DebugContext};
use hmac::{Hmac, Mac};
use sha2::Sha256;

/// Adapter for cryptographic operations in IKEv2
pub struct CryptoAdapter {
    /// Kyber KEM instance
    kem: Kyber512,
    /// Dilithium signature instance
    sig: Dilithium3,
    /// Debug context
    debug: DebugContext,
}

impl CryptoAdapter {
    /// Creates a new crypto adapter
    pub fn new(debug_level: DebugLevel) -> Self {
        Self {
            kem: Kyber512,
            sig: Dilithium3,
            debug: DebugContext::new(debug_level),
        }
    }

    /// Generate a new key pair
    pub fn generate_keypair(&self) -> Result<(Vec<u8>, Vec<u8>)> {
        let (pk, sk) = <Kyber512 as KeyEncapsulation>::keygen();
        let pk_array = pk.as_ref().to_vec();
        let sk_array = sk.as_ref().to_vec();
        self.debug.log_message(&format!("Generated Kyber keypair: pk_len={}, sk_len={}", pk_array.len(), sk_array.len()));
        Ok((pk_array, sk_array))
    }

    /// Encapsulate a shared secret using the given public key
    pub fn encapsulate(&self, pk: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
        let pk_array: [u8; KYBER_PUBLICKEYBYTES] = pk.try_into()
            .map_err(|_| QuantumIpsecError::PacketError("Conversão de chave falhou".into()))?;
        
        let pk_key = KyberPublicKey::from(pk_array);
        let (ct, ss) = Kyber512::encapsulate(&pk_key);
        let ct_array = ct.as_ref().to_vec();
        let ss_array = ss.as_ref().to_vec();
        
        self.debug.log_message(&format!("Encapsulated shared secret: ct_len={}, ss_len={}", ct_array.len(), ss_array.len()));
        Ok((ct_array, ss_array))
    }

    /// Decapsulate a shared secret using the given secret key and ciphertext
    pub fn decapsulate(&self, sk: &[u8], ct: &[u8]) -> Result<Vec<u8>> {
        let sk_array: [u8; KYBER_SECRETKEYBYTES] = sk.try_into()
            .map_err(|_| QuantumIpsecError::PacketError("Conversão de chave falhou".into()))?;
        let ct_array: [u8; KYBER_CIPHERTEXTBYTES] = ct.try_into()
            .map_err(|_| QuantumIpsecError::PacketError("Conversão de chave falhou".into()))?;
        
        let sk_key = KyberSecretKey::from(sk_array);
        let ct_key = KyberCiphertext::from(ct_array);
        let ss = Kyber512::decapsulate(&sk_key, &ct_key);
        let ss_array = ss.as_ref().to_vec();
        
        self.debug.log_message(&format!("Decapsulated shared secret: ss_len={}", ss_array.len()));
        Ok(ss_array)
    }

    /// Signs a message using the given secret key
    pub fn sign(&self, sk: &[u8], msg: &[u8]) -> Result<Vec<u8>> {
        let sk_array: [u8; DILITHIUM_SECRETKEYBYTES] = sk.try_into()
            .map_err(|_| QuantumIpsecError::PacketError("Invalid secret key length".into()))?;
        let sk_key = DilithiumSecretKey::from(sk_array);
        let sig = Dilithium3::sign(&sk_key, msg);
        let sig_array = sig.as_ref().to_vec();
        self.debug.log_message(&format!("Signed message: msg_len={}, sig_len={}", msg.len(), sig_array.len()));
        Ok(sig_array)
    }

    /// Verifies a signature for a message using the given public key
    pub fn verify(&self, pk: &[u8], msg: &[u8], sig: &[u8]) -> Result<bool> {
        let pk_array: [u8; DILITHIUM_PUBLICKEYBYTES] = pk.try_into()
            .map_err(|_| QuantumIpsecError::PacketError("Invalid public key length".into()))?;
        let sig_array: [u8; DILITHIUM_SIGNATUREBYTES] = sig.try_into()
            .map_err(|_| QuantumIpsecError::PacketError("Invalid signature length".into()))?;
        let pk_key = DilithiumPublicKey::from(pk_array);
        let sig_key = DilithiumSignature::from(sig_array);
        let result = Dilithium3::verify(&pk_key, msg, &sig_key);
        self.debug.log_message(&format!("Verified signature: result={}", result));
        Ok(result)
    }

    /// Derives session keys from the shared secret
    pub fn derive_session_keys(&self, shared_secret: &[u8], nonce_i: &[u8], nonce_r: &[u8]) -> Result<Vec<u8>> {
        let mut key = [0u8; 32];
        let mut mac = Hmac::<Sha256>::new_from_slice(shared_secret)
            .map_err(|_| QuantumIpsecError::PacketError("Conversão de chave falhou".into()))?;
        
        mac.update(nonce_i);
        mac.update(nonce_r);
        
        key.copy_from_slice(&mac.finalize().into_bytes()[..32]);
        self.debug.log_message(&format!("Derived session key: key_len={}", key.len()));
        Ok(key.to_vec())
    }

    /// Verifies authentication data
    pub fn verify_auth_data(&self, auth_data: &[u8], shared_secret: &[u8], nonce_i: &[u8], nonce_r: &[u8]) -> Result<bool> {
        let mut mac = Hmac::<Sha256>::new_from_slice(shared_secret)
            .map_err(|_| QuantumIpsecError::PacketError("Conversão de chave falhou".into()))?;
        
        mac.update(nonce_i);
        mac.update(nonce_r);
        
        let expected = mac.finalize().into_bytes();
        let result = auth_data == expected.as_slice();
        self.debug.log_message(&format!("Verified auth data: result={}", result));
        Ok(result)
    }

    /// Creates authentication data for IKE_AUTH
    pub fn create_auth_data(&self, shared_secret: &[u8], nonce_i: &[u8], nonce_r: &[u8]) -> Result<Vec<u8>> {
        let mut mac = Hmac::<Sha256>::new_from_slice(shared_secret)
            .map_err(|_| QuantumIpsecError::PacketError("Conversão de chave falhou".into()))?;
        
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