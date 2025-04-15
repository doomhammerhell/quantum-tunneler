//! Implementation of the Dilithium digital signature scheme.
//!
//! This module provides an implementation of the Dilithium3 variant of the
//! Dilithium digital signature scheme, which is a post-quantum secure signature
//! scheme.

use super::traits::DigitalSignature;
use core::fmt::Debug;
use pqc_dilithium::{keypair, sign, verify};

/// Implementation of the Dilithium3 digital signature scheme.
///
/// This struct implements the `DigitalSignature` trait for the Dilithium3
/// variant of the Dilithium signature scheme.
pub struct Dilithium3;

impl DigitalSignature for Dilithium3 {
    type PublicKey = [u8; pqc_dilithium::DILITHIUM_PUBLICKEYBYTES];
    type SecretKey = [u8; pqc_dilithium::DILITHIUM_SECRETKEYBYTES];
    type Signature = [u8; pqc_dilithium::DILITHIUM_SIGNATUREBYTES];

    fn keygen() -> (Self::PublicKey, Self::SecretKey) {
        let mut pk = [0u8; pqc_dilithium::DILITHIUM_PUBLICKEYBYTES];
        let mut sk = [0u8; pqc_dilithium::DILITHIUM_SECRETKEYBYTES];
        keypair(&mut pk, &mut sk, None).expect("Failed to generate Dilithium key pair");
        (pk, sk)
    }

    fn sign(sk: &Self::SecretKey, msg: &[u8]) -> Self::Signature {
        let mut sig = [0u8; pqc_dilithium::DILITHIUM_SIGNATUREBYTES];
        sign(&mut sig, msg, sk, None).expect("Failed to sign message with Dilithium");
        sig
    }

    fn verify(pk: &Self::PublicKey, msg: &[u8], sig: &Self::Signature) -> bool {
        verify(sig, msg, pk).expect("Failed to verify Dilithium signature")
    }
} 