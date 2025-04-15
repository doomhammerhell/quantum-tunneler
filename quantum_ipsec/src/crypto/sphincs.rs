//! Implementation of the SPHINCS+ digital signature scheme.
//!
//! This module provides an implementation of the SPHINCS+-SHA256-128f-simple
//! variant of the SPHINCS+ digital signature scheme, which is a post-quantum
//! secure signature scheme.

use super::traits::DigitalSignature;
use core::fmt::Debug;
use pqc_sphincs::{keypair, sign, verify};

/// Implementation of the SPHINCS+-SHA256-128f-simple digital signature scheme.
///
/// This struct implements the `DigitalSignature` trait for the SPHINCS+-SHA256-128f-simple
/// variant of the SPHINCS+ signature scheme.
pub struct SphincsPlus;

impl DigitalSignature for SphincsPlus {
    type PublicKey = [u8; pqc_sphincs::SPHINCS_PUBLICKEYBYTES];
    type SecretKey = [u8; pqc_sphincs::SPHINCS_SECRETKEYBYTES];
    type Signature = [u8; pqc_sphincs::SPHINCS_SIGNATUREBYTES];

    fn keygen() -> (Self::PublicKey, Self::SecretKey) {
        let mut pk = [0u8; pqc_sphincs::SPHINCS_PUBLICKEYBYTES];
        let mut sk = [0u8; pqc_sphincs::SPHINCS_SECRETKEYBYTES];
        keypair(&mut pk, &mut sk, None).expect("Failed to generate SPHINCS+ key pair");
        (pk, sk)
    }

    fn sign(sk: &Self::SecretKey, msg: &[u8]) -> Self::Signature {
        let mut sig = [0u8; pqc_sphincs::SPHINCS_SIGNATUREBYTES];
        sign(&mut sig, msg, sk, None).expect("Failed to sign message with SPHINCS+");
        sig
    }

    fn verify(pk: &Self::PublicKey, msg: &[u8], sig: &Self::Signature) -> bool {
        verify(sig, msg, pk).expect("Failed to verify SPHINCS+ signature")
    }
} 