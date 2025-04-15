//! Implementation of the Falcon digital signature scheme.
//!
//! This module provides an implementation of the Falcon-512 variant of the
//! Falcon digital signature scheme, which is a post-quantum secure signature
//! scheme.

use super::traits::DigitalSignature;
use core::fmt::Debug;
use pqc_falcon::{keypair, sign, verify};

/// Implementation of the Falcon-512 digital signature scheme.
///
/// This struct implements the `DigitalSignature` trait for the Falcon-512
/// variant of the Falcon signature scheme.
pub struct Falcon512;

impl DigitalSignature for Falcon512 {
    type PublicKey = [u8; pqc_falcon::FALCON_PUBLICKEYBYTES];
    type SecretKey = [u8; pqc_falcon::FALCON_SECRETKEYBYTES];
    type Signature = [u8; pqc_falcon::FALCON_SIGNATUREBYTES];

    fn keygen() -> (Self::PublicKey, Self::SecretKey) {
        let mut pk = [0u8; pqc_falcon::FALCON_PUBLICKEYBYTES];
        let mut sk = [0u8; pqc_falcon::FALCON_SECRETKEYBYTES];
        keypair(&mut pk, &mut sk, None).expect("Failed to generate Falcon key pair");
        (pk, sk)
    }

    fn sign(sk: &Self::SecretKey, msg: &[u8]) -> Self::Signature {
        let mut sig = [0u8; pqc_falcon::FALCON_SIGNATUREBYTES];
        sign(&mut sig, msg, sk, None).expect("Failed to sign message with Falcon");
        sig
    }

    fn verify(pk: &Self::PublicKey, msg: &[u8], sig: &Self::Signature) -> bool {
        verify(sig, msg, pk).expect("Failed to verify Falcon signature")
    }
} 