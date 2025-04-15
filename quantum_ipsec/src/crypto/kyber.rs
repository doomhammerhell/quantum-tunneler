//! Implementation of the CRYSTALS-Kyber key encapsulation mechanism.
//!
//! This module provides an implementation of the Kyber512 variant of the
//! CRYSTALS-Kyber KEM, which is a post-quantum secure key encapsulation
//! mechanism.

use super::traits::KeyEncapsulation;
use core::fmt::Debug;
use pqc_kyber::{keypair, encapsulate, decapsulate};

/// Implementation of the Kyber512 KEM.
///
/// This struct implements the `KeyEncapsulation` trait for the Kyber512
/// variant of the CRYSTALS-Kyber KEM.
pub struct Kyber512;

impl KeyEncapsulation for Kyber512 {
    type PublicKey = [u8; pqc_kyber::KYBER_PUBLICKEYBYTES];
    type SecretKey = [u8; pqc_kyber::KYBER_SECRETKEYBYTES];
    type Ciphertext = [u8; pqc_kyber::KYBER_CIPHERTEXTBYTES];
    type SharedSecret = [u8; pqc_kyber::KYBER_SSBYTES];

    fn keygen() -> (Self::PublicKey, Self::SecretKey) {
        let mut pk = [0u8; pqc_kyber::KYBER_PUBLICKEYBYTES];
        let mut sk = [0u8; pqc_kyber::KYBER_SECRETKEYBYTES];
        keypair(&mut pk, &mut sk, None).expect("Failed to generate Kyber key pair");
        (pk, sk)
    }

    fn encapsulate(pk: &Self::PublicKey) -> (Self::Ciphertext, Self::SharedSecret) {
        let mut ct = [0u8; pqc_kyber::KYBER_CIPHERTEXTBYTES];
        let mut ss = [0u8; pqc_kyber::KYBER_SSBYTES];
        encapsulate(&mut ct, &mut ss, pk, None).expect("Failed to encapsulate Kyber shared secret");
        (ct, ss)
    }

    fn decapsulate(sk: &Self::SecretKey, ct: &Self::Ciphertext) -> Self::SharedSecret {
        let mut ss = [0u8; pqc_kyber::KYBER_SSBYTES];
        decapsulate(&mut ss, ct, sk).expect("Failed to decapsulate Kyber shared secret");
        ss
    }
} 