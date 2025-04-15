//! Cryptographic traits for post-quantum cryptography.
//!
//! This module defines the core traits for key encapsulation mechanisms (KEM)
//! and digital signature schemes that will be used throughout the quantum-tunneler
//! project.

use core::fmt::Debug;

/// Trait for key encapsulation mechanisms (KEM).
///
/// This trait defines the interface for post-quantum KEMs like Kyber.
/// All associated types must implement `Debug` for error handling and logging.
pub trait KeyEncapsulation {
    /// The type of public keys for this KEM.
    type PublicKey: Debug;
    /// The type of secret keys for this KEM.
    type SecretKey: Debug;
    /// The type of ciphertexts produced by this KEM.
    type Ciphertext: Debug;
    /// The type of shared secrets produced by this KEM.
    type SharedSecret: Debug;

    /// Generates a new key pair.
    ///
    /// # Returns
    /// A tuple containing the public key and secret key.
    fn keygen() -> (Self::PublicKey, Self::SecretKey);

    /// Encapsulates a shared secret using the given public key.
    ///
    /// # Arguments
    /// * `pk` - The public key to use for encapsulation
    ///
    /// # Returns
    /// A tuple containing the ciphertext and the shared secret.
    fn encapsulate(pk: &Self::PublicKey) -> (Self::Ciphertext, Self::SharedSecret);

    /// Decapsulates a shared secret using the given secret key and ciphertext.
    ///
    /// # Arguments
    /// * `sk` - The secret key to use for decapsulation
    /// * `ct` - The ciphertext to decapsulate
    ///
    /// # Returns
    /// The decapsulated shared secret.
    fn decapsulate(sk: &Self::SecretKey, ct: &Self::Ciphertext) -> Self::SharedSecret;
}

/// Trait for digital signature schemes.
///
/// This trait defines the interface for post-quantum digital signature schemes
/// like Falcon. All associated types must implement `Debug` for error handling
/// and logging.
pub trait DigitalSignature {
    /// The type of public keys for this signature scheme.
    type PublicKey: Debug;
    /// The type of secret keys for this signature scheme.
    type SecretKey: Debug;
    /// The type of signatures produced by this scheme.
    type Signature: Debug;

    /// Generates a new key pair.
    ///
    /// # Returns
    /// A tuple containing the public key and secret key.
    fn keygen() -> (Self::PublicKey, Self::SecretKey);

    /// Signs a message using the given secret key.
    ///
    /// # Arguments
    /// * `sk` - The secret key to use for signing
    /// * `message` - The message to sign
    ///
    /// # Returns
    /// The signature for the message.
    fn sign(sk: &Self::SecretKey, message: &[u8]) -> Self::Signature;

    /// Verifies a signature for a message using the given public key.
    ///
    /// # Arguments
    /// * `pk` - The public key to use for verification
    /// * `message` - The message that was signed
    /// * `sig` - The signature to verify
    ///
    /// # Returns
    /// `true` if the signature is valid, `false` otherwise.
    fn verify(pk: &Self::PublicKey, message: &[u8], sig: &Self::Signature) -> bool;
} 