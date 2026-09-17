//! AES-256-GCM with a 96-bit nonce and full 128-bit tag.
use crate::{QuantumIpsecError as Error, Result};
use aes_gcm::{
    aead::{AeadInPlace, KeyInit},
    Aes256Gcm, Nonce, Tag,
};

pub fn seal(key: &[u8; 32], nonce: &[u8; 12], aad: &[u8], buffer: &mut [u8]) -> Result<[u8; 16]> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| Error::Crypto)?;
    let tag = cipher
        .encrypt_in_place_detached(Nonce::from_slice(nonce), aad, buffer)
        .map_err(|_| Error::Crypto)?;
    Ok(tag.into())
}
pub fn open(
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    buffer: &mut [u8],
    tag: &[u8; 16],
) -> Result<()> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| Error::Crypto)?;
    cipher
        .decrypt_in_place_detached(Nonce::from_slice(nonce), aad, buffer, Tag::from_slice(tag))
        .map_err(|_| Error::Authentication)
}
