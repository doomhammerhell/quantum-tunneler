use super::provenance::{KeyDerivationId, KeyProvenance};
use crate::{crypto::secret::SecretBytes, QuantumIpsecError as Error, Result};
use hkdf::Hkdf;
use sha2::Sha256;

#[derive(Debug)]
pub struct TrafficKey {
    pub(crate) key: SecretBytes<32>,
    pub(crate) salt: SecretBytes<4>,
    pub(crate) spi: u32,
    pub(crate) provenance: KeyProvenance,
}
/// Each key belongs to one unidirectional SA. Consumed, never cloned.
#[derive(Debug)]
pub struct TrafficKeys {
    pub initiator_to_responder: TrafficKey,
    pub responder_to_initiator: TrafficKey,
}
#[derive(Debug, Clone, Copy)]
pub struct KeyContext {
    pub initiator_spi: u32,
    pub responder_spi: u32,
    /// Fresh unpredictable identifier agreed through an authenticated channel.
    pub session_id: [u8; 32],
    pub transcript_hash: [u8; 32],
    pub generation: u64,
}
/// LAB ONLY: not IKE KEYMAT or an RFC 9370 hybrid combiner. The caller must
/// authenticate context and supply high-entropy IKM (not a password). Reusing
/// IKM and context after a restart repeats keys; fresh session_id is mandatory.
pub fn derive_traffic_keys(
    ikm: SecretBytes<32>,
    context: &KeyContext,
) -> Result<(TrafficKeys, KeyProvenance)> {
    if context.initiator_spi < 256
        || context.responder_spi < 256
        || context.initiator_spi == context.responder_spi
        || context.session_id == [0; 32]
        || context.generation == 0
    {
        return Err(Error::ConfigError("invalid key context".into()));
    }
    let hk = Hkdf::<Sha256>::new(Some(&context.session_id), ikm.expose());
    let mut info = Vec::from(&b"quantum-tunneler/experimental/esp/aes256gcm/v1"[..]);
    info.extend_from_slice(&context.initiator_spi.to_be_bytes());
    info.extend_from_slice(&context.responder_spi.to_be_bytes());
    info.extend_from_slice(&context.generation.to_be_bytes());
    info.extend_from_slice(&context.transcript_hash);
    let provenance = KeyProvenance {
        derivation: KeyDerivationId::ExperimentalHkdfSha256V1,
        transcript_hash: context.transcript_hash,
        session_id: context.session_id,
        generation: context.generation,
    };
    let derive = |label: &[u8], spi: u32| -> Result<TrafficKey> {
        let mut material = SecretBytes::new([0; 36]);
        let mut labeled = info.clone();
        labeled.extend_from_slice(label);
        hk.expand(&labeled, material.expose_mut())
            .map_err(|_| Error::Crypto)?;
        let mut key = SecretBytes::new([0; 32]);
        let mut salt = SecretBytes::new([0; 4]);
        key.expose_mut().copy_from_slice(&material.expose()[..32]);
        salt.expose_mut().copy_from_slice(&material.expose()[32..]);
        Ok(TrafficKey {
            key,
            salt,
            spi,
            provenance: provenance.clone(),
        })
    };
    Ok((
        TrafficKeys {
            initiator_to_responder: derive(b"/initiator-to-responder", context.responder_spi)?,
            responder_to_initiator: derive(b"/responder-to-initiator", context.initiator_spi)?,
        },
        KeyProvenance {
            derivation: KeyDerivationId::ExperimentalHkdfSha256V1,
            transcript_hash: context.transcript_hash,
            session_id: context.session_id,
            generation: context.generation,
        },
    ))
}
