use serde::Serialize;
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum KeyDerivationId {
    ExperimentalHkdfSha256V1,
    IkeV2PrfHmacSha256,
}
/// Metadata describes derivation, not proof of peer authentication.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct KeyProvenance {
    pub derivation: KeyDerivationId,
    pub transcript_hash: [u8; 32],
    pub session_id: [u8; 32],
    pub generation: u64,
}
