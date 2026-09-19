//! Isolated RFC 7296 §2.15 PSK AUTH arithmetic, using PRF_HMAC_SHA2_256.
//! Does not authenticate a session or authorize an identity. No IKE_INTERMEDIATE
//! support: RFC 9242 transcript accumulation must precede hybrid use.
use super::{
    exchange::ExchangeType,
    parser::parse_message,
    schedule::{prf, IkeKeys},
};
use crate::{crypto::secret::SecretBytes, QuantumIpsecError as Error, Result};
use hmac::{Hmac, Mac};
use sha2::Sha256;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthRole {
    Initiator,
    Responder,
}

/// Borrowed exact wire transcript plus the inputs needed for SignedOctets.
/// Debug is deliberately absent to avoid accidental transcript/identity logging.
pub struct PskAuth<'a> {
    initial_message: &'a [u8],
    peer_nonce: &'a [u8],
    identity_body: &'a [u8],
    sk_p: &'a SecretBytes<32>,
}

impl<'a> PskAuth<'a> {
    /// `initial_message` is the signer's latest successful IKE_SA_INIT message,
    /// starting at SPIi (no UDP/Non-ESP marker); never reserialize it.
    /// `peer_nonce` is Nr for the initiator, Ni for the responder, without headers.
    /// `identity_body` includes ID type and all three reserved bytes, but excludes
    /// the generic payload header. The caller must bind these inputs and `keys`
    /// to the same exchange and enforce peer identity policy separately.
    /// Validation here is structural, not proof of a successful exchange.
    pub fn new(
        role: AuthRole,
        initial_message: &'a [u8],
        peer_nonce: &'a [u8],
        identity_body: &'a [u8],
        keys: &'a IkeKeys,
    ) -> Result<Self> {
        let message = parse_message(initial_message)?;
        let expected_flags = match role {
            AuthRole::Initiator => 0x08,
            AuthRole::Responder => 0x20,
        };
        if message.header.exchange_type != ExchangeType::IkeSaInit
            || message.header.flags & 0x28 != expected_flags
            || (role == AuthRole::Responder && message.header.responder_spi == 0)
            || !(16..=256).contains(&peer_nonce.len())
            || !(5..=4096).contains(&identity_body.len())
        {
            return Err(Error::Crypto);
        }
        Ok(Self {
            initial_message,
            peer_nonce,
            identity_body,
            sk_p: match role {
                AuthRole::Initiator => &keys.sk_pi,
                AuthRole::Responder => &keys.sk_pr,
            },
        })
    }

    fn mac<const N: usize>(&self, psk: &SecretBytes<N>) -> Result<Hmac<Sha256>> {
        if N == 0 {
            return Err(Error::Crypto);
        }
        let padded_key = prf(psk.expose(), &[b"Key Pad for IKEv2"])?;
        let identity_mac = prf(self.sk_p.expose(), &[self.identity_body])?;
        let mut mac =
            Hmac::<Sha256>::new_from_slice(padded_key.expose()).map_err(|_| Error::Crypto)?;
        // Stream exact SignedOctets, including ignored/unknown wire bytes.
        mac.update(self.initial_message);
        mac.update(self.peer_nonce);
        mac.update(identity_mac.expose());
        Ok(mac)
    }

    /// Returns the 32-byte Authentication Data (not the AUTH payload header).
    /// Provision a high-entropy PSK; length alone does not establish entropy.
    /// Owned intermediate secrets are erased; HMAC internal state has no such guarantee.
    pub fn compute<const N: usize>(&self, psk: &SecretBytes<N>) -> Result<[u8; 32]> {
        Ok(self.mac(psk)?.finalize().into_bytes().into())
    }

    /// Constant-time MAC comparison for a correctly sized tag. Success only
    /// verifies these supplied inputs; it never changes IKE/SA state.
    pub fn verify<const N: usize>(&self, psk: &SecretBytes<N>, auth: &[u8]) -> Result<()> {
        self.mac(psk)?
            .verify_slice(auth)
            .map_err(|_| Error::Authentication)
    }
}
