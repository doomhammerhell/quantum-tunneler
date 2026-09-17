//! RFC 7296 §§2.13,2.14,2.17 arithmetic for PRF_HMAC_SHA2_256 and
//! AES-256-GCM-16. Not a negotiated profile or an authenticated IKE implementation.
use crate::{crypto::secret::SecretBytes, QuantumIpsecError as Error, Result};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use zeroize::{Zeroize, Zeroizing};
type Prf = Hmac<Sha256>;

fn prf(key: &[u8], parts: &[&[u8]]) -> Result<SecretBytes<32>> {
    let mut mac = Prf::new_from_slice(key).map_err(|_| Error::Crypto)?;
    for p in parts {
        mac.update(p);
    }
    let mut bytes = mac.finalize().into_bytes();
    let mut result = SecretBytes::new([0; 32]);
    result.expose_mut().copy_from_slice(&bytes);
    bytes.as_mut_slice().zeroize();
    Ok(result)
}
pub fn prf_plus(key: &[u8], seed: &[u8], size: usize) -> Result<Zeroizing<Vec<u8>>> {
    if key.is_empty() || size > 255 * 32 || seed.len() > 65_535 {
        return Err(Error::Crypto);
    }
    let mut result = Zeroizing::new(Vec::with_capacity(size));
    let mut previous = SecretBytes::new([0; 32]);
    for i in 1..=size.div_ceil(32) {
        previous = prf(
            key,
            &[
                if i == 1 { &[] } else { previous.expose() },
                seed,
                &[i as u8],
            ],
        )?;
        let take = (size - result.len()).min(32);
        result.extend_from_slice(&previous.expose()[..take]);
    }
    Ok(result)
}
/// AEAD profile has zero-length SK_ai/SK_ar. SK_e includes 4-byte salt.
#[derive(Debug)]
pub struct IkeKeys {
    pub sk_d: SecretBytes<32>,
    pub sk_ei: SecretBytes<36>,
    pub sk_er: SecretBytes<36>,
    pub sk_pi: SecretBytes<32>,
    pub sk_pr: SecretBytes<32>,
}
fn validate_nonces(ni: &[u8], nr: &[u8]) -> Result<()> {
    if !(16..=256).contains(&ni.len()) || !(16..=256).contains(&nr.len()) {
        return Err(Error::Crypto);
    }
    Ok(())
}
fn expand(seed: SecretBytes<32>, ni: &[u8], nr: &[u8], spii: u64, spir: u64) -> Result<IkeKeys> {
    if spii == 0 || spir == 0 {
        return Err(Error::Crypto);
    }
    let mut context = Vec::new();
    context.extend_from_slice(ni);
    context.extend_from_slice(nr);
    context.extend_from_slice(&spii.to_be_bytes());
    context.extend_from_slice(&spir.to_be_bytes());
    let material = prf_plus(seed.expose(), &context, 168)?;
    fn part<const N: usize>(data: &[u8]) -> Result<SecretBytes<N>> {
        let mut out = SecretBytes::new([0; N]);
        if data.len() != N {
            return Err(Error::Crypto);
        }
        out.expose_mut().copy_from_slice(data);
        Ok(out)
    }
    Ok(IkeKeys {
        sk_d: part(&material[..32])?,
        sk_ei: part(&material[32..68])?,
        sk_er: part(&material[68..104])?,
        sk_pi: part(&material[104..136])?,
        sk_pr: part(&material[136..168])?,
    })
}
pub fn initial_keys(
    shared: &SecretBytes<32>,
    ni: &[u8],
    nr: &[u8],
    spii: u64,
    spir: u64,
) -> Result<IkeKeys> {
    validate_nonces(ni, nr)?;
    let mut nonces = Vec::new();
    nonces.extend_from_slice(ni);
    nonces.extend_from_slice(nr);
    expand(prf(&nonces, &[shared.expose()])?, ni, nr, spii, spir)
}
/// RFC 9370 §2.2.2 sequential update only; IKE_INTERMEDIATE encryption and
/// RFC 9242 IntAuth transcript accumulation must be implemented before use.
pub fn additional_exchange(
    old_sk_d: &SecretBytes<32>,
    shared: &SecretBytes<32>,
    ni: &[u8],
    nr: &[u8],
    spii: u64,
    spir: u64,
) -> Result<IkeKeys> {
    validate_nonces(ni, nr)?;
    expand(
        prf(old_sk_d.expose(), &[shared.expose(), ni, nr])?,
        ni,
        nr,
        spii,
        spir,
    )
}
/// RFC 7296 CHILD KEYMAT, initiator direction followed by responder direction.
/// Optional fresh KE contribution precedes nonces. Returns 2*(32 key+4 salt).
pub fn child_keymat(
    sk_d: &SecretBytes<32>,
    fresh_ke: Option<&SecretBytes<32>>,
    ni: &[u8],
    nr: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    validate_nonces(ni, nr)?;
    let mut seed = Zeroizing::new(Vec::with_capacity(32 + ni.len() + nr.len()));
    if let Some(ke) = fresh_ke {
        seed.extend_from_slice(ke.expose());
    }
    seed.extend_from_slice(ni);
    seed.extend_from_slice(nr);
    prf_plus(sk_d.expose(), &seed, 72)
}
