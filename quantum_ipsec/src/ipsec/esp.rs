//! RFC 4106 packet profile: SPI|SEQ|IV(8)|encrypted(payload|padding|PL|NH)|tag(16).
//! Non-ESN, AES-256-GCM only. Receives previously provisioned directional keys.
use super::sa::{Direction, SecurityAssociation};
use crate::{crypto::symmetric, QuantumIpsecError as Error, Result};
use zeroize::Zeroizing;
pub const MAX_ESP_PACKET: usize = 65_535;
pub const MAX_PLAINTEXT: usize = MAX_ESP_PACKET - 40;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EspHeader {
    pub spi: u32,
    pub sequence: u32,
}
#[derive(Debug)]
pub struct EspPacket<'a> {
    pub header: EspHeader,
    pub iv: [u8; 8],
    pub ciphertext: &'a [u8],
    pub tag: [u8; 16],
}
#[derive(Debug, PartialEq, Eq)]
pub struct Decapsulated {
    pub payload: Vec<u8>,
    pub next_header: u8,
}
impl<'a> EspPacket<'a> {
    pub fn parse(data: &'a [u8]) -> Result<Self> {
        if data.len() < 36 || data.len() > MAX_ESP_PACKET || !data.len().is_multiple_of(4) {
            return Err(Error::PacketError("ESP size".into()));
        }
        let spi = u32::from_be_bytes(data[0..4].try_into().map_err(|_| Error::Crypto)?);
        let sequence = u32::from_be_bytes(data[4..8].try_into().map_err(|_| Error::Crypto)?);
        if spi < 256 || sequence == 0 {
            return Err(Error::PacketError("ESP SPI or sequence".into()));
        }
        Ok(Self {
            header: EspHeader { spi, sequence },
            iv: data[8..16].try_into().map_err(|_| Error::Crypto)?,
            ciphertext: &data[16..data.len() - 16],
            tag: data[data.len() - 16..]
                .try_into()
                .map_err(|_| Error::Crypto)?,
        })
    }
}
/// Salt is per key, IV is the zero-extended packet counter. Never reset counter
/// with the same key. Inbound peers may use any unique 64-bit explicit IV.
pub fn nonce(salt: &[u8; 4], iv: &[u8; 8]) -> [u8; 12] {
    let mut n = [0; 12];
    n[..4].copy_from_slice(salt);
    n[4..].copy_from_slice(iv);
    n
}
pub fn encrypt_packet(
    sa: &mut SecurityAssociation,
    plaintext: &[u8],
    next_header: u8,
) -> Result<Vec<u8>> {
    if plaintext.len() > MAX_PLAINTEXT {
        return Err(Error::PacketError("ESP plaintext too large".into()));
    }
    let padding = (4 - (plaintext.len() + 2) % 4) % 4;
    let protected_len = plaintext.len() + padding + 2;
    sa.check_use(Direction::Outbound, protected_len)?;
    // Reserve before encryption: even a failed seal must never reuse a nonce.
    let sequence = sa.reserve_sequence()?;
    let iv = u64::from(sequence).to_be_bytes();
    let mut output = Vec::with_capacity(32 + protected_len);
    output.extend_from_slice(&sa.spi().to_be_bytes());
    output.extend_from_slice(&sequence.to_be_bytes());
    output.extend_from_slice(&iv);
    let mut body = Zeroizing::new(Vec::with_capacity(protected_len));
    body.extend_from_slice(plaintext);
    for i in 1..=padding {
        body.push(i as u8);
    }
    body.push(padding as u8);
    body.push(next_header);
    let tag = symmetric::seal(
        sa.traffic_key.key.expose(),
        &nonce(sa.traffic_key.salt.expose(), &iv),
        &output[..8],
        &mut body,
    )?;
    output.extend_from_slice(&body);
    output.extend_from_slice(&tag);
    sa.account(protected_len);
    Ok(output)
}
pub fn decrypt_packet(sa: &mut SecurityAssociation, data: &[u8]) -> Result<Decapsulated> {
    decrypt_packet_checked(sa, data, |_, _| Ok(()))
}
/// Enforce negotiated selectors before committing replay/counters or releasing plaintext.
pub(crate) fn decrypt_packet_checked(
    sa: &mut SecurityAssociation,
    data: &[u8],
    authorize: impl FnOnce(&[u8], u8) -> Result<()>,
) -> Result<Decapsulated> {
    let packet = EspPacket::parse(data)?;
    if packet.header.spi != sa.spi() {
        return Err(Error::UnknownSa);
    }
    sa.check_use(Direction::Inbound, packet.ciphertext.len())?;
    sa.replay.check(packet.header.sequence)?;
    let mut body = Zeroizing::new(packet.ciphertext.to_vec());
    symmetric::open(
        sa.traffic_key.key.expose(),
        &nonce(sa.traffic_key.salt.expose(), &packet.iv),
        &data[..8],
        &mut body,
        &packet.tag,
    )?;
    let end = body.len(); // parser guarantees at least four encrypted bytes
    let pad_len = usize::from(body[end - 2]);
    let next_header = body[end - 1];
    let payload_end = (end - 2)
        .checked_sub(pad_len)
        .ok_or_else(|| Error::PacketError("ESP padding length".into()))?;
    if body[payload_end..end - 2]
        .iter()
        .enumerate()
        .any(|(i, b)| *b != (i + 1) as u8)
    {
        return Err(Error::PacketError("ESP padding".into()));
    }
    // Exclusive SA access makes check/authenticate/commit one atomic operation.
    // Neither forged high sequences nor bad padding can poison the window.
    authorize(&body[..payload_end], next_header)?;
    sa.replay.commit(packet.header.sequence)?;
    sa.account(packet.ciphertext.len());
    Ok(Decapsulated {
        payload: body[..payload_end].to_vec(),
        next_header,
    })
}
