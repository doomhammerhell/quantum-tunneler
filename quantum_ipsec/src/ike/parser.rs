//! Bounded structural IKEv2 parser. Parsing is never peer authentication.
use super::exchange::{ExchangeType, IkeHeader, IkeMessage, Payload};
use thiserror::Error;
pub const MAX_IKE_MESSAGE: usize = 65_535;
pub const MAX_PAYLOADS: usize = 64;
pub const MAX_CERTIFICATE: usize = 16_384;
pub const MAX_AUTH: usize = 16_384;
pub const MAX_KE: usize = 16_384;
pub const MAX_VENDOR: usize = 1024;
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum ParseError {
    #[error("truncated input")]
    Truncated,
    #[error("invalid length")]
    Length,
    #[error("resource limit")]
    Limit,
    #[error("unsupported version")]
    Version,
    #[error("unsupported exchange")]
    Exchange,
    #[error("invalid SPI")]
    Spi,
    #[error("invalid flags")]
    Flags,
    #[error("invalid message ID")]
    MessageId,
    #[error("unsupported critical payload")]
    CriticalPayload,
    #[error("invalid payload chain")]
    Chain,
    #[error("duplicate singleton payload")]
    Duplicate,
    #[error("invalid payload body")]
    Payload,
    #[error("invalid proposal")]
    Proposal,
    #[error("unsupported fragmented IKE")]
    Fragmentation,
}
pub type ParseResult<T> = std::result::Result<T, ParseError>;
pub(crate) struct Reader<'a> {
    data: &'a [u8],
}
impl<'a> Reader<'a> {
    pub(crate) fn new(data: &'a [u8]) -> Self {
        Self { data }
    }
    pub(crate) fn remaining(&self) -> usize {
        self.data.len()
    }
    pub(crate) fn take(&mut self, n: usize) -> ParseResult<&'a [u8]> {
        let out = self.data.get(..n).ok_or(ParseError::Truncated)?;
        self.data = self.data.get(n..).ok_or(ParseError::Truncated)?;
        Ok(out)
    }
    pub(crate) fn u8(&mut self) -> ParseResult<u8> {
        self.take(1)?.first().copied().ok_or(ParseError::Truncated)
    }
    pub(crate) fn u16(&mut self) -> ParseResult<u16> {
        Ok(u16::from_be_bytes(
            self.take(2)?
                .try_into()
                .map_err(|_| ParseError::Truncated)?,
        ))
    }
    pub(crate) fn u32(&mut self) -> ParseResult<u32> {
        Ok(u32::from_be_bytes(
            self.take(4)?
                .try_into()
                .map_err(|_| ParseError::Truncated)?,
        ))
    }
    pub(crate) fn u64(&mut self) -> ParseResult<u64> {
        Ok(u64::from_be_bytes(
            self.take(8)?
                .try_into()
                .map_err(|_| ParseError::Truncated)?,
        ))
    }
}
pub fn parse_header(data: &[u8]) -> ParseResult<IkeHeader> {
    if data.len() > MAX_IKE_MESSAGE {
        return Err(ParseError::Limit);
    }
    let mut r = Reader::new(data);
    let initiator_spi = r.u64()?;
    let responder_spi = r.u64()?;
    let next_payload = r.u8()?;
    let version = r.u8()?;
    let exchange_type = ExchangeType::try_from(r.u8()?)?;
    let flags = r.u8()?;
    let message_id = r.u32()?;
    let length = r.u32()?;
    if version >> 4 != 2 {
        return Err(ParseError::Version);
    }
    if length as usize != data.len() {
        return Err(ParseError::Length);
    }
    if initiator_spi == 0 {
        return Err(ParseError::Spi);
    }
    // Reserved bits are ignored on receipt per RFC 7296; only defined flags used.
    if exchange_type == ExchangeType::IkeSaInit {
        if message_id != 0 {
            return Err(ParseError::MessageId);
        }
        if flags & 0x20 == 0 && (responder_spi != 0 || flags & 0x08 == 0) {
            return Err(ParseError::Spi);
        }
        if flags & 0x20 != 0 && flags & 0x08 != 0 {
            return Err(ParseError::Flags);
        }
    } else if responder_spi == 0 {
        return Err(ParseError::Spi);
    }
    Ok(IkeHeader {
        initiator_spi,
        responder_spi,
        next_payload,
        version,
        exchange_type,
        flags,
        message_id,
        length,
    })
}
pub fn parse_message(data: &[u8]) -> ParseResult<IkeMessage<'_>> {
    let header = parse_header(data)?;
    let payloads = parse_payloads(
        header.next_payload,
        data.get(28..).ok_or(ParseError::Truncated)?,
    )?;
    if header.exchange_type == ExchangeType::IkeSaInit && payloads.iter().any(|p| p.kind == 46) {
        return Err(ParseError::Payload);
    }
    Ok(IkeMessage { header, payloads })
}
/// SK is opaque: its next-payload describes decrypted content, not another
/// outer payload. Decrypted inner parsing requires a separately authenticated API.
pub fn parse_payloads(mut kind: u8, data: &[u8]) -> ParseResult<Vec<Payload<'_>>> {
    if data.len() > MAX_IKE_MESSAGE - 28 {
        return Err(ParseError::Limit);
    }
    let mut r = Reader::new(data);
    let mut result = Vec::new();
    let mut seen = [false; 256];
    while kind != 0 {
        if result.len() >= MAX_PAYLOADS {
            return Err(ParseError::Limit);
        }
        let next = r.u8()?;
        let flags = r.u8()?;
        let length = usize::from(r.u16()?);
        let size = length.checked_sub(4).ok_or(ParseError::Length)?;
        if kind == 53 {
            return Err(ParseError::Fragmentation);
        }
        let known = (33..=48).contains(&kind);
        if !known && flags & 0x80 != 0 {
            return Err(ParseError::CriticalPayload);
        }
        let singleton = matches!(kind, 33..=36 | 39 | 40 | 44..=48);
        if singleton && seen[kind as usize] {
            return Err(ParseError::Duplicate);
        }
        seen[kind as usize] = true;
        let limit = match kind {
            34 => MAX_KE,
            37 | 38 => MAX_CERTIFICATE,
            39 => MAX_AUTH,
            43 => MAX_VENDOR,
            _ => MAX_IKE_MESSAGE - 28,
        };
        if size > limit {
            return Err(ParseError::Limit);
        }
        let body = r.take(size)?;
        match kind {
            33 => {
                super::proposal::parse_proposals(body)?;
            }
            34 if size < 5 => return Err(ParseError::Payload),
            35 | 36 | 39 if size < 5 => return Err(ParseError::Payload),
            37 | 38 if size < 1 => return Err(ParseError::Payload),
            40 if !(16..=256).contains(&size) => return Err(ParseError::Payload),
            41 => {
                let mut n = Reader::new(body);
                n.u8()?;
                let spi_len = n.u8()? as usize;
                n.u16()?;
                n.take(spi_len)?;
            }
            42 => {
                let mut d = Reader::new(body);
                let protocol = d.u8()?;
                let spi_len = d.u8()? as usize;
                let count = d.u16()? as usize;
                if !matches!((protocol, spi_len), (1, 0) | (2, 4) | (3, 4))
                    || (protocol == 1 && count != 0)
                    || d.remaining() != spi_len * count
                {
                    return Err(ParseError::Payload);
                }
            }
            44 | 45 => validate_selectors(body)?,
            46 if size < 1 => return Err(ParseError::Payload),
            47 if size < 4 => return Err(ParseError::Payload),
            48 if size < 4 => return Err(ParseError::Payload),
            _ => {}
        }
        result.push(Payload {
            kind,
            critical: flags & 0x80 != 0,
            next_payload: next,
            body,
        });
        if kind == 46 {
            if r.remaining() != 0 {
                return Err(ParseError::Chain);
            }
            return Ok(result);
        }
        kind = next;
    }
    if r.remaining() != 0 {
        return Err(ParseError::Chain);
    }
    Ok(result)
}
fn validate_selectors(body: &[u8]) -> ParseResult<()> {
    let mut r = Reader::new(body);
    let count = r.u8()?;
    r.take(3)?;
    if count == 0 || count > 32 {
        return Err(ParseError::Limit);
    }
    for _ in 0..count {
        let kind = r.u8()?;
        r.u8()?;
        let len = r.u16()?;
        let expected = match kind {
            7 => 16,
            8 => 40,
            _ => return Err(ParseError::Payload),
        };
        if len != expected {
            return Err(ParseError::Length);
        }
        let start = r.u16()?;
        let end = r.u16()?;
        if start > end {
            return Err(ParseError::Payload);
        }
        let size = if kind == 7 { 4 } else { 16 };
        let first = r.take(size)?;
        let last = r.take(size)?;
        if first > last {
            return Err(ParseError::Payload);
        }
    }
    if r.remaining() != 0 {
        return Err(ParseError::Length);
    }
    Ok(())
}
