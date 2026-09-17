use super::parser::{parse_message, ParseError, ParseResult, MAX_IKE_MESSAGE};
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ExchangeType {
    IkeSaInit = 34,
    IkeAuth = 35,
    CreateChildSa = 36,
    Informational = 37,
    IkeIntermediate = 43,
    IkeFollowupKe = 44,
}
impl TryFrom<u8> for ExchangeType {
    type Error = ParseError;
    fn try_from(v: u8) -> ParseResult<Self> {
        match v {
            34 => Ok(Self::IkeSaInit),
            35 => Ok(Self::IkeAuth),
            36 => Ok(Self::CreateChildSa),
            37 => Ok(Self::Informational),
            43 => Ok(Self::IkeIntermediate),
            44 => Ok(Self::IkeFollowupKe),
            _ => Err(ParseError::Exchange),
        }
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IkeHeader {
    pub initiator_spi: u64,
    pub responder_spi: u64,
    pub next_payload: u8,
    pub version: u8,
    pub exchange_type: ExchangeType,
    pub flags: u8,
    pub message_id: u32,
    pub length: u32,
}
#[derive(Debug, PartialEq, Eq)]
pub struct Payload<'a> {
    pub kind: u8,
    pub critical: bool,
    pub next_payload: u8,
    pub body: &'a [u8],
}
#[derive(Debug, PartialEq, Eq)]
pub struct IkeMessage<'a> {
    pub header: IkeHeader,
    pub payloads: Vec<Payload<'a>>,
}
impl<'a> IkeMessage<'a> {
    pub fn deserialize(data: &'a [u8]) -> ParseResult<Self> {
        parse_message(data)
    }
    pub fn serialize(&self) -> ParseResult<Vec<u8>> {
        let mut size = 28usize;
        for p in &self.payloads {
            size = size
                .checked_add(4)
                .and_then(|s| s.checked_add(p.body.len()))
                .ok_or(ParseError::Limit)?;
        }
        if size > MAX_IKE_MESSAGE {
            return Err(ParseError::Limit);
        }
        let h = &self.header;
        let mut out = Vec::with_capacity(size);
        out.extend_from_slice(&h.initiator_spi.to_be_bytes());
        out.extend_from_slice(&h.responder_spi.to_be_bytes());
        out.extend_from_slice(&[h.next_payload, h.version, h.exchange_type as u8, h.flags]);
        out.extend_from_slice(&h.message_id.to_be_bytes());
        out.extend_from_slice(&(size as u32).to_be_bytes());
        let mut expected = h.next_payload;
        for p in &self.payloads {
            if p.kind != expected {
                return Err(ParseError::Chain);
            }
            expected = p.next_payload;
            let length = u16::try_from(p.body.len() + 4).map_err(|_| ParseError::Limit)?;
            out.extend_from_slice(&[p.next_payload, if p.critical { 0x80 } else { 0 }]);
            out.extend_from_slice(&length.to_be_bytes());
            out.extend_from_slice(p.body);
        }
        parse_message(&out)?;
        Ok(out)
    }
}
