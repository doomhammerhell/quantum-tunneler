//! Syntax validation only. Transform IDs are untrusted numeric registry values;
//! a proposal being well-formed does not mean its algorithms are supported.
use super::parser::{ParseError, ParseResult, Reader};
pub const MAX_PROPOSALS: usize = 16;
pub const MAX_TRANSFORMS: usize = 32;
#[derive(Debug)]
pub struct Proposal<'a> {
    pub number: u8,
    pub protocol: u8,
    pub spi: &'a [u8],
    pub transforms: Vec<Transform<'a>>,
}
#[derive(Debug)]
pub struct Transform<'a> {
    pub kind: u8,
    pub id: u16,
    pub attributes: &'a [u8],
}
pub fn parse_proposals(data: &[u8]) -> ParseResult<Vec<Proposal<'_>>> {
    if data.len() > super::parser::MAX_IKE_MESSAGE - 28 {
        return Err(ParseError::Limit);
    }
    let mut r = Reader::new(data);
    let mut proposals = Vec::new();
    let mut previous = 0u8;
    loop {
        if proposals.len() >= MAX_PROPOSALS {
            return Err(ParseError::Limit);
        }
        let more = r.u8()?;
        r.u8()?;
        let len = r.u16()? as usize;
        let mut p = Reader::new(r.take(len.checked_sub(4).ok_or(ParseError::Length)?)?);
        let number = p.u8()?;
        let protocol = p.u8()?;
        let spi_size = p.u8()? as usize;
        let count = p.u8()? as usize;
        if number == 0
            || number <= previous
            || !matches!((protocol, spi_size), (1, 0) | (1, 8) | (2, 4) | (3, 4))
            || count == 0
        {
            return Err(ParseError::Proposal);
        }
        if count > MAX_TRANSFORMS {
            return Err(ParseError::Limit);
        }
        previous = number;
        let spi = p.take(spi_size)?;
        let mut transforms = Vec::with_capacity(count);
        for index in 0..count {
            let last = p.u8()?;
            p.u8()?;
            let len = p.u16()? as usize;
            if last != if index + 1 == count { 0 } else { 3 } {
                return Err(ParseError::Proposal);
            }
            let mut t = Reader::new(p.take(len.checked_sub(4).ok_or(ParseError::Length)?)?);
            let kind = t.u8()?;
            t.u8()?;
            let id = t.u16()?;
            let attributes = t.take(t.remaining())?;
            validate_attributes(attributes)?;
            transforms.push(Transform {
                kind,
                id,
                attributes,
            });
        }
        if p.remaining() != 0 {
            return Err(ParseError::Length);
        }
        proposals.push(Proposal {
            number,
            protocol,
            spi,
            transforms,
        });
        match more {
            0 if r.remaining() == 0 => break,
            2 if r.remaining() > 0 => {}
            _ => return Err(ParseError::Proposal),
        }
    }
    Ok(proposals)
}
fn validate_attributes(data: &[u8]) -> ParseResult<()> {
    let mut r = Reader::new(data);
    let mut count = 0;
    while r.remaining() > 0 {
        count += 1;
        if count > 32 {
            return Err(ParseError::Limit);
        }
        let kind = r.u16()?;
        let value = r.u16()?;
        if kind & 0x8000 == 0 {
            r.take(value as usize)?;
        }
    }
    Ok(())
}
