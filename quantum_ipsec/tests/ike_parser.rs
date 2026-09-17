use proptest::prelude::*;
use quantum_ipsec::ike::{
    parser::{self, ParseError},
    proposal::parse_proposals,
    IkeMessage, IkeProcessor, SessionState,
};
fn packet(kind: u8, body: &[u8]) -> Vec<u8> {
    let mut out = vec![0; 28];
    out[7] = 1;
    out[16] = kind;
    out[17] = 0x20;
    out[18] = 34;
    out[19] = 8;
    out.extend_from_slice(body);
    let len = out.len() as u32;
    out[24..28].copy_from_slice(&len.to_be_bytes());
    out
}
fn nonce() -> Vec<u8> {
    let mut n = vec![0, 0, 0, 20];
    n.extend_from_slice(&[1; 16]);
    n
}
#[test]
fn correct_wire_header_and_round_trip() {
    let p = packet(40, &nonce());
    let msg = parser::parse_message(&p).unwrap();
    assert_eq!(msg.header.version, 0x20);
    assert_eq!(msg.header.initiator_spi, 1);
    assert_eq!(msg.payloads[0].body, &[1; 16]);
    assert_eq!(msg.serialize().unwrap(), p);
    let auth = {
        let mut p = packet(0, &[]);
        p[15] = 2;
        p[18] = 35;
        p[23] = 1;
        p
    };
    assert!(parser::parse_header(&auth).is_ok());
}
#[test]
fn all_truncations_rejected() {
    let wire = packet(40, &nonce());
    for n in 0..wire.len() {
        assert!(parser::parse_message(&wire[..n]).is_err());
    }
}
#[test]
fn length_spi_version_exchange_and_message_id() {
    let wire = packet(40, &nonce());
    for (offset, value) in [(7, 0), (17, 0x10), (18, 39), (23, 1), (27, 0), (15, 1)] {
        let mut bad = wire.clone();
        bad[offset] = value;
        assert!(parser::parse_message(&bad).is_err());
    }
    let mut extra = wire.clone();
    extra.push(0);
    assert!(parser::parse_message(&extra).is_err());
}
#[test]
fn unknown_critical_and_noncritical() {
    assert!(parser::parse_message(&packet(250, &[0, 0, 0, 4])).is_ok());
    assert_eq!(
        parser::parse_message(&packet(250, &[0, 128, 0, 4])).unwrap_err(),
        ParseError::CriticalPayload
    );
}
#[test]
fn duplicate_nonce_and_invalid_chain() {
    let mut body = nonce();
    body[0] = 40;
    body.extend_from_slice(&nonce());
    assert_eq!(
        parser::parse_message(&packet(40, &body)).unwrap_err(),
        ParseError::Duplicate
    );
    let mut bad = nonce();
    bad[0] = 40;
    assert!(parser::parse_message(&packet(40, &bad)).is_err());
    assert!(parser::parse_message(&packet(0, &nonce())).is_err());
    assert!(parser::parse_message(&packet(40, &[0, 0, 0, 3])).is_err());
}
#[test]
fn limits_before_allocation() {
    assert!(parser::parse_header(&vec![0; 65_536]).is_err());
    let mut vendor = vec![0, 0, 4, 5];
    vendor.extend_from_slice(&vec![0; 1025]);
    assert_eq!(
        parser::parse_message(&packet(43, &vendor)).unwrap_err(),
        ParseError::Limit
    );
    let mut body = Vec::new();
    for i in 0..65 {
        body.extend_from_slice(&[if i == 64 { 0 } else { 250 }, 0, 0, 4]);
    }
    assert_eq!(
        parser::parse_message(&packet(250, &body)).unwrap_err(),
        ParseError::Limit
    );
}
#[test]
fn encrypted_payload_is_terminal_and_not_parsed_as_plaintext() {
    let mut wire = packet(46, &[39, 0, 0, 8, 1, 2, 3, 4]);
    wire[18] = 35;
    wire[15] = 2;
    wire[23] = 1;
    let msg = parser::parse_message(&wire).unwrap();
    assert_eq!(msg.payloads.len(), 1);
    assert_eq!(msg.payloads[0].next_payload, 39);
    assert_eq!(msg.serialize().unwrap(), wire);
    wire.push(0);
    let len = wire.len() as u32;
    wire[24..28].copy_from_slice(&len.to_be_bytes());
    assert!(parser::parse_message(&wire).is_err());
}
#[test]
fn proposal_structure_and_nested_lengths() {
    // IKE initial proposal, PRF_HMAC_SHA2_256 transform (not a complete suite).
    let p = [0, 0, 0, 16, 1, 1, 0, 1, 0, 0, 0, 8, 2, 0, 0, 5];
    assert_eq!(parse_proposals(&p).unwrap()[0].transforms[0].id, 5);
    for n in 0..p.len() {
        assert!(parse_proposals(&p[..n]).is_err());
    }
    let mut bad = p;
    bad[7] = 2;
    assert!(parse_proposals(&bad).is_err());
    let mut bad = p;
    bad[8] = 3;
    assert!(parse_proposals(&bad).is_err());
    let mut bad = p;
    bad[6] = 4;
    assert!(parse_proposals(&bad).is_err());
}
#[test]
fn no_message_can_fake_authentication() {
    let mut ike = IkeProcessor::new();
    assert!(ike.process(&packet(40, &nonce())).is_err());
    assert_eq!(ike.state(), SessionState::Failed);
    assert!(ike.connect().is_err());
}
proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]
    #[test] fn parsers_are_deterministic_and_panic_free(data in prop::collection::vec(any::<u8>(),0..4096)) {
        let a=parser::parse_message(&data);let b=IkeMessage::deserialize(&data);prop_assert_eq!(a,b);
        let _=parser::parse_payloads(data.first().copied().unwrap_or(0),&data);let _=parse_proposals(&data);
    }
}
