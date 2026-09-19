//! One authenticated CREATE_CHILD_SA exchange: IPv4 host-to-host tunnel ESP.
//! No additional DH, ESN, narrowing, rekey, multiple children or transport mode.
use super::{
    auth::AuthRole,
    exchange::ExchangeType,
    parser::parse_payloads,
    proposal::parse_proposals,
    schedule::child_keymat,
    session::{open_sk, payloads, random, seal_sk, Context},
};
use crate::{
    crypto::secret::SecretBytes,
    ipsec::{
        esp,
        sa::{Direction, SaLifetime, SaMetadata, SecurityAssociation},
        utils::parse_ip_header,
    },
    keying::{
        provenance::{KeyDerivationId, KeyProvenance},
        schedule::TrafficKey,
    },
    QuantumIpsecError as Error, Result,
};
use sha2::{Digest, Sha256};
use std::net::Ipv4Addr;

/// Exact inner hosts authorized for this session's configured PSK identity pair.
/// All upper-layer protocols/ports; options and fragmented IPv4 are unsupported.
#[derive(Debug, Clone, Copy)]
pub struct ChildPolicy {
    local: Ipv4Addr,
    peer: Ipv4Addr,
}
impl ChildPolicy {
    pub fn new(local: Ipv4Addr, peer: Ipv4Addr) -> Result<Self> {
        let invalid = |ip: Ipv4Addr| ip.is_unspecified() || ip.is_multicast() || ip.is_broadcast();
        if local == peer || invalid(local) || invalid(peer) {
            return Err(Error::ConfigError(
                "distinct unicast inner IPv4 hosts required".into(),
            ));
        }
        Ok(Self { local, peer })
    }
    fn hosts(&self, role: AuthRole) -> (Ipv4Addr, Ipv4Addr) {
        if role == AuthRole::Initiator {
            (self.local, self.peer)
        } else {
            (self.peer, self.local)
        }
    }
    fn authorize(&self, packet: &[u8], next_header: u8, inbound: bool) -> Result<()> {
        if next_header != 4 {
            return Err(Error::Unsupported("IPv4 tunnel payload required"));
        }
        let h = parse_ip_header(packet)?;
        let (source, destination) = if inbound {
            (self.peer, self.local)
        } else {
            (self.local, self.peer)
        };
        if h.source != source || h.destination != destination {
            return Err(Error::Authentication);
        }
        Ok(())
    }
}

struct ChildSa {
    inbound: SecurityAssociation,
    outbound: SecurityAssociation,
    policy: ChildPolicy,
}
enum Phase {
    Ready,
    Pending {
        spi: u32,
        nonce: Vec<u8>,
        request: Vec<u8>,
    },
    Installed(Box<ChildSa>),
}
pub(super) struct ChildExchange {
    policy: ChildPolicy,
    phase: Phase,
    // AUTH consumed IV 0. Reserve before each encryption, never reset on failure.
    next_iv: u64,
}
impl ChildExchange {
    pub(super) fn new(policy: ChildPolicy) -> Self {
        Self {
            policy,
            phase: Phase::Ready,
            next_iv: 1,
        }
    }
    fn reserve_iv(&mut self) -> Result<u64> {
        let iv = self.next_iv;
        self.next_iv = iv.checked_add(1).ok_or(Error::SequenceExhausted)?;
        Ok(iv)
    }
    pub(super) fn start(&mut self, c: &Context, role: AuthRole) -> Result<Vec<u8>> {
        if role != AuthRole::Initiator || !matches!(self.phase, Phase::Ready) {
            return Err(Error::Unsupported(
                "only one initiator-created CHILD_SA allowed",
            ));
        }
        let spi = child_spi(0)?;
        let nonce = random::<32>()?.expose().to_vec();
        let plain = body(self.policy, role, spi, &nonce)?;
        let iv = self.reserve_iv()?;
        let request = seal_sk(c, role, ExchangeType::CreateChildSa, 2, iv, 33, &plain)?;
        self.phase = Phase::Pending {
            spi,
            nonce,
            request: request.clone(),
        };
        Ok(request)
    }
    pub(super) fn receive(
        &mut self,
        c: &Context,
        role: AuthRole,
        wire: &[u8],
    ) -> Result<Option<Vec<u8>>> {
        match &self.phase {
            Phase::Ready if role == AuthRole::Responder => {
                let (first, plain) =
                    open_sk(c, AuthRole::Initiator, ExchangeType::CreateChildSa, 2, wire)?;
                let offer = parse(first, &plain, self.policy, role)?;
                let spi = child_spi(offer.spi)?;
                let nonce = random::<32>()?.expose().to_vec();
                let response_body = body(self.policy, role, spi, &nonce)?;
                let iv = self.reserve_iv()?;
                let response = seal_sk(
                    c,
                    role,
                    ExchangeType::CreateChildSa,
                    2,
                    iv,
                    33,
                    &response_body,
                )?;
                let child = install(
                    c,
                    self.policy,
                    role,
                    offer.spi,
                    spi,
                    offer.nonce,
                    &nonce,
                    wire,
                    &response,
                )?;
                self.phase = Phase::Installed(Box::new(child));
                Ok(Some(response))
            }
            Phase::Pending {
                spi,
                nonce,
                request,
            } if role == AuthRole::Initiator => {
                let (first, plain) =
                    open_sk(c, AuthRole::Responder, ExchangeType::CreateChildSa, 2, wire)?;
                let accepted = parse(first, &plain, self.policy, role)?;
                if accepted.spi == *spi {
                    return Err(Error::Duplicate);
                }
                let child = install(
                    c,
                    self.policy,
                    role,
                    *spi,
                    accepted.spi,
                    nonce,
                    accepted.nonce,
                    request,
                    wire,
                )?;
                self.phase = Phase::Installed(Box::new(child));
                Ok(None)
            }
            _ => Err(Error::Unsupported("CHILD_SA exchange in this state")),
        }
    }
    pub(super) fn installed(&self) -> bool {
        matches!(&self.phase, Phase::Installed(child) if !child.inbound.is_expired() && !child.outbound.is_expired())
    }
    pub(super) fn encrypt(&mut self, packet: &[u8]) -> Result<Vec<u8>> {
        let Phase::Installed(child) = &mut self.phase else {
            return Err(Error::UnknownSa);
        };
        child.policy.authorize(packet, 4, false)?;
        esp::encrypt_packet(&mut child.outbound, packet, 4)
    }
    pub(super) fn decrypt(&mut self, wire: &[u8]) -> Result<Vec<u8>> {
        let Phase::Installed(child) = &mut self.phase else {
            return Err(Error::UnknownSa);
        };
        Ok(
            esp::decrypt_packet_checked(&mut child.inbound, wire, |packet, next| {
                child.policy.authorize(packet, next, true)
            })?
            .payload,
        )
    }
    pub(super) fn metadata(&self) -> Option<[SaMetadata<'_>; 2]> {
        let Phase::Installed(child) = &self.phase else {
            return None;
        };
        Some([child.inbound.metadata(), child.outbound.metadata()])
    }
}
fn child_spi(exclude: u32) -> Result<u32> {
    for _ in 0..8 {
        let spi = u32::from_be_bytes(*random::<4>()?.expose());
        if spi >= 256 && spi != exclude {
            return Ok(spi);
        }
    }
    Err(Error::Crypto)
}
fn selector(ip: Ipv4Addr) -> Vec<u8> {
    let mut body = vec![1, 0, 0, 0, 7, 0, 0, 16, 0, 0, 255, 255];
    body.extend_from_slice(&ip.octets());
    body.extend_from_slice(&ip.octets());
    body
}
fn proposal(spi: u32) -> Vec<u8> {
    let mut body = vec![0, 0, 0, 32, 1, 3, 4, 2];
    body.extend_from_slice(&spi.to_be_bytes());
    body.extend_from_slice(&[
        3, 0, 0, 12, 1, 0, 0, 20, 0x80, 14, 1, 0, 0, 0, 0, 8, 5, 0, 0, 0,
    ]);
    body
}
fn body(policy: ChildPolicy, role: AuthRole, spi: u32, nonce: &[u8]) -> Result<Vec<u8>> {
    let (i, r) = policy.hosts(role);
    payloads(&[
        (33, &proposal(spi)),
        (40, nonce),
        (44, &selector(i)),
        (45, &selector(r)),
    ])
}
struct Offer<'a> {
    spi: u32,
    nonce: &'a [u8],
}
fn parse<'a>(first: u8, plain: &'a [u8], policy: ChildPolicy, role: AuthRole) -> Result<Offer<'a>> {
    let p = parse_payloads(first, plain)?;
    if p.iter().map(|p| p.kind).collect::<Vec<_>>() != [33, 40, 44, 45] {
        return Err(Error::Unsupported(
            "CHILD_SA requires SA, nonce, TSi, TSr only",
        ));
    }
    let proposals = parse_proposals(p[0].body)?;
    if proposals.len() != 1 {
        return Err(Error::Unsupported("CHILD_SA proposal alternatives"));
    }
    let sa = &proposals[0];
    if sa.number != 1 || sa.protocol != 3 || sa.spi.len() != 4 || sa.transforms.len() != 2 {
        return Err(Error::Unsupported("CHILD_SA ESP proposal"));
    }
    for (kind, id, attributes) in [(1, 20, &[0x80, 14, 1, 0][..]), (5, 0, &[][..])] {
        if sa
            .transforms
            .iter()
            .filter(|t| t.kind == kind && t.id == id && t.attributes == attributes)
            .count()
            != 1
        {
            return Err(Error::Unsupported(
                "CHILD_SA AES-GCM-256 without ESN required",
            ));
        }
    }
    let spi = u32::from_be_bytes(sa.spi.try_into().map_err(|_| Error::Crypto)?);
    if spi < 256 {
        return Err(Error::UnknownSa);
    }
    let (i, r) = policy.hosts(role);
    for (payload, host) in [(&p[2], i), (&p[3], r)] {
        let expected = selector(host);
        // Reserved bytes ignored on receipt; SK authenticates their wire value.
        if payload.body.len() != 20 || payload.body[0] != 1 || payload.body[4..] != expected[4..] {
            return Err(Error::Authentication);
        }
    }
    Ok(Offer {
        spi,
        nonce: p[1].body,
    })
}
// Both SAs are built privately, then published together. No partially installed
// pair or publicly importable/exportable key material can reset ESP counters.
#[allow(clippy::too_many_arguments)]
fn install(
    c: &Context,
    policy: ChildPolicy,
    role: AuthRole,
    spii: u32,
    spir: u32,
    ni: &[u8],
    nr: &[u8],
    request: &[u8],
    response: &[u8],
) -> Result<ChildSa> {
    let material = child_keymat(&c.keys.sk_d, None, ni, nr)?;
    let mut session = Sha256::new();
    session.update(b"ike-session");
    session.update(&c.request);
    session.update(&c.response);
    let mut transcript = Sha256::new();
    for bytes in [&c.request[..], &c.response[..], request, response] {
        transcript.update(bytes);
    }
    let provenance = KeyProvenance {
        derivation: KeyDerivationId::IkeV2PrfHmacSha256,
        session_id: session.finalize().into(),
        transcript_hash: transcript.finalize().into(),
        generation: 1,
    };
    let make = |spi, direction, bytes: &[u8]| -> Result<SecurityAssociation> {
        let key = TrafficKey {
            key: SecretBytes::new(bytes[..32].try_into().map_err(|_| Error::Crypto)?),
            salt: SecretBytes::new(bytes[32..36].try_into().map_err(|_| Error::Crypto)?),
            spi,
            provenance: provenance.clone(),
        };
        SecurityAssociation::new(
            spi,
            direction,
            key,
            SaLifetime::default(),
            provenance.clone(),
        )
    };
    // Initiator-to-responder KEYMAT comes first; the receiver selected its SPI.
    let (outbound, inbound) = if role == AuthRole::Initiator {
        (
            make(spir, Direction::Outbound, &material[..36])?,
            make(spii, Direction::Inbound, &material[36..])?,
        )
    } else {
        (
            make(spii, Direction::Outbound, &material[36..])?,
            make(spir, Direction::Inbound, &material[..36])?,
        )
    };
    Ok(ChildSa {
        inbound,
        outbound,
        policy,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use x25519_dalek::{PublicKey, StaticSecret};
    fn context() -> Context {
        let initial: Vec<_> = include_str!("../../tests/fixtures/ike_session.hex")
            .lines()
            .map(|l| crate::utils::hex_to_bytes(l).unwrap())
            .collect();
        let a = StaticSecret::from(core::array::from_fn::<_, 32, _>(|i| i as u8 + 1));
        let b = StaticSecret::from(core::array::from_fn::<_, 32, _>(|i| i as u8 + 33));
        let shared = SecretBytes::new(*a.diffie_hellman(&PublicKey::from(&b)).as_bytes());
        Context {
            spii: 1,
            spir: 2,
            request: initial[0].clone(),
            response: initial[1].clone(),
            ni: vec![0x11; 32],
            nr: vec![0x22; 32],
            keys: super::super::schedule::initial_keys(&shared, &[0x11; 32], &[0x22; 32], 1, 2)
                .unwrap(),
        }
    }
    fn policies() -> (ChildPolicy, ChildPolicy) {
        (
            ChildPolicy::new("10.0.0.1".parse().unwrap(), "10.0.0.2".parse().unwrap()).unwrap(),
            ChildPolicy::new("10.0.0.2".parse().unwrap(), "10.0.0.1".parse().unwrap()).unwrap(),
        )
    }
    fn vectors() -> Vec<Vec<u8>> {
        include_str!("../../tests/fixtures/ike_child.hex")
            .lines()
            .map(|l| crate::utils::hex_to_bytes(l).unwrap())
            .collect()
    }
    #[test]
    fn independent_child_and_bidirectional_esp_wire_vectors() {
        let c = context();
        let (i, r) = policies();
        let v = vectors();
        for (role, policy, spi, nonce, expected) in [
            (AuthRole::Initiator, i, 256, 0x33, &v[0]),
            (AuthRole::Responder, r, 257, 0x44, &v[1]),
        ] {
            let plain = body(policy, role, spi, &[nonce; 32]).unwrap();
            assert_eq!(
                &seal_sk(&c, role, ExchangeType::CreateChildSa, 2, 1, 33, &plain).unwrap(),
                expected
            );
            let (first, decrypted) =
                open_sk(&c, role, ExchangeType::CreateChildSa, 2, expected).unwrap();
            assert_eq!(parse(first, &decrypted, policy, role).unwrap().spi, spi);
        }
        let mut initiator = install(
            &c,
            i,
            AuthRole::Initiator,
            256,
            257,
            &[0x33; 32],
            &[0x44; 32],
            &v[0],
            &v[1],
        )
        .unwrap();
        let mut responder = install(
            &c,
            r,
            AuthRole::Responder,
            256,
            257,
            &[0x33; 32],
            &[0x44; 32],
            &v[0],
            &v[1],
        )
        .unwrap();
        assert_eq!(
            esp::encrypt_packet(&mut initiator.outbound, &v[2], 4).unwrap(),
            v[3]
        );
        assert_eq!(
            esp::decrypt_packet_checked(&mut responder.inbound, &v[3], |p, n| r
                .authorize(p, n, true))
            .unwrap()
            .payload,
            v[2]
        );
        assert_eq!(
            esp::encrypt_packet(&mut responder.outbound, &v[4], 4).unwrap(),
            v[5]
        );
        assert_eq!(
            esp::decrypt_packet_checked(&mut initiator.inbound, &v[5], |p, n| i
                .authorize(p, n, true))
            .unwrap()
            .payload,
            v[4]
        );
    }
    #[test]
    fn authenticated_bad_proposals_and_selectors_never_install() {
        let c = context();
        let (i, r) = policies();
        let mut exchange = ChildExchange::new(r);
        let original = body(i, AuthRole::Initiator, 256, &[0x33; 32]).unwrap();
        for index in [9, 14, 23, 35, 95] {
            let mut plain = original.clone();
            plain[index] ^= 1;
            // Test-only adversarial envelopes under known fixture keys.
            let wire = seal_sk(
                &c,
                AuthRole::Initiator,
                ExchangeType::CreateChildSa,
                2,
                index as u64 + 1,
                33,
                &plain,
            )
            .unwrap();
            assert!(
                exchange.receive(&c, AuthRole::Responder, &wire).is_err(),
                "{index}"
            );
            assert!(!exchange.installed());
            assert_eq!(exchange.next_iv, 1);
        }
        exchange.next_iv = u64::MAX;
        assert_eq!(exchange.reserve_iv(), Err(Error::SequenceExhausted));
        assert_eq!(exchange.next_iv, u64::MAX);
    }
    #[test]
    fn inbound_policy_failure_does_not_commit_replay_or_accounting() {
        let c = context();
        let (i, r) = policies();
        let v = vectors();
        let mut sender = install(
            &c,
            i,
            AuthRole::Initiator,
            256,
            257,
            &[0x33; 32],
            &[0x44; 32],
            &v[0],
            &v[1],
        )
        .unwrap();
        let receiver = install(
            &c,
            r,
            AuthRole::Responder,
            256,
            257,
            &[0x33; 32],
            &[0x44; 32],
            &v[0],
            &v[1],
        )
        .unwrap();
        let mut exchange = ChildExchange::new(r);
        exchange.phase = Phase::Installed(Box::new(receiver));
        // Deliberately bypass sender policy to model a malicious authenticated peer.
        let bad = esp::encrypt_packet(&mut sender.outbound, &v[4], 4).unwrap();
        assert_eq!(exchange.decrypt(&bad), Err(Error::Authentication));
        assert_eq!(exchange.decrypt(&bad), Err(Error::Authentication));
        assert_eq!(exchange.metadata().unwrap()[0].packets, 0);
        let good = esp::encrypt_packet(&mut sender.outbound, &v[2], 4).unwrap();
        assert_eq!(exchange.decrypt(&good).unwrap(), v[2]);
    }
}
