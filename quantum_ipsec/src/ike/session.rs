//! Opt-in, transport-independent childless PSK IKE SA establishment.
//! Fixed profile: X25519 / PRF_HMAC_SHA2_256 / AES-256-GCM-16.
use super::{
    auth::{AuthRole, PskAuth},
    child::{ChildExchange, ChildPolicy},
    exchange::ExchangeType,
    parser::{parse_message, parse_payloads},
    proposal::parse_proposals,
    schedule::{initial_keys, IkeKeys},
    SessionState,
};
use crate::{
    crypto::{secret::SecretBytes, symmetric},
    QuantumIpsecError as Error, Result,
};
use std::time::{Duration, Instant};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

const CHILDLESS: &[u8] = &[1, 0, 0x40, 0x22];
// One IKE proposal: AES-GCM-16 with 256-bit key, HMAC-SHA256 PRF, group 31.
const PROPOSAL: &[u8] = &[
    0, 0, 0, 36, 1, 1, 0, 3, 3, 0, 0, 12, 1, 0, 0, 20, 0x80, 14, 1, 0, 3, 0, 0, 8, 2, 0, 0, 5, 0,
    0, 0, 8, 4, 0, 0, 31,
];

/// Explicit ID_KEY_ID policy, compared as opaque bytes with no normalization.
/// A dedicated high-entropy PSK must be provisioned for this exact identity pair.
/// No Debug/Clone/serialization is implemented for credentials.
pub struct PskPolicy {
    local: Vec<u8>,
    peer: Vec<u8>,
    psk: SecretBytes<32>,
}
impl PskPolicy {
    pub fn new(local: &[u8], peer: &[u8], psk: SecretBytes<32>) -> Result<Self> {
        if local.is_empty()
            || peer.is_empty()
            || local.len() > 1024
            || peer.len() > 1024
            || local == peer
        {
            return Err(Error::ConfigError(
                "distinct local and peer key IDs (1..=1024 bytes) required".into(),
            ));
        }
        Ok(Self {
            local: local.to_vec(),
            peer: peer.to_vec(),
            psk,
        })
    }
    fn identity(&self) -> Vec<u8> {
        let mut body = vec![11, 0, 0, 0];
        body.extend_from_slice(&self.local);
        body
    }
    fn authorize(&self, body: &[u8]) -> Result<()> {
        // Reserved identity bytes are ignored by policy, but included in AUTH.
        if body.len() < 5 || body[0] != 11 || body[4..] != self.peer {
            return Err(Error::Authentication);
        }
        Ok(())
    }
}

pub(super) struct Context {
    pub(super) spii: u64,
    pub(super) spir: u64,
    pub(super) ni: Vec<u8>,
    pub(super) nr: Vec<u8>,
    pub(super) request: Vec<u8>,
    pub(super) response: Vec<u8>,
    pub(super) keys: IkeKeys,
}
enum Stage {
    Initial,
    InitSent {
        secret: StaticSecret,
        request: Vec<u8>,
        ni: Vec<u8>,
        spii: u64,
    },
    AwaitingAuth(Box<Context>),
    AuthSent(Box<Context>),
    Authenticated(Box<Context>),
    Closed,
}

/// One peer, one fresh IKE SA and an optional single CHILD_SA pair; no key import/export.
/// The transport owns routing, admission control and retransmission scheduling.
/// Call `expire` periodically even when no packets arrive, to release secrets.
pub struct PskSession {
    role: AuthRole,
    policy: Option<PskPolicy>,
    stage: Stage,
    deadline: Instant,
    // At most three accepted inbound messages (INIT, AUTH, optional CHILD).
    cache: Vec<(Vec<u8>, Option<Vec<u8>>)>,
    last_outbound: Option<Vec<u8>>,
    child: Option<ChildExchange>,
}
impl core::fmt::Debug for PskSession {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PskSession")
            .field("state", &self.state())
            .finish_non_exhaustive()
    }
}
impl PskSession {
    /// Lifetime starts now, includes negotiation, and is limited to one hour.
    /// Both endpoints explicitly opt in to RFC 6023 childless operation.
    pub fn new(role: AuthRole, policy: PskPolicy, lifetime: Duration) -> Result<Self> {
        if lifetime.is_zero() || lifetime > Duration::from_secs(3600) {
            return Err(Error::ConfigError(
                "IKE session lifetime must be in (0, 3600s]".into(),
            ));
        }
        Ok(Self {
            role,
            policy: Some(policy),
            stage: Stage::Initial,
            deadline: Instant::now() + lifetime,
            cache: Vec::new(),
            last_outbound: None,
            child: None,
        })
    }
    pub fn state(&self) -> SessionState {
        if Instant::now() >= self.deadline {
            return SessionState::Closed;
        }
        match self.stage {
            Stage::Initial => SessionState::Initial,
            Stage::InitSent { .. } => SessionState::InitSent,
            Stage::AwaitingAuth(_) => SessionState::AwaitingAuth,
            Stage::AuthSent(_) => SessionState::AuthSent,
            Stage::Authenticated(_) => SessionState::Authenticated,
            Stage::Closed => SessionState::Closed,
        }
    }
    pub fn close(&mut self) {
        self.stage = Stage::Closed;
        self.policy = None;
        self.cache.clear();
        self.last_outbound = None;
        self.child = None;
    }
    pub fn expire(&mut self) -> bool {
        if Instant::now() >= self.deadline {
            self.close();
        }
        matches!(self.stage, Stage::Closed)
    }
    fn live(&mut self) -> Result<()> {
        if self.expire() {
            Err(Error::SaExpired)
        } else {
            Ok(())
        }
    }
    pub fn authenticated_peer(&self) -> Option<&[u8]> {
        if self.state() == SessionState::Authenticated {
            self.policy.as_ref().map(|p| p.peer.as_slice())
        } else {
            None
        }
    }
    /// No new encryption or IV allocation: retries send the original bytes.
    pub fn retransmit(&mut self) -> Result<Option<Vec<u8>>> {
        self.live()?;
        Ok(self.last_outbound.clone())
    }
    pub fn start(&mut self) -> Result<Vec<u8>> {
        self.live()?;
        if self.role != AuthRole::Initiator || !matches!(self.stage, Stage::Initial) {
            return Err(Error::Unsupported("IKE start in this state"));
        }
        let secret = ephemeral()?;
        let spii = spi()?;
        let ni = random::<32>()?.expose().to_vec();
        let request = init_message(spii, 0, &secret, &ni, false)?;
        self.stage = Stage::InitSent {
            secret,
            request: request.clone(),
            ni,
            spii,
        };
        self.last_outbound = Some(request.clone());
        Ok(request)
    }
    /// Processes a single IKE message without UDP encapsulation. Rejected packets
    /// never advance state or replace the retransmission cache. Unknown/spoofed
    /// traffic cannot terminate an in-progress handshake; lifetime bounds retries.
    pub fn receive(&mut self, wire: &[u8]) -> Result<Option<Vec<u8>>> {
        self.live()?;
        if let Some((_, response)) = self.cache.iter().find(|(input, _)| input == wire) {
            return Ok(response.clone());
        }
        if let Stage::Authenticated(c) = &self.stage {
            let response = self
                .child
                .as_mut()
                .ok_or(Error::Unsupported("CHILD_SA policy not configured"))?
                .receive(c, self.role, wire)?;
            self.last_outbound = response.clone();
            self.cache.push((wire.to_vec(), response.clone()));
            return Ok(response);
        }
        let policy = self.policy.as_ref().ok_or(Error::SaExpired)?;
        let (next, outbound) = match &self.stage {
            Stage::Initial if self.role == AuthRole::Responder => {
                let init = parse_init(wire, false)?;
                let secret = ephemeral()?;
                let spir = spi()?;
                let nr = random::<32>()?.expose().to_vec();
                let response = init_message(init.spii, spir, &secret, &nr, true)?;
                let keys = derive(&secret, init.public, init.nonce, &nr, init.spii, spir)?;
                let context = Context {
                    spii: init.spii,
                    spir,
                    ni: init.nonce.to_vec(),
                    nr,
                    request: wire.to_vec(),
                    response: response.clone(),
                    keys,
                };
                (Stage::AwaitingAuth(Box::new(context)), Some(response))
            }
            Stage::InitSent {
                secret,
                request,
                ni,
                spii,
            } => {
                let init = parse_init(wire, true)?;
                if init.spii != *spii {
                    return Err(Error::UnknownSa);
                }
                let keys = derive(secret, init.public, ni, init.nonce, *spii, init.spir)?;
                let context = Context {
                    spii: *spii,
                    spir: init.spir,
                    ni: ni.clone(),
                    nr: init.nonce.to_vec(),
                    request: request.clone(),
                    response: wire.to_vec(),
                    keys,
                };
                let auth = auth_message(&context, policy, AuthRole::Initiator)?;
                (Stage::AuthSent(Box::new(context)), Some(auth))
            }
            Stage::AwaitingAuth(context) => {
                verify_auth(context, policy, AuthRole::Initiator, wire)?;
                let response = auth_message(context, policy, AuthRole::Responder)?;
                // Move context only after every fallible operation has succeeded.
                let Stage::AwaitingAuth(context) =
                    std::mem::replace(&mut self.stage, Stage::Closed)
                else {
                    unreachable!()
                };
                (Stage::Authenticated(context), Some(response))
            }
            Stage::AuthSent(context) => {
                verify_auth(context, policy, AuthRole::Responder, wire)?;
                let Stage::AuthSent(context) = std::mem::replace(&mut self.stage, Stage::Closed)
                else {
                    unreachable!()
                };
                (Stage::Authenticated(context), None)
            }
            _ => return Err(Error::Unsupported("IKE exchange in this state")),
        };
        self.stage = next;
        self.last_outbound = outbound.clone();
        self.cache.push((wire.to_vec(), outbound.clone()));
        Ok(outbound)
    }
    /// Bind inner host authorization before admitting any handshake input.
    pub fn configure_child(&mut self, policy: ChildPolicy) -> Result<()> {
        self.live()?;
        if !matches!(self.stage, Stage::Initial) || self.child.is_some() {
            return Err(Error::Unsupported(
                "CHILD_SA policy is immutable after configuration",
            ));
        }
        self.child = Some(ChildExchange::new(policy));
        Ok(())
    }
    /// Original initiator may create exactly one CHILD_SA, using message ID 2.
    pub fn start_child(&mut self) -> Result<Vec<u8>> {
        self.live()?;
        let Stage::Authenticated(c) = &self.stage else {
            return Err(Error::Authentication);
        };
        let request = self
            .child
            .as_mut()
            .ok_or(Error::Unsupported("CHILD_SA policy not configured"))?
            .start(c, self.role)?;
        self.last_outbound = Some(request.clone());
        Ok(request)
    }
    pub fn child_established(&self) -> bool {
        self.state() == SessionState::Authenticated
            && self.child.as_ref().is_some_and(ChildExchange::installed)
    }
    pub fn child_metadata(&self) -> Option<[crate::ipsec::sa::SaMetadata<'_>; 2]> {
        if self.state() != SessionState::Authenticated {
            return None;
        }
        self.child.as_ref().and_then(ChildExchange::metadata)
    }
    /// Encapsulate one policy-authorized complete IPv4 datagram in ESP.
    pub fn encrypt_ipv4(&mut self, packet: &[u8]) -> Result<Vec<u8>> {
        self.live()?;
        self.child.as_mut().ok_or(Error::UnknownSa)?.encrypt(packet)
    }
    /// Verify ESP and inbound host policy before committing replay state.
    pub fn decrypt_ipv4(&mut self, wire: &[u8]) -> Result<Vec<u8>> {
        self.live()?;
        self.child.as_mut().ok_or(Error::UnknownSa)?.decrypt(wire)
    }
    /// Public SPI metadata is available only after authentication.
    pub fn authenticated_spis(&self) -> Option<(u64, u64)> {
        match &self.stage {
            Stage::Authenticated(c) if self.state() == SessionState::Authenticated => {
                Some((c.spii, c.spir))
            }
            _ => None,
        }
    }
}

pub(super) fn random<const N: usize>() -> Result<SecretBytes<N>> {
    let mut bytes = SecretBytes::new([0; N]);
    getrandom::getrandom(bytes.expose_mut()).map_err(|_| Error::Crypto)?;
    Ok(bytes)
}
fn ephemeral() -> Result<StaticSecret> {
    Ok(StaticSecret::from(*random::<32>()?.expose()))
}
fn spi() -> Result<u64> {
    for _ in 0..8 {
        let value = u64::from_be_bytes(*random::<8>()?.expose());
        if value != 0 {
            return Ok(value);
        }
    }
    Err(Error::Crypto)
}
fn derive(
    secret: &StaticSecret,
    peer: &[u8],
    ni: &[u8],
    nr: &[u8],
    spii: u64,
    spir: u64,
) -> Result<IkeKeys> {
    let public = PublicKey::from(<[u8; 32]>::try_from(peer).map_err(|_| Error::Crypto)?);
    let shared = secret.diffie_hellman(&public);
    if !shared.was_contributory() {
        return Err(Error::Crypto);
    }
    initial_keys(&SecretBytes::new(*shared.as_bytes()), ni, nr, spii, spir)
}
pub(super) fn payloads(items: &[(u8, &[u8])]) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    for (index, (_, body)) in items.iter().enumerate() {
        let len = u16::try_from(body.len() + 4).map_err(|_| Error::Capacity)?;
        bytes.extend_from_slice(&[items.get(index + 1).map_or(0, |p| p.0), 0]);
        bytes.extend_from_slice(&len.to_be_bytes());
        bytes.extend_from_slice(body);
    }
    Ok(bytes)
}
fn header(spii: u64, spir: u64, next: u8, response: bool, auth: bool, size: usize) -> Vec<u8> {
    let mut wire = spii.to_be_bytes().to_vec();
    wire.extend_from_slice(&spir.to_be_bytes());
    wire.extend_from_slice(&[
        next,
        0x20,
        if auth { 35 } else { 34 },
        if response { 0x20 } else { 0x08 },
    ]);
    wire.extend_from_slice(&(u32::from(auth)).to_be_bytes());
    wire.extend_from_slice(&(size as u32).to_be_bytes());
    wire
}
fn init_message(
    spii: u64,
    spir: u64,
    secret: &StaticSecret,
    nonce: &[u8],
    response: bool,
) -> Result<Vec<u8>> {
    let mut ke = vec![0, 31, 0, 0];
    ke.extend_from_slice(PublicKey::from(secret).as_bytes());
    let mut items = vec![(33, PROPOSAL), (34, ke.as_slice()), (40, nonce)];
    if response {
        items.push((41, CHILDLESS));
    }
    let body = payloads(&items)?;
    let mut wire = header(spii, spir, 33, response, false, 28 + body.len());
    wire.extend_from_slice(&body);
    Ok(wire)
}
struct Init<'a> {
    spii: u64,
    spir: u64,
    public: &'a [u8],
    nonce: &'a [u8],
}
fn parse_init(wire: &[u8], response: bool) -> Result<Init<'_>> {
    let m = parse_message(wire)?;
    if m.header.exchange_type != ExchangeType::IkeSaInit
        || m.header.flags & 0x28 != if response { 0x20 } else { 0x08 }
        || (response && m.header.responder_spi == 0)
    {
        return Err(Error::UnknownSa);
    }
    let kinds: Vec<_> = m.payloads.iter().map(|p| p.kind).collect();
    if kinds
        != if response {
            vec![33, 34, 40, 41]
        } else {
            vec![33, 34, 40]
        }
    {
        return Err(Error::Unsupported("fixed childless IKE profile payloads"));
    }
    let proposals = parse_proposals(m.payloads[0].body)?;
    if proposals.len() != 1 {
        return Err(Error::Unsupported("IKE proposal alternatives"));
    }
    let p = &proposals[0];
    if p.number != 1 || p.protocol != 1 || !p.spi.is_empty() || p.transforms.len() != 3 {
        return Err(Error::Unsupported("IKE proposal"));
    }
    for (kind, id, attributes) in [
        (1, 20, &[0x80, 14, 1, 0][..]),
        (2, 5, &[][..]),
        (4, 31, &[][..]),
    ] {
        if p.transforms
            .iter()
            .filter(|t| t.kind == kind && t.id == id && t.attributes == attributes)
            .count()
            != 1
        {
            return Err(Error::Unsupported("IKE transform"));
        }
    }
    let ke = m.payloads[1].body;
    if ke.len() != 36 || ke[..2] != [0, 31] || (response && m.payloads[3].body != CHILDLESS) {
        return Err(Error::Unsupported("X25519 or childless capability"));
    }
    Ok(Init {
        spii: m.header.initiator_spi,
        spir: m.header.responder_spi,
        public: &ke[4..],
        nonce: m.payloads[2].body,
    })
}
fn auth_inputs(c: &Context, role: AuthRole) -> (&[u8], &[u8], &SecretBytes<36>) {
    match role {
        AuthRole::Initiator => (&c.request, &c.nr, &c.keys.sk_ei),
        AuthRole::Responder => (&c.response, &c.ni, &c.keys.sk_er),
    }
}
fn auth_message(c: &Context, policy: &PskPolicy, role: AuthRole) -> Result<Vec<u8>> {
    let (initial, nonce, _) = auth_inputs(c, role);
    let id = policy.identity();
    let mut auth = vec![2, 0, 0, 0];
    auth.extend_from_slice(
        &PskAuth::new(role, initial, nonce, &id, &c.keys)?.compute(&policy.psk)?,
    );
    let first = if role == AuthRole::Initiator { 35 } else { 36 };
    let plain = payloads(&[(first, &id), (39, &auth)])?;
    seal_sk(c, role, ExchangeType::IkeAuth, 1, 0, first, &plain)
}

// IV 0 belongs to AUTH. Child exchanges reserve monotonically increasing IVs
// before sealing, including failed attempts. Only cached ciphertext is retried.
pub(super) fn seal_sk(
    c: &Context,
    role: AuthRole,
    exchange: ExchangeType,
    id: u32,
    iv: u64,
    first: u8,
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    if plaintext.len() > 4096 {
        return Err(Error::Capacity);
    }
    let (_, _, key) = auth_inputs(c, role);
    let mut plain = Zeroizing::new(plaintext.to_vec());
    plain.push(0);
    let size = 32 + 8 + plain.len() + 16;
    let mut wire = header(c.spii, c.spir, 46, role == AuthRole::Responder, true, size);
    wire[18] = exchange as u8;
    wire[20..24].copy_from_slice(&id.to_be_bytes());
    wire.extend_from_slice(&[first, 0]);
    wire.extend_from_slice(&((size - 28) as u16).to_be_bytes());
    let iv = iv.to_be_bytes();
    let mut aead_nonce = [0; 12];
    aead_nonce[..4].copy_from_slice(&key.expose()[32..]);
    aead_nonce[4..].copy_from_slice(&iv);
    let aes_key = key.expose()[..32].try_into().map_err(|_| Error::Crypto)?;
    let tag = symmetric::seal(aes_key, &aead_nonce, &wire, &mut plain)?;
    wire.extend_from_slice(&iv);
    wire.extend_from_slice(&plain);
    wire.extend_from_slice(&tag);
    Ok(wire)
}
pub(super) fn open_sk(
    c: &Context,
    role: AuthRole,
    exchange: ExchangeType,
    id: u32,
    wire: &[u8],
) -> Result<(u8, Zeroizing<Vec<u8>>)> {
    let m = parse_message(wire)?;
    let h = &m.header;
    if h.exchange_type != exchange
        || h.message_id != id
        || h.initiator_spi != c.spii
        || h.responder_spi != c.spir
        || h.flags & 0x28 != if role == AuthRole::Initiator { 8 } else { 32 }
        || m.payloads.len() != 1
        || m.payloads[0].kind != 46
    {
        return Err(Error::UnknownSa);
    }
    let sk = &m.payloads[0];
    if sk.body.len() < 25 {
        return Err(Error::Authentication);
    }
    let (_, _, key) = auth_inputs(c, role);
    let mut aead_nonce = [0; 12];
    aead_nonce[..4].copy_from_slice(&key.expose()[32..]);
    aead_nonce[4..].copy_from_slice(&sk.body[..8]);
    let end = sk.body.len() - 16;
    let mut plain = Zeroizing::new(sk.body[8..end].to_vec());
    let aes_key = key.expose()[..32].try_into().map_err(|_| Error::Crypto)?;
    let tag = sk.body[end..]
        .try_into()
        .map_err(|_| Error::Authentication)?;
    symmetric::open(aes_key, &aead_nonce, &wire[..32], &mut plain, tag)?;
    let padding = usize::from(*plain.last().ok_or(Error::Authentication)?) + 1;
    let len = plain
        .len()
        .checked_sub(padding)
        .ok_or(Error::Authentication)?;
    plain.truncate(len);
    Ok((sk.next_payload, plain))
}
fn verify_auth(c: &Context, policy: &PskPolicy, role: AuthRole, wire: &[u8]) -> Result<()> {
    let (first, plain) = open_sk(c, role, ExchangeType::IkeAuth, 1, wire)?;
    let (initial, nonce, _) = auth_inputs(c, role);
    let inner = parse_payloads(first, &plain)?;
    let expected_id = if role == AuthRole::Initiator { 35 } else { 36 };
    if inner.len() != 2
        || inner[0].kind != expected_id
        || inner[1].kind != 39
        || inner[1].body.len() != 36
        || inner[1].body[0] != 2
    {
        return Err(Error::Authentication);
    }
    PskAuth::new(role, initial, nonce, inner[0].body, &c.keys)?
        .verify(&policy.psk, &inner[1].body[4..])?;
    policy.authorize(inner[0].body)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture_context() -> Context {
        let a = StaticSecret::from(core::array::from_fn::<_, 32, _>(|i| i as u8 + 1));
        let b = StaticSecret::from(core::array::from_fn::<_, 32, _>(|i| i as u8 + 33));
        let ni = vec![0x11; 32];
        let nr = vec![0x22; 32];
        Context {
            spii: 1,
            spir: 2,
            request: init_message(1, 0, &a, &ni, false).unwrap(),
            response: init_message(1, 2, &b, &nr, true).unwrap(),
            keys: derive(&a, PublicKey::from(&b).as_bytes(), &ni, &nr, 1, 2).unwrap(),
            ni,
            nr,
        }
    }
    #[test]
    fn independent_python_full_wire_fixture() {
        let c = fixture_context();
        let lines: Vec<_> = include_str!("../../tests/fixtures/ike_session.hex")
            .lines()
            .map(|line| crate::utils::hex_to_bytes(line).unwrap())
            .collect();
        assert_eq!(c.request, lines[0]);
        assert_eq!(c.response, lines[1]);
        let client = PskPolicy::new(b"client", b"server", SecretBytes::new([7; 32])).unwrap();
        let server = PskPolicy::new(b"server", b"client", SecretBytes::new([7; 32])).unwrap();
        assert_eq!(
            auth_message(&c, &client, AuthRole::Initiator).unwrap(),
            lines[2]
        );
        assert_eq!(
            auth_message(&c, &server, AuthRole::Responder).unwrap(),
            lines[3]
        );
        verify_auth(&c, &server, AuthRole::Initiator, &lines[2]).unwrap();
        verify_auth(&c, &client, AuthRole::Responder, &lines[3]).unwrap();
    }
    #[test]
    fn expiry_erases_state_and_credentials() {
        let policy = PskPolicy::new(b"client", b"server", SecretBytes::new([7; 32])).unwrap();
        let mut s = PskSession::new(AuthRole::Initiator, policy, Duration::from_secs(60)).unwrap();
        s.start().unwrap();
        s.deadline = Instant::now();
        assert_eq!(s.state(), SessionState::Closed);
        assert!(s.authenticated_peer().is_none());
        assert_eq!(s.retransmit(), Err(Error::SaExpired));
        assert!(s.policy.is_none());
        assert!(s.cache.is_empty());
        assert!(matches!(s.stage, Stage::Closed));
    }
    #[test]
    fn encrypted_but_invalid_inner_auth_is_rejected() {
        let c = fixture_context();
        let client = PskPolicy::new(b"client", b"server", SecretBytes::new([7; 32])).unwrap();
        let server = PskPolicy::new(b"server", b"client", SecretBytes::new([7; 32])).unwrap();
        let original = auth_message(&c, &client, AuthRole::Initiator).unwrap();
        let key: &[u8; 32] = c.keys.sk_ei.expose()[..32].try_into().unwrap();
        let mut nonce = [0; 12];
        nonce[..4].copy_from_slice(&c.keys.sk_ei.expose()[32..]);
        let end = original.len() - 16;
        let mut plain = original[40..end].to_vec();
        symmetric::open(
            key,
            &nonce,
            &original[..32],
            &mut plain,
            original[end..].try_into().unwrap(),
        )
        .unwrap();
        // Valid GCM envelope, invalid PSK MAC, method, ID type, chain or padding.
        for index in [4, 14, 18, 22, plain.len() - 1] {
            let mut changed = plain.clone();
            changed[index] ^= 0x80;
            let mut wire = original[..40].to_vec();
            let tag = symmetric::seal(key, &nonce, &wire[..32], &mut changed).unwrap();
            wire.extend_from_slice(&changed);
            wire.extend_from_slice(&tag);
            assert!(
                verify_auth(&c, &server, AuthRole::Initiator, &wire).is_err(),
                "index {index}"
            );
        }
        let mut altered = fixture_context();
        altered.request[19] ^= 1;
        assert!(verify_auth(&altered, &server, AuthRole::Initiator, &original).is_err());
    }
}
