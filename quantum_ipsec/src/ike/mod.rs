//! Bounded IKE foundation with opt-in authenticated childless PSK sessions.
pub mod auth;
pub mod child;
pub mod exchange;
pub mod parser;
pub mod proposal;
pub mod schedule;
pub mod session;
pub mod udp;
use crate::{QuantumIpsecError as Error, Result};
pub use session::{PskPolicy, PskSession};
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionState {
    Initial,
    InitSent,
    AwaitingAuth,
    AuthSent,
    Authenticated,
    Closed,
    Failed,
}
#[derive(Debug)]
pub struct IkeProcessor {
    state: SessionState,
    session: Option<PskSession>,
}
impl Default for IkeProcessor {
    fn default() -> Self {
        Self::new()
    }
}
impl IkeProcessor {
    pub fn new() -> Self {
        Self {
            state: SessionState::Initial,
            session: None,
        }
    }
    pub fn state(&self) -> SessionState {
        self.session.as_ref().map_or(self.state, PskSession::state)
    }
    /// Explicit opt-in: fixed identities, PSK and childless IKE profile.
    pub fn with_psk(
        role: auth::AuthRole,
        policy: PskPolicy,
        lifetime: std::time::Duration,
    ) -> Result<Self> {
        Ok(Self {
            state: SessionState::Initial,
            session: Some(PskSession::new(role, policy, lifetime)?),
        })
    }
    pub fn start(&mut self) -> Result<Vec<u8>> {
        self.session
            .as_mut()
            .ok_or(Error::Unsupported("IKE credentials not configured"))?
            .start()
    }
    pub fn receive(&mut self, wire: &[u8]) -> Result<Option<Vec<u8>>> {
        self.session
            .as_mut()
            .ok_or(Error::Unsupported("IKE credentials not configured"))?
            .receive(wire)
    }
    pub fn authenticated_peer(&self) -> Option<&[u8]> {
        self.session
            .as_ref()
            .and_then(PskSession::authenticated_peer)
    }
    pub fn retransmit(&mut self) -> Result<Option<Vec<u8>>> {
        self.session
            .as_mut()
            .ok_or(Error::Unsupported("IKE credentials not configured"))?
            .retransmit()
    }
    pub fn close(&mut self) {
        if let Some(session) = &mut self.session {
            session.close();
        }
        self.state = SessionState::Closed;
    }
    pub fn expire(&mut self) -> bool {
        self.session.as_mut().is_some_and(PskSession::expire)
    }
    /// Legacy API cannot return protocol responses. Use configured `receive`.
    pub fn process(&mut self, wire: &[u8]) -> Result<()> {
        parser::parse_message(wire)?;
        self.state = SessionState::Failed;
        Err(Error::Unsupported("authenticated IKEv2 negotiation"))
    }
    pub fn connect(&mut self) -> Result<()> {
        self.state = SessionState::Failed;
        Err(Error::Unsupported("authenticated IKEv2 negotiation"))
    }
}
pub use exchange::{ExchangeType, IkeHeader, IkeMessage};
