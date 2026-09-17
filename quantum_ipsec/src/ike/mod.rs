//! Structural IKE foundation. Full authenticated IKE is intentionally unavailable.
pub mod exchange;
pub mod parser;
pub mod proposal;
pub mod schedule;
use crate::{QuantumIpsecError as Error, Result};
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionState {
    Initial,
    Failed,
}
#[derive(Debug)]
pub struct IkeProcessor {
    state: SessionState,
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
        }
    }
    pub fn state(&self) -> SessionState {
        self.state
    }
    /// No parsed message, missing AUTH or caller-controlled boolean may establish
    /// an SA. Re-enable negotiation only with verified identities, full transcript
    /// binding, encrypted IKE and a tested message-ID/SPI state machine.
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
