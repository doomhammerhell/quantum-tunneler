//! IKEv2 negotiation debugging module.
//!
//! This module provides debugging capabilities for IKEv2 negotiations,
//! allowing inspection of each step of the protocol exchange.

use super::{IKEMessage, ExchangeType, SessionState};
use core::fmt::Debug;

/// Debug level for IKEv2 negotiations
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum DebugLevel {
    /// No debugging output
    None,
    /// Basic protocol information
    Basic,
    /// Detailed protocol information
    Detailed,
    /// Full protocol trace with cryptographic details
    Full,
}

/// Debug information for IKEv2 negotiations
#[derive(Debug, Clone)]
pub struct NegotiationDebug {
    /// Current debug level
    level: DebugLevel,
    /// Current exchange type
    exchange_type: ExchangeType,
    /// Current session state
    session_state: SessionState,
    /// Message history
    message_history: Vec<IKEMessage>,
}

impl NegotiationDebug {
    /// Creates a new negotiation debug instance
    pub fn new(level: DebugLevel) -> Self {
        Self {
            level,
            exchange_type: ExchangeType::SAInit,
            session_state: SessionState::None,
            message_history: Vec::new(),
        }
    }

    /// Logs a message exchange
    pub fn log_message(&mut self, message: &IKEMessage) {
        if self.level == DebugLevel::None {
            return;
        }

        self.message_history.push(message.clone());
        self.exchange_type = message.exchange_type;

        match self.level {
            DebugLevel::Basic => {
                defmt::info!(
                    "IKEv2 {} exchange: message_id={}",
                    self.exchange_type,
                    message.message_id
                );
            }
            DebugLevel::Detailed => {
                defmt::info!(
                    "IKEv2 {} exchange: message_id={}, state={}",
                    self.exchange_type,
                    message.message_id,
                    self.session_state
                );
            }
            DebugLevel::Full => {
                defmt::info!(
                    "IKEv2 {} exchange: message_id={}, state={}, proposal={:?}",
                    self.exchange_type,
                    message.message_id,
                    self.session_state,
                    message.proposal
                );
            }
            _ => {}
        }
    }

    /// Updates the session state
    pub fn update_state(&mut self, state: SessionState) {
        self.session_state = state;
        if self.level != DebugLevel::None {
            defmt::info!("IKEv2 state changed to: {}", self.session_state);
        }
    }

    /// Returns the current debug level
    pub fn level(&self) -> DebugLevel {
        self.level
    }

    /// Returns the message history
    pub fn message_history(&self) -> &[IKEMessage] {
        &self.message_history
    }
}

/// Debug context for IKEv2 operations
pub struct DebugContext {
    /// Negotiation debug instance
    debug: NegotiationDebug,
}

impl DebugContext {
    /// Creates a new debug context
    pub fn new(level: DebugLevel) -> Self {
        Self {
            debug: NegotiationDebug::new(level),
        }
    }

    /// Logs a message exchange
    pub fn log_message(&mut self, message: &IKEMessage) {
        self.debug.log_message(message);
    }

    /// Updates the session state
    pub fn update_state(&mut self, state: SessionState) {
        self.debug.update_state(state);
    }

    /// Returns the current debug level
    pub fn level(&self) -> DebugLevel {
        self.debug.level()
    }

    /// Returns the message history
    pub fn message_history(&self) -> &[IKEMessage] {
        self.debug.message_history()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_debug_creation() {
        let debug = NegotiationDebug::new(DebugLevel::Basic);
        assert_eq!(debug.level(), DebugLevel::Basic);
    }

    #[test]
    fn test_message_logging() {
        let mut debug = NegotiationDebug::new(DebugLevel::Basic);
        let message = IKEMessage::new(
            1,
            ExchangeType::SAInit,
            super::IKEProposal::default(),
            [0u8; 32],
        );
        debug.log_message(&message);
        assert_eq!(debug.message_history().len(), 1);
    }
} 