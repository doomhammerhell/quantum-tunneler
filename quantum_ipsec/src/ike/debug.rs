//! Debug utilities for IKEv2 protocol
//!
//! This module provides debugging and logging functionality for the IKEv2 implementation.

use crate::ike::SessionState;

/// Debug level enumeration
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum DebugLevel {
    None,
    Basic,
    Verbose,
    All,
}

/// Debug context for IKEv2 operations
pub struct DebugContext {
    level: DebugLevel,
    session_state: SessionState,
}

impl DebugContext {
    /// Create a new debug context
    pub fn new(level: DebugLevel) -> Self {
        Self {
            level,
            session_state: SessionState::Initial,
        }
    }

    /// Log a message at the current debug level
    pub fn log_message(&self, message: &str) {
        if self.level != DebugLevel::None {
            println!("[IKE DEBUG] {}", message);
            }
    }
    
    /// Log state change
    pub fn log_state_change(&self, new_state: SessionState) {
        if self.level != DebugLevel::None {
            println!("[IKE DEBUG] State changed to: {:?}", new_state);
        }
    }

    /// Get current debug level
    pub fn level(&self) -> DebugLevel {
        self.level
    }

    /// Set debug level
    pub fn set_level(&mut self, level: DebugLevel) {
        self.level = level;
    }

    /// Get current session state
    pub fn session_state(&self) -> SessionState {
        self.session_state
    }

    /// Set session state
    pub fn set_session_state(&mut self, state: SessionState) {
        self.session_state = state;
        self.log_state_change(state);
    }
} 