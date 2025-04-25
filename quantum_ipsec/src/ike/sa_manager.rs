//! Security Association management for IKEv2.
//!
//! This module implements the management of Security Associations (SAs)
//! for both IKE and CHILD SAs, including lifetime management and rekeying.

use super::{IKEError, IKEResult, IKEProposal, SessionState};
use std::collections::HashMap;
use std::time::{Duration, Instant};

/// Represents a Security Association
#[derive(Debug, Clone)]
pub struct SecurityAssociation {
    /// Unique identifier for the SA
    id: u32,
    /// Security proposal
    proposal: IKEProposal,
    /// Session state
    state: SessionState,
    /// Creation time
    created_at: Instant,
    /// Lifetime duration
    lifetime: Duration,
    /// Session keys
    keys: Vec<u8>,
    /// Rekey threshold (percentage of lifetime)
    rekey_threshold: f32,
}

impl SecurityAssociation {
    /// Creates a new Security Association
    pub fn new(id: u32, proposal: IKEProposal, lifetime: Duration) -> Self {
        Self {
            id,
            proposal,
            state: SessionState::None,
            created_at: Instant::now(),
            lifetime,
            keys: Vec::new(),
            rekey_threshold: 0.8, // 80% of lifetime
        }
    }

    /// Checks if the SA needs rekeying
    pub fn needs_rekey(&self) -> bool {
        let elapsed = self.created_at.elapsed();
        let threshold = self.lifetime.mul_f32(self.rekey_threshold);
        elapsed >= threshold
    }

    /// Updates the session keys
    pub fn update_keys(&mut self, keys: Vec<u8>) {
        self.keys = keys;
    }

    /// Returns the current state
    pub fn state(&self) -> SessionState {
        self.state
    }

    /// Updates the state
    pub fn update_state(&mut self, state: SessionState) {
        self.state = state;
    }
}

/// Manages Security Associations
pub struct SAManager {
    /// IKE SAs
    ike_sas: HashMap<u32, SecurityAssociation>,
    /// CHILD SAs
    child_sas: HashMap<u32, SecurityAssociation>,
    /// Next SA ID
    next_sa_id: u32,
}

impl SAManager {
    /// Creates a new SA manager
    pub fn new() -> Self {
        Self {
            ike_sas: HashMap::new(),
            child_sas: HashMap::new(),
            next_sa_id: 1,
        }
    }

    /// Creates a new IKE SA
    pub fn create_ike_sa(&mut self, proposal: IKEProposal) -> u32 {
        let id = self.next_sa_id;
        self.next_sa_id += 1;
        
        let sa = SecurityAssociation::new(
            id,
            proposal,
            Duration::from_secs(3600), // 1 hour default lifetime
        );
        
        self.ike_sas.insert(id, sa);
        id
    }

    /// Creates a new CHILD SA
    pub fn create_child_sa(&mut self, proposal: IKEProposal) -> u32 {
        let id = self.next_sa_id;
        self.next_sa_id += 1;
        
        let sa = SecurityAssociation::new(
            id,
            proposal,
            Duration::from_secs(1800), // 30 minutes default lifetime
        );
        
        self.child_sas.insert(id, sa);
        id
    }

    /// Gets an IKE SA by ID
    pub fn get_ike_sa(&self, id: u32) -> Option<&SecurityAssociation> {
        self.ike_sas.get(&id)
    }

    /// Gets a CHILD SA by ID
    pub fn get_child_sa(&self, id: u32) -> Option<&SecurityAssociation> {
        self.child_sas.get(&id)
    }

    /// Updates an IKE SA
    pub fn update_ike_sa(&mut self, id: u32, sa: SecurityAssociation) -> IKEResult<()> {
        if !self.ike_sas.contains_key(&id) {
            return Err(IKEError::StateError);
        }
        self.ike_sas.insert(id, sa);
        Ok(())
    }

    /// Updates a CHILD SA
    pub fn update_child_sa(&mut self, id: u32, sa: SecurityAssociation) -> IKEResult<()> {
        if !self.child_sas.contains_key(&id) {
            return Err(IKEError::StateError);
        }
        self.child_sas.insert(id, sa);
        Ok(())
    }

    /// Removes an IKE SA
    pub fn remove_ike_sa(&mut self, id: u32) -> IKEResult<()> {
        if !self.ike_sas.contains_key(&id) {
            return Err(IKEError::StateError);
        }
        self.ike_sas.remove(&id);
        Ok(())
    }

    /// Removes a CHILD SA
    pub fn remove_child_sa(&mut self, id: u32) -> IKEResult<()> {
        if !self.child_sas.contains_key(&id) {
            return Err(IKEError::StateError);
        }
        self.child_sas.remove(&id);
        Ok(())
    }

    /// Checks for SAs that need rekeying
    pub fn check_rekeying(&self) -> Vec<u32> {
        let mut needs_rekey = Vec::new();
        
        for (id, sa) in &self.ike_sas {
            if sa.needs_rekey() {
                needs_rekey.push(*id);
            }
        }
        
        for (id, sa) in &self.child_sas {
            if sa.needs_rekey() {
                needs_rekey.push(*id);
            }
        }
        
        needs_rekey
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sa_creation() {
        let mut manager = SAManager::new();
        let proposal = IKEProposal::default();
        
        let ike_sa_id = manager.create_ike_sa(proposal.clone());
        let child_sa_id = manager.create_child_sa(proposal);
        
        assert!(manager.get_ike_sa(ike_sa_id).is_some());
        assert!(manager.get_child_sa(child_sa_id).is_some());
    }

    #[test]
    fn test_sa_rekeying() {
        let mut manager = SAManager::new();
        let proposal = IKEProposal::default();
        
        let sa_id = manager.create_ike_sa(proposal);
        let sa = manager.get_ike_sa(sa_id).unwrap();
        
        assert!(!sa.needs_rekey());
    }

    #[test]
    fn test_sa_removal() {
        let mut manager = SAManager::new();
        let proposal = IKEProposal::default();
        
        let sa_id = manager.create_ike_sa(proposal);
        assert!(manager.remove_ike_sa(sa_id).is_ok());
        assert!(manager.get_ike_sa(sa_id).is_none());
    }
} 