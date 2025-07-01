//! Security Policy Database (SPD) for quantum-safe IPSec.
//!
//! This module provides policy management for IPSec packet filtering and routing.

use crate::{QuantumIpsecError, Result};
use heapless::Vec as HVec;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Policy action
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum PolicyAction {
    /// Allow packet without IPSec
    Allow,
    /// Require IPSec protection
    Require,
    /// Block packet
    Block,
}

/// Policy protocol
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum PolicyProtocol {
    /// Any protocol
    Any,
    /// TCP
    Tcp,
    /// UDP
    Udp,
    /// ICMP
    Icmp,
    /// ESP
    Esp,
    /// AH
    Ah,
}

/// Security policy entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityPolicy {
    /// Policy ID
    pub id: u32,
    /// Source address range
    pub src_addr: IpAddr,
    /// Destination address range
    pub dst_addr: IpAddr,
    /// Protocol
    pub protocol: PolicyProtocol,
    /// Source port (0 for any)
    pub src_port: u16,
    /// Destination port (0 for any)
    pub dst_port: u16,
    /// Policy action
    pub action: PolicyAction,
    /// Priority (higher = more specific)
    pub priority: u32,
    /// Whether policy is active
    pub is_active: bool,
}

impl SecurityPolicy {
    /// Create a new security policy
    pub fn new(
        id: u32,
        src_addr: IpAddr,
        dst_addr: IpAddr,
        protocol: PolicyProtocol,
        action: PolicyAction,
    ) -> Self {
        Self {
            id,
            src_addr,
            dst_addr,
            protocol,
            src_port: 0,
            dst_port: 0,
            action,
            priority: 100,
            is_active: true,
        }
    }

    /// Check if policy matches packet
    pub fn matches(&self, src: IpAddr, dst: IpAddr, protocol: u8, src_port: u16, dst_port: u16) -> bool {
        if !self.is_active {
            return false;
        }

        // Check addresses
        if self.src_addr != src && self.src_addr != IpAddr::V4(Ipv4Addr::UNSPECIFIED) {
            return false;
        }
        if self.dst_addr != dst && self.dst_addr != IpAddr::V4(Ipv4Addr::UNSPECIFIED) {
            return false;
        }

        // Check protocol
        match self.protocol {
            PolicyProtocol::Any => {},
            PolicyProtocol::Tcp => if protocol != 6 { return false; },
            PolicyProtocol::Udp => if protocol != 17 { return false; },
            PolicyProtocol::Icmp => if protocol != 1 { return false; },
            PolicyProtocol::Esp => if protocol != 50 { return false; },
            PolicyProtocol::Ah => if protocol != 51 { return false; },
        }

        // Check ports
        if self.src_port != 0 && self.src_port != src_port {
            return false;
        }
        if self.dst_port != 0 && self.dst_port != dst_port {
            return false;
        }

        true
    }
}

/// Security Policy Database
pub struct SecurityPolicyDatabase {
    /// Map of policy ID to policy
    policies: HashMap<u32, SecurityPolicy>,
    /// Maximum number of policies
    max_policies: usize,
}

impl SecurityPolicyDatabase {
    /// Create a new SPD
    pub fn new(max_policies: usize) -> Self {
        Self {
            policies: HashMap::new(),
            max_policies,
        }
    }

    /// Add policy to database
    pub fn add_policy(&mut self, policy: SecurityPolicy) -> Result<()> {
        if self.policies.len() >= self.max_policies {
            return Err(QuantumIpsecError::PacketError("SPD full".into()));
        }
        
        self.policies.insert(policy.id, policy);
        Ok(())
    }

    /// Get policy by ID
    pub fn get_policy(&self, id: u32) -> Option<&SecurityPolicy> {
        self.policies.get(&id)
    }

    /// Remove policy by ID
    pub fn remove_policy(&mut self, id: u32) -> Option<SecurityPolicy> {
        self.policies.remove(&id)
    }

    /// Find matching policy for packet
    pub fn find_matching_policy(
        &self,
        src: IpAddr,
        dst: IpAddr,
        protocol: u8,
        src_port: u16,
        dst_port: u16,
    ) -> Option<&SecurityPolicy> {
        let mut best_match: Option<&SecurityPolicy> = None;
        let mut best_priority = 0u32;

        for policy in self.policies.values() {
            if policy.matches(src, dst, protocol, src_port, dst_port) {
                if policy.priority > best_priority {
                    best_match = Some(policy);
                    best_priority = policy.priority;
                }
            }
        }

        best_match
    }

    /// Get all policies
    pub fn get_all_policies(&self) -> Vec<&SecurityPolicy> {
        self.policies.values().collect()
    }

    /// Get number of policies
    pub fn count(&self) -> usize {
        self.policies.len()
    }
}

/// Exemplo de regra de policy para modo tunnel
pub fn example_policy() -> SecurityPolicy {
    SecurityPolicy {
        id: 1,
        src_addr: "10.0.0.1".parse().unwrap(),
        dst_addr: "10.0.0.2".parse().unwrap(),
        protocol: PolicyProtocol::Esp,
        action: PolicyAction::Require,
        src_port: 0,
        dst_port: 0,
        priority: 100,
        is_active: true,
    }
}

/// Adiciona uma policy à base de dados
pub fn add_policy(spd: &mut SecurityPolicyDatabase, policy: SecurityPolicy) {
    let _ = spd.add_policy(policy);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_policy_matching() {
        let mut spd = SecurityPolicyDatabase::new(10);
        
        let policy = SecurityPolicy::new(
            1,
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 0)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            PolicyProtocol::Tcp,
            PolicyAction::Require,
        );
        
        spd.add_policy(policy).unwrap();
        
        let matching = spd.find_matching_policy(
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            6, // TCP
            80,
            443,
        );
        
        assert!(matching.is_some());
        assert_eq!(matching.unwrap().action, PolicyAction::Require);
    }

    #[test]
    fn test_subnet_matching() {
        let mut spd = SecurityPolicyDatabase::new(10);
        
        let policy = SecurityPolicy::new(
            1,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)),
            PolicyProtocol::Any,
            PolicyAction::Allow,
        );
        
        spd.add_policy(policy).unwrap();
        
        let matching = spd.find_matching_policy(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            6, // TCP
            80,
            443,
        );
        
        assert!(matching.is_some());
        assert_eq!(matching.unwrap().action, PolicyAction::Allow);
    }
} 