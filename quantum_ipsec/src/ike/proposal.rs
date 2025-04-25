//! IKEv2 security proposals implementation.
//!
//! This module implements the security proposals used in IKEv2 protocol
//! negotiation, including post-quantum cryptographic primitives.

use core::fmt::Debug;

/// Represents a security proposal in IKEv2
#[derive(Debug, Clone, PartialEq)]
pub struct IKEProposal {
    /// Proposal number
    proposal_num: u8,
    /// Protocol ID (IKE, ESP, etc.)
    protocol_id: ProtocolID,
    /// SPI (Security Parameter Index)
    spi: [u8; 8],
    /// Number of transforms
    num_transforms: u8,
    /// Transforms in this proposal
    transforms: [Transform; 3],
}

impl Default for IKEProposal {
    fn default() -> Self {
        Self {
            proposal_num: 1,
            protocol_id: ProtocolID::IKE,
            spi: [0u8; 8],
            num_transforms: 3,
            transforms: [
                Transform::new(TransformType::Encryption, TransformID::Kyber512),
                Transform::new(TransformType::PRF, TransformID::SHA256),
                Transform::new(TransformType::Auth, TransformID::Falcon512),
            ],
        }
    }
}

/// Protocol IDs used in IKEv2
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ProtocolID {
    /// IKE protocol
    IKE = 1,
    /// ESP protocol
    ESP = 3,
    /// AH protocol
    AH = 2,
}

/// Transform types in IKEv2
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum TransformType {
    /// Encryption transform
    Encryption = 1,
    /// Pseudo-random function transform
    PRF = 2,
    /// Authentication transform
    Auth = 3,
}

/// Transform IDs for different cryptographic algorithms
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum TransformID {
    /// Kyber512 KEM
    Kyber512 = 1,
    /// Falcon512 digital signature
    Falcon512 = 2,
    /// SHA-256 hash function
    SHA256 = 3,
}

/// Represents a transform in an IKEv2 proposal
#[derive(Debug, Clone, PartialEq)]
pub struct Transform {
    /// Transform type
    transform_type: TransformType,
    /// Transform ID
    transform_id: TransformID,
    /// Transform attributes
    attributes: [TransformAttribute; 2],
}

impl Transform {
    /// Creates a new transform
    pub fn new(transform_type: TransformType, transform_id: TransformID) -> Self {
        Self {
            transform_type,
            transform_id,
            attributes: [
                TransformAttribute::new(AttributeType::KeyLength, 256),
                TransformAttribute::new(AttributeType::GroupType, 1),
            ],
        }
    }
}

/// Transform attribute types
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum AttributeType {
    /// Key length attribute
    KeyLength = 1,
    /// Group type attribute
    GroupType = 2,
}

/// Represents a transform attribute
#[derive(Debug, Clone, PartialEq)]
pub struct TransformAttribute {
    /// Attribute type
    attribute_type: AttributeType,
    /// Attribute value
    value: u16,
}

impl TransformAttribute {
    /// Creates a new transform attribute
    pub fn new(attribute_type: AttributeType, value: u16) -> Self {
        Self {
            attribute_type,
            value,
        }
    }
} 