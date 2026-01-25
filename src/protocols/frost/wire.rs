//! Wire messages for FROST-based protocols.
// `rkyv::Archive` generates public types without doc comments.
// This causes unavoidable `missing_docs` false positives.
#![allow(missing_docs)]

use rkyv::{
    Archive,
    Deserialize,
    Serialize,
};

/// Wire messages exchanged between orchestrator and peer
/// for any FROST-based protocol.
#[derive(Debug, PartialEq, Archive, Serialize, Deserialize)]
#[repr(u8)]
pub enum FrostWire {
    /// Participant commitments (round 0 → 1).
    Commitments {
        /// Participant identifier.
        identifier: u32,
        /// postcard-encoded commitments.
        commitments: Vec<u8>,
    },

    /// Signing package (round 1 → 2).
    SigningPackage {
        /// postcard-encoded signing package.
        signing_package: Vec<u8>,
    },

    /// Participant signature share (round 2).
    SignatureShare {
        /// Participant identifier.
        identifier: u32,
        /// postcard-encoded signature share.
        signature_share: Vec<u8>,
    },
}
