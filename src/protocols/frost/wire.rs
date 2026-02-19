//! Wire messages for FROST-based protocols.
// `rkyv::Archive` generates public types without doc comments.
// This causes unavoidable `missing_docs` false positives.
#![allow(missing_docs)]

use rkyv::{Archive, Deserialize, Serialize};

/// Wire messages exchanged between controller and node for any FROST-based
/// protocol.
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

    /// Round 1 DKG package.
    DkgRound1Package {
        /// Participant identifier.
        identifier: u32,
        /// postcard-encoded round 1 package.
        package: Vec<u8>,
    },

    /// Round 1 DKG packages from all participants.
    DkgRound1Packages {
        /// (from_identifier_u32, round1::Package bytes).
        packages: Vec<(u32, Vec<u8>)>,
    },

    /// Round 2 DKG packages output to be sent to other participants.
    DkgRound2PackagesOutput {
        /// (to_identifier_u32, round2::Package bytes).
        packages: Vec<(u32, Vec<u8>)>,
    },

    DkgRound2Packages {
        /// (from_identifier_u32, round2::Package bytes).
        packages: Vec<(u32, Vec<u8>)>,
    },
}
