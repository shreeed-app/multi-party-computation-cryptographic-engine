//! Wire messages for CGGMP'24 protocols.
// `rkyv::Archive` generates public types without doc comments.
// This causes unavoidable `missing_docs` false positives.
#![allow(missing_docs)]

use rkyv::{
    Archive,
    Deserialize,
    Serialize,
};

/// Wire messages exchanged between orchestrator and peer
/// for CGGMP24 ECDSA protocol.
#[derive(Debug, PartialEq, Archive, Serialize, Deserialize)]
#[repr(u8)]
pub enum Cggmp24Wire {
    /// Wrapper for a `round_based::Msg`.
    /// The inner payload is a `serde_json` or `bincode` serialized
    /// `round_based::Msg<cggmp24::signing::Msg<E, D>>`.
    ProtocolMessage {
        /// Serialized inner protocol message.
        payload: Vec<u8>,
    },
}
