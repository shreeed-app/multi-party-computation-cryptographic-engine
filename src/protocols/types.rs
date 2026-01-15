//! Protocol types used across different protocol implementations.

use crate::secrets::types::KeyShare;

/// Protocol round number.
pub type Round = u32;

/// Message exchanged between participants during protocol execution.
#[derive(Debug)]
pub struct RoundMessage {
    /// Current round number.
    pub round: Round,
    /// Opaque payload bytes.
    pub payload: Vec<u8>,
}

/// Final output (protocol-dependent).
#[derive(Debug)]
pub struct Signature {
    /// Opaque signature bytes.
    pub bytes: Vec<u8>,
}

/// Protocol initialization context.
#[derive(Debug)]
pub struct ProtocolInit {
    /// Unique key identifier.
    pub key_id: String,
    /// Algorithm name.
    pub algorithm: String,
    /// Number of participants.
    pub threshold: u32,
    /// Number of total participants.
    pub participants: u32,
    /// Message to be signed.
    pub message: Vec<u8>,
    /// Participant's key share.
    pub key_share: KeyShare,
}
