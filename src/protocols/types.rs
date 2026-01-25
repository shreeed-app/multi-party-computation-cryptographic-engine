//! Protocol types used across different protocol implementations.

use crate::{protocols::algorithm::Algorithm, secrets::types::KeyShare};

/// Protocol round number.
pub type Round = u32;

/// Message exchanged between participants during protocol execution.
#[derive(Debug)]
pub struct RoundMessage {
    /// Current round number.
    pub round: Round,
    /// Sender participant identifier.
    pub from: Option<u32>,
    /// Recipient participant identifier (None = broadcast).
    pub to: Option<u32>,
    /// Opaque payload bytes.
    pub payload: Vec<u8>,
}

/// Final output (protocol-dependent).
#[derive(Debug)]
pub enum Signature {
    /// Ed25519 or Schnorr signature (raw bytes).
    Raw(Vec<u8>),
    /// ECDSA signature on secp256k1 curve.
    EcdsaSecp256k1 {
        /// R component of the signature.
        r: [u8; 32],
        /// S component of the signature.
        s: [u8; 32],
        /// Recovery identifier.
        v: u8,
    },
}

/// Protocol initialization context.
#[derive(Debug)]
pub struct ProtocolInit {
    /// Unique key identifier.
    pub key_id: String,
    /// Algorithm name.
    pub algorithm: Algorithm,
    /// Number of participants.
    pub threshold: u32,
    /// Number of total participants.
    pub participants: u32,
    /// Message to be signed.
    pub message: Vec<u8>,
    /// Participant's key share.
    pub key_share: KeyShare,
}
