//! Protocol types used across different protocol implementations.

use crate::{
    proto::signer::v1::signature_result::FinalSignature,
    protocols::algorithm::Algorithm,
    secrets::types::KeyShare,
    transport::grpc::node_client::NodeIpcClient,
};

/// Protocol round number.
pub type Round = u32;

/// Protocol initialization context.
pub enum ProtocolInit {
    /// Key generation protocol initialization.
    KeyGeneration(KeyGenerationInit),
    /// Signing protocol initialization.
    Signing(SigningInit),
}

/// Signing protocol initialization context.
pub enum SigningInit {
    /// Node participant signing protocol initialization.
    Node(NodeSigningInit),
    /// Controller signing protocol initialization.
    Controller(ControllerSigningInit),
}

/// Key generation protocol initialization context.
pub enum KeyGenerationInit {
    /// Node participant key generation protocol initialization.
    Node(NodeKeyGenerationInit),
    /// Controller key generation protocol initialization.
    Controller(ControllerKeyGenerationInit),
}

/// Signing protocol initialization context.
#[derive(Debug)]
pub struct DefaultSigningInit {
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
}

/// Node participant signing protocol initialization context.
#[derive(Debug)]
pub struct NodeSigningInit {
    /// Common signing initialization parameters.
    pub common: DefaultSigningInit,
    /// Participant's key share.
    pub key_share: KeyShare,
}

/// Controller signing protocol initialization context.
#[derive(Debug)]
pub struct ControllerSigningInit {
    /// Common signing initialization parameters.
    pub common: DefaultSigningInit,
    /// Public key bytes (curve-specific, canonical format).
    pub public_key_package: Vec<u8>,
    /// Participant identifiers and addresses of all participants (including
    /// self).
    pub nodes: Vec<NodeIpcClient>,
}

/// Key generation protocol initialization context.
#[derive(Debug)]
pub struct DefaultKeyGenerationInit {
    /// Unique key identifier.
    pub key_id: String,
    /// Algorithm name.
    pub algorithm: Algorithm,
    /// Number of participants.
    pub threshold: u32,
    /// Number of total participants.
    pub participants: u32,
}

/// Node participant key generation protocol initialization context.
#[derive(Debug)]
pub struct NodeKeyGenerationInit {
    /// Common key generation initialization parameters.
    pub common: DefaultKeyGenerationInit,
    /// Participant's identifier as u32.
    pub identifier: u32,
}

/// Controller key generation protocol initialization context.
#[derive(Debug)]
pub struct ControllerKeyGenerationInit {
    /// Common key generation initialization parameters.
    pub common: DefaultKeyGenerationInit,
}

/// Message exchanged between participants during protocol execution.
#[derive(Debug, Clone)]
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

/// Final output of a protocol execution.
#[derive(Debug)]
pub enum ProtocolOutput {
    /// Result of a key generation protocol.
    KeyGeneration {
        /// Unique key identifier.
        key_id: String,
        /// Blob to be stored locally (protocol-specific).
        key_share: KeyShare,
        /// Public key bytes (curve-specific, canonical format).
        public_key: Vec<u8>,
        /// Serialized protocol-specific public key package.
        /// Required for threshold signing aggregation.
        /// For FROST: serialized frost::keys::PublicKeyPackage (postcard
        /// encoded). For CGGMP24: protocol-specific aggregation
        /// context.
        public_key_package: Vec<u8>,
    },

    /// Result of a signing protocol.
    Signature(FinalSignature),
}
