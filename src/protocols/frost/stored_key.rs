//! FROST stored key representation.

use rkyv::{Archive, Deserialize, Serialize};

/// Stored in Vault for any FROST participant.
#[derive(Debug, PartialEq, Archive, Serialize, Deserialize)]
pub struct FrostStoredKey {
    /// Canonical participant identifier.
    pub identifier: u32,
    /// postcard-encoded KeyPackage (curve-specific).
    pub key_package: Vec<u8>,
    /// Opaque protocol-specific blob for public key reconstruction.
    pub public_key_package: Vec<u8>,
}
