//! CGGMP'24 stored key representation.

use rkyv::{Archive, Deserialize, Serialize};

/// Stored in Vault for any CGGMP'24 participant.
#[derive(Debug, PartialEq, Archive, Serialize, Deserialize)]
pub struct Cggmp24StoredKey {
    /// Canonical participant identifier (1-based index).
    pub identifier: u16,
    /// JSON-encoded cggmp24::security_level::SecurityLevel (optional/implicit
    /// in share). Used here mainly to store the
    /// `cggmp24::key_share::KeyShare` serialized as JSON.
    pub key_share_json: Vec<u8>,
}
