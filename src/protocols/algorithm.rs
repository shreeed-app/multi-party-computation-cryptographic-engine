//! Supported signing algorithms.

use serde::{
    Deserialize,
    Serialize,
};
use strum_macros::{
    AsRefStr,
    EnumString,
};

/// Supported signing algorithms.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
    Serialize,
    Deserialize,
    AsRefStr,
    EnumString,
)]
#[strum(serialize_all = "kebab-case")]
#[serde(rename_all = "kebab-case")]
pub enum Algorithm {
    /// FROST over Ed25519 (RFC 8032).
    FrostEd25519,
    /// FROST Schnorr over Secp256k1.
    FrostSchnorrSecp256k1,
    /// CGGMP'24 ECDSA over Secp256k1.
    Cggmp24EcdsaSecp256k1,
}

impl Algorithm {
    /// Canonical string identifier.
    ///
    /// # Returns
    /// * `&str` - String representation of the algorithm.
    #[inline]
    pub fn as_str(&self) -> &str {
        self.as_ref()
    }
}
