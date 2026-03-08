//! FROST controller-side signing protocols.
//!
//! The signing logic lives in `protocol` as a single generic implementation
//! over the `FrostControllerSigningCurve` trait. Each curve variant
//! (`ed25519`, `schnorr_secp256k1`) implements that trait and exposes a
//! concrete type alias.

pub mod ed25519;
pub mod protocol;
pub mod schnorr_secp256k1;
