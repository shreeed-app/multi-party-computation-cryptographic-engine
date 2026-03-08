//! FROST participant-side key generation protocols.
//!
//! The DKG logic lives in `protocol` as a single generic implementation over
//! the `FrostCurve` trait. Each curve variant (`ed25519`, `schnorr_secp256k1`)
//! implements that trait and exposes a concrete type alias.

pub mod ed25519;
pub mod protocol;
pub mod schnorr_secp256k1;
