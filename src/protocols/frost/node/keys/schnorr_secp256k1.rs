//! FROST(Schnorr secp256k1) curve implementation for node-side key generation.

use super::protocol::{FrostCurve, FrostNodeKeyGeneration};

/// Concrete type alias for FROST(schnorr secp256k1) node key generation.
pub type FrostSchnorrSecp256k1NodeKeyGeneration =
    FrostNodeKeyGeneration<FrostSchnorrSecp256k1Curve>;

/// FROST(schnorr secp256k1) curve descriptor.
pub struct FrostSchnorrSecp256k1Curve;

impl FrostCurve for FrostSchnorrSecp256k1Curve {
    type Curve = frost_secp256k1::Secp256K1Sha256;
}
