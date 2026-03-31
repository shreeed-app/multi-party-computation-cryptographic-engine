//! FROST(schnorr-secp256k1) curve implementation for node-side signing.

use super::protocol::{FrostNodeSigning, FrostSigningCurve};

/// Concrete type alias for FROST(schnorr-secp256k1) node signing.
pub type FrostSchnorrSecp256k1NodeSigning =
    FrostNodeSigning<FrostSchnorrSecp256k1SigningCurve>;

/// FROST(schnorr-secp256k1) curve descriptor for signing.
pub struct FrostSchnorrSecp256k1SigningCurve;

impl FrostSigningCurve for FrostSchnorrSecp256k1SigningCurve {
    type Curve = frost_secp256k1::Secp256K1Sha256;
}
