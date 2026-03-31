//! FROST(schnorr-secp256k1) curve implementation for controller-side signing.

use frost_secp256k1::Secp256K1Sha256;

use super::protocol::{FrostControllerSigning, FrostControllerSigningCurve};

/// Concrete type alias for FROST(schnorr-secp256k1) controller signing.
pub type FrostSchnorrSecp256k1ControllerSigning =
    FrostControllerSigning<FrostSchnorrSecp256k1ControllerSigningCurve>;

/// FROST(schnorr-secp256k1) curve descriptor for controller-side signing.
pub struct FrostSchnorrSecp256k1ControllerSigningCurve;

impl FrostControllerSigningCurve
    for FrostSchnorrSecp256k1ControllerSigningCurve
{
    type Curve = Secp256K1Sha256;
}
