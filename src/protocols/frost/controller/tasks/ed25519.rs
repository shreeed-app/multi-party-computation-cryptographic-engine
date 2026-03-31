//! FROST(ed25519) curve implementation for controller-side signing.

use frost_ed25519::Ed25519Sha512;

use super::protocol::{FrostControllerSigning, FrostControllerSigningCurve};

/// Concrete type alias for FROST(ed25519) controller signing.
pub type FrostEd25519ControllerSigning =
    FrostControllerSigning<FrostEd25519ControllerSigningCurve>;

/// FROST(ed25519) curve descriptor for controller-side signing.
pub struct FrostEd25519ControllerSigningCurve;

impl FrostControllerSigningCurve for FrostEd25519ControllerSigningCurve {
    type Curve = Ed25519Sha512;
}
