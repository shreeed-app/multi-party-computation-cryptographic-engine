//! FROST(ed25519) curve implementation for node-side signing.

use super::protocol::{FrostNodeSigning, FrostSigningCurve};

/// Concrete type alias for FROST(ed25519) node signing.
pub type FrostEd25519NodeSigning = FrostNodeSigning<FrostEd25519SigningCurve>;

/// FROST(ed25519) curve descriptor for signing.
pub struct FrostEd25519SigningCurve;

impl FrostSigningCurve for FrostEd25519SigningCurve {
    type Curve = frost_ed25519::Ed25519Sha512;
}
