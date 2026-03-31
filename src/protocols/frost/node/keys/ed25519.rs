//! FROST(ed25519) curve implementation for node-side key generation.

use super::protocol::{FrostCurve, FrostNodeKeyGeneration};

/// Concrete type alias for FROST(ed25519) node key generation.
pub type FrostEd25519NodeKeyGeneration =
    FrostNodeKeyGeneration<FrostEd25519Curve>;

/// FROST(ed25519) curve descriptor.
pub struct FrostEd25519Curve;

impl FrostCurve for FrostEd25519Curve {
    type Curve = frost_ed25519::Ed25519Sha512;
}
