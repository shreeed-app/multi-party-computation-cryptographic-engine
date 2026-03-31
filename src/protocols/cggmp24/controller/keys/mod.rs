//! CGGMP24 controller-side key generation protocol implementations.
//!
//! Key generation is orchestrated by the controller across two phases:
//! distributed key generation (DKG) followed by auxiliary info generation.
//! Each phase produces key material stored in Vault per participant.
//! Curve-specific protocol instances live in their own modules.

pub mod auxiliary;
pub mod ecdsa_secp256k1;
