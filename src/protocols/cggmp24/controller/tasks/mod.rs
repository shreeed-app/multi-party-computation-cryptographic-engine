//! CGGMP24 controller-side signing protocol implementations.
//!
//! Signing is orchestrated by the controller, which manages session
//! lifecycle, routes messages between participant nodes across rounds,
//! and finalizes all sessions to produce the aggregated signature.
//! Curve-specific protocol instances live in their own modules.

pub mod ecdsa_secp256k1;
