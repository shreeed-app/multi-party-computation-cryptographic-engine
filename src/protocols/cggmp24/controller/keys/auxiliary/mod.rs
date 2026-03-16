//! CGGMP24 controller-side auxiliary info generation protocol implementations.
//!
//! Auxiliary info generation sets up the Paillier moduli and Pedersen
//! parameters required for signing. It is run once after DKG and produces
//! complete key shares by combining the `IncompleteKeyShare` from keygen
//! with the generated `AuxInfo`. Curve-specific instances live in their own
//! modules.

pub mod ecdsa_secp256k1;
