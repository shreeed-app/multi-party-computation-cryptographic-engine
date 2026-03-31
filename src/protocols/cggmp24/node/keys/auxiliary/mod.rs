//! CGGMP24 node-side auxiliary information generation protocols.
//!
//! Auxiliary information generation sets up the Paillier moduli and Pedersen
//! parameters required for signing. It is run once after key generation and
//! produces a complete `KeyShare` by combining the `IncompleteKeyShare` from
//! DKG with the generated `AuxInfo`.
//!
//! The generic worker logic lives in `worker`, and curve-specific protocol
//! instances live in their own modules.

pub mod ecdsa_secp256k1;
pub mod worker;
