//! CGGMP24 node-side signing protocols.
//!
//! Signing logic is in `worker` as a generic implementation over
//! `CggmpProtocol`. Curve-specific protocol instances live in their own
//! modules.

pub mod ecdsa_secp256k1;
pub mod worker;
