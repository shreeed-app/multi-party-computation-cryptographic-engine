//! CGGMP24 node-side key generation protocols.
//!
//! Key generation logic is in `worker` as a generic implementation over
//! `CggmpProtocol`. Curve-specific protocol instances live in their own
//! modules.

pub mod ecdsa_secp256k1;
pub mod worker;