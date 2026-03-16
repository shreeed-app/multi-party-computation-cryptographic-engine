//! CGGMP24 threshold ECDSA protocols.
//!
//! `controller` orchestrates key generation and signing across nodes.
//! `node` implements the local participant-side protocol execution.
//! `stored_key` defines the serialization format for persisted key shares.
//! `wire` defines the on-wire message format for CGGMP24 protocol messages.

pub mod controller;
pub mod node;
pub mod security_level;
pub mod stored_key;
pub mod wire;
