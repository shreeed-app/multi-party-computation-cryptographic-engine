//! FROST threshold signature protocols.
//!
//! `controller` orchestrates key generation and signing across nodes.
//! `node` implements the local participant-side protocol execution.
//! `stored_key` defines the serialization format for persisted key shares.
//! `wire` defines the on-wire message format for FROST protocol messages.

pub mod controller;
pub mod node;
pub mod stored_key;
pub mod wire;
