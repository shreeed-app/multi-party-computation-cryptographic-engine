//! Protocol implementations.
//!
//! This module organizes all supported protocol families, the factory
//! responsible for instantiating them, and the shared types and traits they
//! build on.
//!
//! # Structure
//! - `algorithm` — Algorithm identifier enum shared across all protocols.
//! - `cggmp24` — CGGMP-24 ECDSA key generation and signing over secp256k1.
//! - `frost` — FROST threshold Schnorr key generation and signing over ed25519
//!   and secp256k1.
//! - `factory` — Protocol factory: instantiates the correct protocol from a
//!   `ProtocolInit` context.
//! - `codec` — Wire encoding/decoding utilities shared across protocols.
//! - `protocol` — `Protocol` trait definition.
//! - `types` — Shared initialization and output types.

pub mod algorithm;
pub mod cggmp24;
pub mod codec;
pub mod factory;
pub mod frost;
pub mod protocol;
pub mod types;
