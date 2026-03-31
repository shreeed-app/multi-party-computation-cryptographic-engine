//! CGGMP24 controller-side protocol implementations.
//!
//! The controller orchestrates all CGGMP24 multi-party protocols across
//! participant nodes. It manages session lifecycle, routes messages between
//! nodes, and finalizes outputs.
//!
//! - `keys` — key generation and auxiliary info generation protocols.
//! - `tasks` — signing protocols.

pub mod keys;
pub mod protocol;
pub mod tasks;
