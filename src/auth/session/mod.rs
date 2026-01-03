//! MPC session management.
//!
//! This module enforces the lifecycle and state transitions
//! of MPC signing sessions. It is a critical security boundary.

pub mod identifier;
pub mod state;
pub mod store;

#[cfg(test)]
pub mod tests;
