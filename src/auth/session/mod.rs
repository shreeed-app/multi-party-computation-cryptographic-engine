//! Session lifecycle management.
//!
//! `store` holds active sessions keyed by identifier. `state` defines the
//! session state machine and valid transitions. `identifier` provides
//! typed session identifier wrappers.

pub mod identifier;
pub mod state;
pub mod store;
