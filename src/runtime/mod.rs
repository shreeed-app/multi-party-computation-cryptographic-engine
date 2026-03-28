//! Runtime management.
//!
//! Each runtime binds a gRPC server to a configured address and wires up
//! the service layer. `controller` orchestrates the session lifecycle
//! across nodes. `node` handles local protocol execution and key storage.
//! `api` exposes the external-facing HTTP interface.

pub mod api;
pub mod controller;
pub mod node;
pub mod types;
