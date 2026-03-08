//! Configuration — structured settings for all runtime components.
//!
//! `controller` and `node` define the top-level runtime configurations.
//! `ipc` holds inter-process communication settings shared between them.
//! `api` configures the external-facing HTTP interface.

pub mod api;
pub mod controller;
pub mod ipc;
pub mod node;
