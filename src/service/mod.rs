//! Service layer — request handling and session lifecycle management.
//!
//! `controller_engine` drives sessions across nodes, coordinating
//! round dispatch and finalization. `node_engine` manages local protocol
//! execution and interfaces with key storage. `api` handles external HTTP
//! requests. `entry` defines shared session entry types. `builder` provides
//! construction helpers for service instances.

pub mod api;
pub mod builder;
pub mod controller_engine;
pub mod entry;
pub mod node_engine;
