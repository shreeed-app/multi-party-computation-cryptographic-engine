//! Transport layer for gRPC communication.
//!
//! `node_client` sends requests from the controller to nodes over gRPC.
//! `node_server` and `controller_server` expose the gRPC service endpoints.
//! `mapping` translates between internal domain types and protobuf messages.

pub mod controller_server;
pub mod mapping;
pub mod node_client;
pub mod node_server;
