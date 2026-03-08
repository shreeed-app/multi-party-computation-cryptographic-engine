//! Authentication — bearer token validation and session management.
//!
//! `bearer_client` attaches outgoing bearer tokens to gRPC requests.
//! `bearer_server` validates incoming bearer tokens on the node side.
//! `session` manages authenticated session state for active connections.

pub mod bearer_client;
pub mod bearer_server;
pub mod session;