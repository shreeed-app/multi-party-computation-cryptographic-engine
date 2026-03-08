//! Transport layer — wire format, error types, and protocol mappings.
//!
//! `grpc` contains the gRPC client, servers, and protobuf translation layer.
//! `errors` defines transport-level error variants shared across the stack.

pub mod errors;
pub mod grpc;
