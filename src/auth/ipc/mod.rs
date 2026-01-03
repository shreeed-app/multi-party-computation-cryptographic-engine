//! IPC module for the Multi-Party Computation signer engine.
//!
//! This module provides the necessary components for inter-process
//! communication (IPC) in the MPC signer engine. It includes authentication
//! mechanisms and the gRPC server implementation to handle signing requests.

pub mod auth;
pub mod config;
pub mod server;

#[cfg(test)]
pub mod tests;
