//! IPC runtime configuration.

use serde::Deserialize;

/// IPC runtime configuration for the node.
#[derive(Debug, Deserialize)]
pub struct NodeIpcConfig {
    /// Logical node identifier (used for scoping).
    pub node_id: String,
    /// Participant ID for the node (used for authentication).
    pub participant_id: u32,
    /// Authentication configuration.
    pub auth: AuthConfig,
    /// IPC server address (e.g. "[::1]:50051").
    pub address: String,
    /// Session TTL in seconds.
    pub ttl_seconds: u64,
}

/// IPC runtime configuration for the controller.
#[derive(Debug, Deserialize)]
pub struct ControllerIpcConfig {
    /// IPC server address (e.g. "[::1]:50051").
    pub address: String,
    /// Logical service identifier (used for scoping).
    pub service_id: String,
    /// Authentication configuration.
    pub auth: AuthConfig,
}

/// IPC authentication configuration.
#[derive(Debug, Deserialize)]
pub struct AuthConfig {
    /// Shared secret or token for IPC authentication.
    pub token: String,
}
