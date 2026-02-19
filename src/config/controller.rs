//! Controller configuration module.

use std::{fs::read_to_string, io::Error as IoError};

use serde::Deserialize;
use toml::{de::Error as TomlError, from_str};

use crate::{
    auth::ipc::config::ControllerIpcConfig,
    config::api::RuntimeConfig,
    transport::errors::Errors,
};

/// Controller runtime configuration and related types.
#[derive(Debug, Deserialize)]
pub struct ControllerRuntimeConfig {
    /// IPC configuration for the controller.
    pub ipc: ControllerIpcConfig,
    /// List of nodes that the controller will connect to.
    pub nodes: Vec<NodeConfig>,
}

/// Configuration for a node that the controller will connect to.
#[derive(Debug, Deserialize)]
pub struct NodeConfig {
    /// Endpoint of the node's IPC server.
    pub endpoint: String,
    /// Participant ID associated with the node.
    pub participant_id: u32,
    /// Authentication token for connecting to the node.
    pub auth_token: String,
}

impl RuntimeConfig for ControllerRuntimeConfig {
    /// Load configuration from a file path.
    ///
    /// # Arguments
    /// * `path` (`&str`) - Path to the configuration file.
    ///
    /// # Errors
    /// * `Error` - If file reading or parsing fails.
    ///
    /// # Returns
    /// * `Self` - Loaded configuration instance.
    fn load_from_file(path: &str) -> Result<Self, Errors> {
        let content: String =
            read_to_string(path).map_err(|error: IoError| {
                Errors::ConfigError(error.to_string())
            })?;

        from_str(&content)
            .map_err(|error: TomlError| Errors::ConfigError(error.to_string()))
    }
}
