//! Node configuration module.

use std::{fs::read_to_string, io::Error as IoError};

use serde::Deserialize;
use toml::{de::Error as TomlError, from_str};

use crate::{
    config::{api::RuntimeConfig, ipc::NodeIpcConfig},
    secrets::vault::config::VaultConfig,
    transport::errors::Errors,
};

/// Node runtime configuration and related types.
#[derive(Debug, Deserialize)]
pub struct NodeRuntimeConfig {
    /// IPC configuration for the node.
    pub ipc: NodeIpcConfig,
    /// Vault configuration for the node.
    pub vault: VaultConfig,
}

impl RuntimeConfig for NodeRuntimeConfig {
    /// Load configuration from a file path.
    ///
    /// # Arguments
    /// * `path` (`&str`) - Path to the configuration file.
    ///
    /// # Errors
    /// * `Errors` - If file reading or parsing fails.
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
