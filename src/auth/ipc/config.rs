//! IPC runtime configuration.

use config::{Config, ConfigError, File};
use serde::Deserialize;

/// IPC runtime configuration.
#[derive(Debug, Deserialize)]
pub struct IpcConfig {
    /// Logical node identifier (used for scoping).
    pub node_id: String,

    /// Authentication configuration.
    pub auth: AuthConfig,
}

/// IPC authentication configuration.
#[derive(Debug, Deserialize)]
pub struct AuthConfig {
    /// Shared secret or token for IPC authentication.
    pub token: String,
}

impl IpcConfig {
    /// Load configuration from a file.
    ///
    /// # Errors
    /// `Result<Self, ConfigError>` - Returns an error if the file cannot
    ///     be read or parsed.
    pub fn load(path: &str) -> Result<Self, ConfigError> {
        Config::builder()
            .add_source(File::with_name(path))
            .build()?
            .try_deserialize()
    }
}
