//! Configuration module for loading settings from environment variables.

use figment::providers::Env;
use figment::{Error, Figment};
use once_cell::sync::Lazy;
use serde::{Deserialize, Deserializer};

/// Custom deserializer that converts empty strings to `None`.
///
/// # Arguments
/// * `deserializer` (`D`) - The deserializer to use.
///
/// # Returns
/// * `Result<Option<String>, D::Error>` - The deserialized optional string.
pub fn empty_string_as_none<'l, D: Deserializer<'l>>(
    deserializer: D,
) -> Result<Option<String>, D::Error> {
    let option: Option<String> = Option::<String>::deserialize(deserializer)?;
    Ok(option.filter(|string: &String| !string.trim().is_empty()))
}

/// Configuration loaded from environment variables.
#[derive(Debug, Deserialize)]
pub struct EnvConfig {
    /// IPC configuration path.
    pub ipc_config_path: String,
    /// Vault configuration path.
    pub vault_config_path: String,
    /// Vault token.
    #[serde(deserialize_with = "empty_string_as_none")]
    pub vault_token: Option<String>,
}

/// Static lazy-loaded environment configuration.
pub static CONFIG: Lazy<Result<EnvConfig, Error>> =
    Lazy::new(|| Figment::new().merge(Env::raw()).extract());

impl EnvConfig {
    /// Load configuration from environment variables.
    ///
    /// # Errors
    /// * `Error` - If loading fails.
    ///
    /// # Returns
    /// * `&'static EnvConfig` - Loaded environment configuration.
    pub fn load() -> Result<&'static EnvConfig, &'static Error> {
        CONFIG.as_ref()
    }
}
