//! Vault configuration loader.

use config::{Config, ConfigError, File};
use serde::Deserialize;

/// HashiCorp Vault KVv2 configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct VaultConfig {
    /// Vault address, e.g. "https://vault.service.consul:8200".
    pub address: String,
    /// KV mount, e.g. "secret" or "kv"
    pub mount: String,
    /// Base prefix under mount, e.g. "mpc/shares".
    pub prefix: String,
    /// Which field contains the base64 payload inside the KV JSON data.
    /// Example secret JSON: { "share_b64": "...." }
    pub field: String,
    /// Optional Vault namespace for Vault Enterprise.
    pub namespace: Option<String>,
    /// Token can be provided directly, but prefer env var.
    pub token: Option<String>,
}

impl VaultConfig {
    /// Load Vault config from file.
    ///
    /// # Arguments
    /// * `path` (`&str`) - Config file path.
    ///
    /// # Errors
    /// * `ConfigError` - If loading fails.
    ///
    /// # Returns
    /// * `Self` - Loaded Vault configuration.
    pub fn load(path: &str) -> Result<Self, ConfigError> {
        Config::builder()
            .add_source(File::with_name(path))
            .build()?
            .try_deserialize()
    }
}
