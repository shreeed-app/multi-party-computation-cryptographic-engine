//! HashiCorp Vault provider (KV v2).

use async_trait::async_trait;
use base64::{
    Engine as _,
    engine::general_purpose,
};
use serde_json::Value;
use vaultrs::{
    client::{
        VaultClient,
        VaultClientSettings,
        VaultClientSettingsBuilder,
    },
    kv2,
};

use crate::{
    config::EnvConfig,
    messages::error::Error,
    secrets::{
        secret::Secret,
        vault::{
            api::VaultProvider,
            config::VaultConfig,
        },
    },
};

/// HashiCorp Vault KVv2 provider.
/// It reads secrets from {mount}/{prefix}/{key_id}.
pub struct HashicorpVaultProvider {
    /// Vault client.
    client: VaultClient,
    /// KV mount point, e.g. "secret" or "kv".
    mount: String,
    /// Base prefix under mount, e.g. "mpc/shares".
    prefix: String,
    /// Field in JSON containing base64 share.
    field: String,
}

impl HashicorpVaultProvider {
    /// Build a provider from config.
    ///
    /// # Arguments
    /// * `config` (`VaultConfig`) - Vault configuration.
    ///
    /// # Errors
    /// * `Error` - If initialization fails.
    ///
    /// # Returns
    /// * `Self` - New HashiCorp Vault provider instance.
    pub fn try_from_config(config: VaultConfig) -> Result<Self, Error> {
        let token: String = match &config.token {
            Some(token) => token.clone(),
            None => match EnvConfig::load() {
                Ok(config) => match &config.vault_token {
                    Some(token) => token.clone(),
                    None => return Err(Error::VaultTokenMissing),
                },
                Err(_) => return Err(Error::VaultTokenMissing),
            },
        };

        let settings: VaultClientSettings =
            match VaultClientSettingsBuilder::default()
                .address(config.address.clone())
                .set_namespace(config.namespace.clone().unwrap_or_default())
                .token(token)
                .build()
            {
                Ok(settings) => settings,
                Err(_) => return Err(Error::VaultConfigError),
            };

        let client: VaultClient = match VaultClient::new(settings) {
            Ok(client) => client,
            Err(_) => return Err(Error::VaultError),
        };

        Ok(Self {
            client,
            mount: config.mount,
            prefix: config.prefix,
            field: config.field,
        })
    }

    /// Resolve Vault path for a given key_id.
    ///
    /// # Arguments
    /// * `key_id` (`&str`) - Key share identifier.
    ///
    /// # Returns
    /// * `String` - Full Vault secret path.
    fn secret_path(&self, key_id: &str) -> String {
        let prefix: &str = self.prefix.trim_matches('/');
        let key_id: &str = key_id.trim_matches('/');
        format!("{}/{}", prefix, key_id)
    }
}

#[async_trait]
impl VaultProvider for HashicorpVaultProvider {
    async fn get_key_share(
        &self,
        key_id: &str,
    ) -> Result<Secret<Vec<u8>>, Error> {
        let path: String = self.secret_path(key_id);

        // We read JSON data from Vault KV v2, it returns a "data" object
        // with versioning. It deserializes the "data" content.
        let value: Value =
            match kv2::read(&self.client, &self.mount, &path).await {
                Ok(data) => data,
                Err(_) => return Err(Error::KeyNotFound),
            };

        // Extract field (configurable) from JSON.
        let share_b64: &str = match value
            .get(&self.field)
            .and_then(|value: &Value| value.as_str())
        {
            Some(share) => share,
            None => return Err(Error::InvalidKeyShare),
        };

        // Decode base64 to opaque bytes.
        let bytes: Vec<u8> = match general_purpose::STANDARD
            .decode(share_b64.as_bytes())
            .map_err(|_| Error::InvalidKeyShare)
        {
            Ok(bytes) => bytes,
            Err(error) => return Err(error),
        };

        Ok(Secret::new(bytes))
    }
}
