//! HashiCorp Vault provider (KV v2).

use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose};
use serde_json::Value;
use vaultrs::{
    client::{VaultClient, VaultClientSettings, VaultClientSettingsBuilder},
    kv2,
};

use crate::{
    secrets::{
        secret::Secret,
        types::KeyShare,
        vault::{api::VaultProvider, config::VaultConfig},
    },
    transport::errors::Errors,
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
    pub fn try_from_config(config: VaultConfig) -> Result<Self, Errors> {
        let token: String = match &config.token {
            Some(token) => token.clone(),
            None => return Err(Errors::VaultTokenMissing),
        };

        let settings: VaultClientSettings =
            match VaultClientSettingsBuilder::default()
                .address(config.address.clone())
                .set_namespace(config.namespace.clone().unwrap_or_default())
                .token(token)
                .build()
            {
                Ok(settings) => settings,
                Err(_) => return Err(Errors::VaultConfigError),
            };

        let client: VaultClient = match VaultClient::new(settings) {
            Ok(client) => client,
            Err(_) => return Err(Errors::VaultError),
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
    ) -> Result<Secret<Vec<u8>>, Errors> {
        let path: String = self.secret_path(key_id);
        // Extract and decode the base64 share in steps: first get the string,
        // then decode to bytes, then drop JSON value.
        let bytes: Vec<u8> = {
            // Get the base64 string from JSON.
            let value: Value =
                match kv2::read(&self.client, &self.mount, &path).await {
                    Ok(data) => data,
                    Err(_) => return Err(Errors::KeyNotFound),
                };

            // Decode base64 to bytes.
            let bytes: Vec<u8> = {
                let share_b64: &str = value
                    .get(&self.field)
                    .and_then(|value: &Value| value.as_str())
                    .ok_or(Errors::InvalidKeyShare)?;

                general_purpose::STANDARD
                    .decode(share_b64.as_bytes())
                    .map_err(|_| Errors::InvalidKeyShare)?
            };

            bytes
        };

        // Put the bytes into Secret immediately.
        Ok(Secret::new(bytes))
    }

    /// Store a key share in Vault.
    ///
    /// # Arguments
    /// * `key_id` (`&str`) - Key share identifier.
    /// * `key_share` (`&KeyShare`) - Opaque key share bytes.
    ///
    /// # Errors
    /// * `Error` - If storage fails.
    ///
    /// # Returns
    /// * `()` - Empty result on success.
    async fn store_key_share(
        &self,
        key_id: &str,
        key_share: KeyShare,
    ) -> Result<(), Errors> {
        let path: String = self.secret_path(key_id);

        // Encode directly from reference, without cloning.
        let share_b64: String = key_share.with_ref(|bytes: &Vec<u8>| {
            general_purpose::STANDARD.encode(bytes)
        });

        // Prepare JSON object with field.
        let mut data: Value = Value::Object(serde_json::Map::new());
        if let Some(data) = data.as_object_mut() {
            data.insert(self.field.clone(), Value::String(share_b64));
        } else {
            return Err(Errors::VaultError);
        }

        // Store in Vault KV v2.
        match kv2::set(&self.client, &self.mount, &path, &data).await {
            Ok(_) => Ok(()),
            Err(_) => Err(Errors::VaultError),
        }
    }
}
