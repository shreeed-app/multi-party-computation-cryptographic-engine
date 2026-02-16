//! Mock Vault Provider for testing purposes.
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use async_trait::async_trait;
use mpc_signer_engine::{
    secrets::{types::KeyShare, vault::api::VaultProvider},
    transport::error::Error,
};

/// In-memory mock Vault provider.
#[derive(Clone, Default)]
pub struct MockVault {
    inner: Arc<Mutex<HashMap<String, KeyShare>>>,
}

#[async_trait]
impl VaultProvider for MockVault {
    /// Retrieve a key share by its identifier.
    ///
    /// # Arguments
    /// * `key_id` (`&str`) - Key share identifier.
    ///
    /// # Errors
    /// * `Error` - If retrieval fails.
    async fn get_key_share(&self, key_id: &str) -> Result<KeyShare, Error> {
        self.inner
            .lock()
            .map_err(|_| Error::VaultError)?
            .remove(key_id)
            .ok_or(Error::KeyNotFound)
    }

    /// Store a key share by its identifier.
    ///
    /// # Arguments
    /// * `key_id` (`&str`) - Key share identifier.
    /// * `key_share` (`&KeyShare`) - Opaque key share bytes.
    ///
    /// # Errors
    /// * `Error` - If storage fails.
    async fn store_key_share(
        &self,
        key_id: &str,
        key_share: KeyShare,
    ) -> Result<(), Error> {
        self.inner
            .lock()
            .map_err(|_| Error::VaultError)?
            .insert(key_id.to_string(), key_share);
        Ok(())
    }
}
