use std::{collections::HashMap, sync::Arc};

use app::{
    secrets::{secret::Secret, types::KeyShare, vault::api::VaultProvider},
    transport::errors::Errors,
};
use async_trait::async_trait;
use tokio::sync::Mutex;

/// In-memory vault mock. Key shares are stored in a `HashMap` protected by
/// a `Mutex` so the provider can be cloned and shared across async tasks.
#[derive(Clone)]
pub struct MockVaultProvider {
    store: Arc<Mutex<HashMap<String, Vec<u8>>>>,
}

impl MockVaultProvider {
    /// Create a new, empty mock vault.
    pub fn new() -> Self {
        Self { store: Arc::new(Mutex::new(HashMap::new())) }
    }
}

#[async_trait]
impl VaultProvider for MockVaultProvider {
    async fn get_key_share(
        &self,
        key_identifier: &str,
    ) -> Result<KeyShare, Errors> {
        self.store
            .lock()
            .await
            .get(key_identifier)
            .map(|bytes: &Vec<u8>| Secret::new(bytes.clone()))
            .ok_or_else(|| {
                Errors::VaultError(format!(
                    "Key not found in mock vault: {}",
                    key_identifier
                ))
            })
    }

    async fn store_key_share(
        &self,
        key_identifier: &str,
        key_share: KeyShare,
    ) -> Result<(), Errors> {
        let bytes: Vec<u8> =
            key_share.with_ref(|bytes: &Vec<u8>| bytes.clone());
        self.store.lock().await.insert(key_identifier.to_string(), bytes);
        Ok(())
    }
}
