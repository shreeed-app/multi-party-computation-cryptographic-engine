//! Vault provider abstraction for key shares.

use async_trait::async_trait;

use crate::{secrets::types::KeyShare, transport::error::Error};

/// Vault abstraction for retrieving key shares.
#[async_trait]
pub trait VaultProvider: Send + Sync + 'static {
    /// Retrieve a key share by its identifier.
    ///
    /// # Arguments
    /// * `key_id` (`&str`) - Identifier of the key share.
    ///
    /// # Errors
    /// * `Error` - If retrieval fails.
    ///
    /// # Returns
    /// * `KeyShare` - Opaque key share bytes.
    async fn get_key_share(&self, key_id: &str) -> Result<KeyShare, Error>;

    /// Store a key share by its identifier.
    ///
    /// # Arguments
    /// * `key_id` (`&str`) - Identifier of the key share.
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
    ) -> Result<(), Error>;
}
