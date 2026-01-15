//! Vault provider abstraction for key shares.

use async_trait::async_trait;

use crate::messages::error::Error;
use crate::secrets::types::KeyShare;

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
}
