//! Mock authentication provider for testing purposes.
use mpc_signer_engine::{
    auth::ipc::auth::AuthProvider,
    transport::error::Error,
};
use tonic::Request;

/// Mock authentication provider that allows all requests.
#[derive(Clone, Default)]
pub struct MockAuth;

impl AuthProvider for MockAuth {
    /// Always authenticate successfully.
    ///
    /// # Arguments
    /// * `request` (`&Request<T>`) - Incoming request to authenticate.
    ///
    /// # Returns
    /// * `Result<(), Error>` - Always returns `Ok(())`.
    fn authenticate<T>(&self, _: &Request<T>) -> Result<(), Error> {
        Ok(())
    }
}
