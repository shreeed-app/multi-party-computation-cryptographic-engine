//! Mock authentication providers for testing.
use mpc_signer_engine::auth::ipc::auth::AuthProvider;
use mpc_signer_engine::messages::error::Error;
use tonic::Request;

/// Auth provider that always allows requests.
pub struct AllowAllAuth;

impl AuthProvider for AllowAllAuth {
    fn authenticate<T>(&self, _: &Request<T>) -> Result<(), Error> {
        Ok(())
    }
}

/// Auth provider that always rejects requests.
pub struct DenyAllAuth;

impl AuthProvider for DenyAllAuth {
    fn authenticate<T>(&self, _: &Request<T>) -> Result<(), Error> {
        Err(Error::InvalidToken)
    }
}
