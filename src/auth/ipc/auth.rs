//! IPC authentication for gRPC requests.

use tonic::{
    Request,
    metadata::{Ascii, MetadataValue},
};

use crate::messages::error::Error;

/// IPC authentication provider.
///
/// This trait defines how incoming IPC requests are authenticated.
pub trait AuthProvider: Send + Sync {
    /// Authenticate an incoming request.
    ///
    /// # Errors
    /// `Result<(), Error>` - Returns an authentication error if the
    ///     request is not authorized.
    fn authenticate<T>(&self, request: &Request<T>) -> Result<(), Error>;
}

/// Token-based IPC authentication.
///
/// Intended for local IPC over Unix sockets or mTLS-protected channels.
pub struct TokenAuth {
    expected_token: String,
}

impl TokenAuth {
    /// Create a new token authentication provider.
    ///
    /// # Arguments
    /// * `expected_token` - Pre-shared authentication token.
    ///
    /// # Returns
    /// * `Self` - New token authentication provider.
    pub fn new(expected_token: String) -> Self {
        Self { expected_token }
    }
}

impl AuthProvider for TokenAuth {
    /// Authenticate an incoming request using a pre-shared token.
    ///
    /// # Errors
    /// `Result<(), AuthError>` - Returns an authentication error if the
    ///     request is not authorized.
    ///
    /// # Arguments
    /// * `request` (`&Request<T>`) - Incoming gRPC request.
    ///
    /// # Returns
    /// * `Result<(), AuthError>` - Ok if authenticated, error otherwise.
    fn authenticate<T>(&self, request: &Request<T>) -> Result<(), Error> {
        let value: &MetadataValue<Ascii> = request
            .metadata()
            .get("authorization")
            .ok_or(Error::MissingAuthorization)?;

        let token: &str =
            value.to_str().map_err(|_| Error::InvalidAuthorizationEncoding)?;

        if token != self.expected_token {
            return Err(Error::InvalidToken);
        }

        Ok(())
    }
}
