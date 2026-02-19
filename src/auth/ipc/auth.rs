//! IPC authentication for gRPC requests.

use tonic::{
    Request,
    metadata::{Ascii, MetadataValue},
};

use crate::{auth::identity::Identity, transport::errors::Errors};

/// IPC authentication provider. This trait defines how incoming IPC requests
/// are authenticated.
pub trait AuthProvider: Send + Sync {
    /// Authenticate an incoming request.
    ///
    /// # Errors
    /// `Result<Identity, Error>` - Returns an authentication error if the
    ///     request is not authorized.
    fn authenticate<T>(
        &self,
        request: &Request<T>,
    ) -> Result<Identity, Errors>;
}

/// Token-based IPC authentication. Intended for local IPC over Unix sockets
/// or mTLS-protected channels.
pub struct TokenAuth {
    expected_token: String,
    identity: Identity,
}

impl TokenAuth {
    /// Create a new token authentication provider.
    ///
    /// # Arguments
    /// * `expected_token` (`String`) - Pre-shared authentication token.
    /// * `identity` (`Identity`) - Identity to associate with authenticated
    ///   requests.
    ///
    /// # Returns
    /// * `Self` - New token authentication provider.
    pub fn new(expected_token: String, identity: Identity) -> Self {
        Self { expected_token, identity }
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
    fn authenticate<T>(
        &self,
        request: &Request<T>,
    ) -> Result<Identity, Errors> {
        let value: &MetadataValue<Ascii> =
            match request.metadata().get("authorization") {
                Some(value) => value,
                None => return Err(Errors::MissingAuthorization),
            };

        let token: &str = match value.to_str() {
            Ok(token) => token,
            Err(_) => return Err(Errors::InvalidAuthorizationEncoding),
        };

        if token != self.expected_token {
            return Err(Errors::InvalidToken);
        }

        Ok(self.identity.clone())
    }
}
