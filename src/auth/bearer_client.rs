//! Authentication components ensuring authentication between controller and
//! nodes.

use headers::{Authorization, authorization::Bearer};
use http::header::AUTHORIZATION;
use tonic::{
    Request,
    Status,
    metadata::{Ascii, MetadataValue},
    service::Interceptor,
};

use crate::{config::ipc::AuthConfig, transport::errors::Errors};

/// Authentication interceptor for gRPC clients.
#[derive(Clone)]
pub struct ClientAuthInterceptor {
    /// The token to be included in the Authorization header.
    pub config: AuthConfig,
}

impl Interceptor for ClientAuthInterceptor {
    /// Intercept the outgoing request and add the Authorization header with
    /// the Bearer token.
    ///
    /// # Arguments
    /// * `request` (`Request<()>`) - The outgoing gRPC request.
    ///
    /// # Errors
    /// * `Status` - If the token is invalid, returns an unauthenticated
    ///   status.
    ///
    /// # Returns
    /// * `Result<Request<()>, Status>` - The modified request with the
    ///   Authorization header if successful, or an error status if the token
    ///   is invalid.
    fn call(
        &mut self,
        mut request: Request<()>,
    ) -> Result<Request<()>, Status> {
        let value: Authorization<Bearer> =
            Authorization::bearer(&self.config.token)
                .map_err(|_| Errors::InvalidToken)?;

        let metadata_value: MetadataValue<Ascii> =
            MetadataValue::try_from(value.token())
                .map_err(|_| Errors::InvalidToken)?;

        request.metadata_mut().insert(AUTHORIZATION.as_str(), metadata_value);

        Ok(request)
    }
}
