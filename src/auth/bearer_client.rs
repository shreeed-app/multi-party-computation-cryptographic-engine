//! Authentication components ensuring authentication between controller and
//! nodes.

use headers::{
    Authorization,
    Header,
    authorization::{Bearer, InvalidBearerToken},
};
use http::{HeaderValue, header::AUTHORIZATION};
use tonic::{
    Request,
    Status,
    metadata::{Ascii, MetadataValue, errors::InvalidMetadataValueBytes},
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
        let auth: Authorization<Bearer> = Authorization::bearer(
            &self.config.token,
        )
        .map_err(|error: InvalidBearerToken| {
            Errors::InvalidToken(format!(
                "Failed to create Bearer authorization: {}",
                error
            ))
        })?;

        // Encode the Authorization header value.
        let mut values: Vec<HeaderValue> = Vec::new();
        auth.encode(&mut values);

        // Take the first header value (there should only be one) and convert
        // it to a MetadataValue for gRPC metadata.
        let header_value: HeaderValue =
            values.into_iter().next().ok_or(Errors::InvalidToken(
                "Failed to extract Authorization header value.".into(),
            ))?;

        // Convert the header value to a MetadataValue for gRPC metadata.
        let metadata_value: MetadataValue<Ascii> = MetadataValue::try_from(
            header_value.as_bytes(),
        )
        .map_err(|error: InvalidMetadataValueBytes| {
            Errors::InvalidToken(format!(
                "Failed to convert Authorization header value to \
                MetadataValue, got error: {}",
                error
            ))
        })?;

        request.metadata_mut().insert(AUTHORIZATION.as_str(), metadata_value);

        Ok(request)
    }
}
