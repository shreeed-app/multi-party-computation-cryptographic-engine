//! Authentication middleware for the gRPC server.

use std::{future::Future, pin::Pin};

use headers::{Authorization, HeaderMapExt, authorization::Bearer};
use http::Request;
use subtle::ConstantTimeEq;
use tonic::{Status, body::Body};
use tonic_middleware::RequestInterceptor;

use crate::transport::errors::Errors;

/// Authentication interceptor for gRPC requests.
#[derive(Clone)]
pub struct BearerAuthInterceptor {
    /// The expected token for authentication.
    expected_token: String,
}

impl BearerAuthInterceptor {
    /// Create a new `AuthInterceptor` with the given expected token.
    ///
    /// # Arguments
    /// * `expected` (`String`) - The expected token for authentication.
    ///
    /// # Returns
    /// * `AuthInterceptor` - A new instance of `AuthInterceptor`.
    pub fn new(expected: String) -> Self {
        Self { expected_token: expected }
    }
}

impl RequestInterceptor for BearerAuthInterceptor {
    /// Intercept the incoming request and perform authentication.
    ///
    /// # Arguments
    /// * `request` (`Request<Body>`) - The incoming gRPC request.
    ///
    /// # Errors
    /// * `Status` - If authentication fails, returns an unauthenticated
    ///   status.
    ///
    /// # Returns
    /// * `Pin<Box<dyn Future<Output = Result<Request<Body>, Status>> + Send +
    ///   'async_trait>>` - The original request if authentication succeeds.
    fn intercept<'l, 'async_trait>(
        &'l self,
        request: Request<Body>,
    ) -> Pin<
        Box<
            dyn Future<Output = Result<Request<Body>, Status>>
                + Send
                + 'async_trait,
        >,
    >
    where
        'l: 'async_trait,
        Self: 'async_trait,
    {
        let expected: String = self.expected_token.clone();

        Box::pin(async move {
            // Extract the Bearer token from the Authorization header.
            let auth: Authorization<Bearer> = request
                .headers()
                .typed_get()
                .ok_or(Errors::MissingAuthorization)?;

            let token: &str = auth.token();

            // Perform constant-time comparison of the provided token with the
            // expected token.
            if expected.len() != token.len()
                || !bool::from(ConstantTimeEq::ct_eq(
                    expected.as_bytes(),
                    token.as_bytes(),
                ))
            {
                return Err(Errors::InvalidToken.into());
            }

            Ok(request)
        })
    }
}
