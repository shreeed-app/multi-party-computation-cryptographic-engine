//! Authentication middleware for the gRPC server.

use std::{future::Future, pin::Pin, sync::Arc};

use headers::{Authorization, HeaderMapExt, authorization::Bearer};
use http::Request;
use subtle::ConstantTimeEq;
use tonic::{Status, body::Body};
use tonic_middleware::RequestInterceptor;

use crate::{secrets::secret::Secret, transport::errors::Errors};

/// Authentication interceptor for gRPC requests.
///
/// The expected token is stored inside an `Arc<Secret<String>>` so that:
/// - The underlying bytes are zeroized on drop (via `Secret`).
/// - Cloning the interceptor (required by `tonic_middleware`) increments a
///   reference count rather than duplicating the token in memory.
#[derive(Clone)]
pub struct BearerAuthInterceptor {
    /// The expected token for authentication.
    expected_token: Arc<Secret<String>>,
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
        Self { expected_token: Arc::new(Secret::new(expected)) }
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
        let expected_token: Arc<Secret<String>> =
            Arc::clone(&self.expected_token);

        Box::pin(async move {
            // Extract the Bearer token from the Authorization header.
            let auth: Authorization<Bearer> = request
                .headers()
                .typed_get()
                .ok_or(Errors::MissingAuthorization(
                    "Authorization header is missing.".into(),
                ))?;

            let token: &str = auth.token();

            // Perform constant-time comparison inside `with_ref` to limit the
            // window during which the expected token bytes are accessible.
            // Both the length check and byte comparison run within the same
            // closure — the short-circuit on length is unavoidable with
            // `subtle::ct_eq` (requires equal-length slices) but is acceptable
            // when the token is a fixed-length random credential.
            let token_matches: bool =
                expected_token.with_ref(|expected: &String| {
                    expected.len() == token.len()
                        && bool::from(ConstantTimeEq::ct_eq(
                            expected.as_bytes(),
                            token.as_bytes(),
                        ))
                });

            if !token_matches {
                return Err(Errors::InvalidToken(
                    "Provided token does not match expected token.".into(),
                )
                .into());
            }

            Ok(request)
        })
    }
}
