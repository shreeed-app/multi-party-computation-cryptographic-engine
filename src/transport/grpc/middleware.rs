//! Middleware for gRPC requests in the authentication IPC module.

use tonic::Request;

use crate::auth::{context::IdentityContext, identity::Identity};

/// Injects an Identity into the request extensions.
///
/// # Arguments
/// * `request` (`Request<T>`) - The gRPC request to inject the identity into.
/// * `identity` (`Identity`) - The identity to inject.
///
/// # Returns
/// * `Request<T>` - The modified request with the identity injected.
pub fn inject_identity<T>(
    mut request: Request<T>,
    identity: Identity,
) -> Request<T> {
    request.extensions_mut().insert(IdentityContext(identity));
    request
}
