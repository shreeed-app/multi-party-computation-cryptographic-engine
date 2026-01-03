//! Tests for the authentication module.
use tonic::Request;

use crate::auth::ipc::auth::{AuthProvider, TokenAuth};
use crate::messages::error::Error;

const EXPECTED_TOKEN: &str = "secret";
const UNEXPECTED_TOKEN: &str = "not_secret";

/// Tests that the TokenAuth successfully authenticates a request with the
/// correct token.
///
/// # Panics
/// Panics if the authentication fails.
#[test]
pub fn accepts_valid_token() {
    let auth: TokenAuth = TokenAuth::new(EXPECTED_TOKEN.into());

    let mut request: Request<()> = Request::new(());
    request
        .metadata_mut()
        .insert("authorization", EXPECTED_TOKEN.parse().unwrap());

    assert!(auth.authenticate(&request).is_ok());
}

/// Rejects requests with an invalid token.
///
/// # Panics
/// Panics if the authentication does not return an `InvalidToken` error.
#[test]
pub fn rejects_invalid_token() {
    let auth: TokenAuth = TokenAuth::new(EXPECTED_TOKEN.into());

    let mut request: Request<()> = Request::new(());
    request
        .metadata_mut()
        .insert("authorization", UNEXPECTED_TOKEN.parse().unwrap());
    assert_eq!(auth.authenticate(&request).unwrap_err(), Error::InvalidToken);
}
