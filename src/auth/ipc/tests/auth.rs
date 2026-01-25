//! Tests for the authentication module.
use rand::{Rng, distr::Alphanumeric, prelude::ThreadRng};
use tonic::Request;

use crate::{
    auth::ipc::auth::{AuthProvider, TokenAuth},
    messages::error::Error,
};

/// Generates a random alphanumeric token of the specified length.
///
/// # Arguments
////// * `len` (`usize`) - The length of the token to generate.
///
/// # Returns
/// `String` - A randomly generated alphanumeric token.
pub fn random_token(len: usize) -> String {
    let mut random: ThreadRng = rand::rng();
    (&mut random).sample_iter(Alphanumeric).take(len).map(char::from).collect()
}

/// Tests that the TokenAuth successfully authenticates a request with the
/// correct token.
///
/// # Panics
/// Panics if the authentication fails.
#[test]
pub fn accepts_valid_token() {
    let expected_token: String = random_token(32);
    let auth: TokenAuth = TokenAuth::new(expected_token.clone());

    let mut request: Request<()> = Request::new(());
    if let Ok(token) = expected_token.parse() {
        request.metadata_mut().insert("authorization", token);
    }

    assert!(auth.authenticate(&request).is_ok());
}

/// Rejects requests with an invalid token.
///
/// # Panics
/// Panics if the authentication does not return an `InvalidToken` error.
#[test]
pub fn rejects_invalid_token() {
    let expected_token: String = random_token(32);
    let unexpected_token: String = random_token(32);
    let auth: TokenAuth = TokenAuth::new(expected_token);

    let mut request: Request<()> = Request::new(());
    if let Ok(token) = unexpected_token.parse() {
        request.metadata_mut().insert("authorization", token);
    }

    assert_eq!(auth.authenticate(&request).unwrap_err(), Error::InvalidToken);
}
