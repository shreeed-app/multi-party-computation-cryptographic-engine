//! Canonical error definitions for the MPC signer engine.

use thiserror::Error;

/// Canonical error type for the MPC signer engine.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum Error {
    /// Missing authorization.
    #[error("Missing authorization.")]
    MissingAuthorization,

    /// Invalid authorization encoding.
    #[error("Invalid authorization encoding.")]
    InvalidAuthorizationEncoding,

    /// Invalid authorization token.
    #[error("Invalid authorization token.")]
    InvalidToken,

    /// Unauthorized access.
    #[error("Unauthorized.")]
    Unauthorized,

    /// Session not found.
    #[error("Session not found.")]
    SessionNotFound,

    /// Invalid session state.
    #[error("Invalid session state.")]
    InvalidSessionState,

    /// Policy violation.
    #[error("Policy violation.")]
    PolicyViolation,

    /// Unsupported algorithm.
    #[error("Unsupported algorithm.")]
    UnsupportedAlgorithm,

    /// Internal error.
    #[error("Internal error.")]
    Internal,
}
