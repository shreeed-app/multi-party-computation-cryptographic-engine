//! Canonical error definitions.

use thiserror::Error;
use tonic::Status;

/// Map a gRPC status to a canonical error type.
///
/// # Arguments
/// * `error` (`Status`) - The gRPC status to map.
///
/// # Returns
/// * `Error` - The corresponding canonical error type.
pub fn map_status(error: Status) -> Errors {
    Errors::Generic(error.to_string())
}

/// Canonical error type.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum Errors {
    /// Configuration error: invalid configuration provided.
    #[error("Configuration error: {0}")]
    ConfigError(String),

    /// Unauthorized access: identity lacks necessary permissions.
    #[error("Unauthorized access.")]
    Unauthorized,

    /// Missing authorization: missing "authorization" metadata.
    #[error("Missing authorization.")]
    MissingAuthorization,

    /// Invalid authorization encoding: failed to parse authorization header.
    #[error("Invalid authorization encoding.")]
    InvalidAuthorizationEncoding,

    /// Invalid authorization token: token does not match expected value.
    #[error("Invalid authorization token.")]
    InvalidToken,

    /// Session not found: no session exists for the given ID.
    #[error("Invalid session ID: {0}")]
    SessionNotFound(String),

    /// Session is not in the initialized state.
    #[error("Invalid session state: expected round 0, got {0}.")]
    SessionStateInitialized(u32),

    /// Session is actively processing rounds.
    #[error("Invalid session state: expected round {0}, got {1}.")]
    SessionStateInProgress(u32, u32),

    /// Session is in a terminal state.
    #[error("Session is in a terminal state.")]
    SessionStateFinalized,

    /// Session cannot be finalized from its current state.
    #[error("Session cannot be finalized from its current state.")]
    SessionStateNotFinalized,

    /// Unsupported algorithm: requested algorithm is not supported.
    #[error("Unsupported algorithm: {0}")]
    UnsupportedAlgorithm(String),

    /// Invalid protocol initialization parameters.
    #[error("Invalid protocol initialization parameters.")]
    InvalidProtocolInit,

    /// Invalid key share: provided key share is malformed.
    #[error("Invalid key share.")]
    InvalidKeyShare,

    /// Invalid protocol state: operation not allowed in current protocol
    /// state.
    #[error("Invalid protocol state: {0}")]
    InvalidState(String),

    /// Invalid round number: round number is out of expected range.
    #[error("Invalid round number: {0}")]
    InvalidRound(u32),

    /// Invalid message: message is malformed or unexpected.
    #[error("Invalid message.")]
    InvalidMessage,

    /// Invalid signature: produced signature is malformed.
    #[error("Invalid signature.")]
    InvalidSignature,

    /// Invalid participant: participant identifier is not recognized.
    #[error("Invalid participant.")]
    InvalidParticipant,

    /// Invalid argument: the provided argument is invalid.
    #[error("Invalid argument: {0}")]
    InvalidArgument(String),

    /// Failed to sign: protocol failed to produce a valid signature.
    #[error("Failed to sign.")]
    FailedToSign,

    /// Invalid threshold: threshold value is invalid.
    #[error("Invalid threshold.")]
    InvalidThreshold,

    /// Vault token missing: no token provided for vault access.
    #[error("Vault token missing.")]
    VaultTokenMissing,

    /// Vault configuration error: invalid vault configuration.
    #[error("Vault configuration error.")]
    VaultConfigError,

    /// Vault error: error occurred while interacting with the vault.
    #[error("Vault error.")]
    VaultError,

    /// Key not found: the requested key does not exist in the vault.
    #[error("Key not found in vault.")]
    KeyNotFound,

    /// Protocol aborted: the protocol has been aborted.
    #[error("Protocol aborted.")]
    Aborted,

    /// Internal error: an unexpected internal error occurred.
    #[error("Internal error: {0}")]
    Internal(String),

    /// Generic error: a generic error with a message.
    #[error("Error: {0}")]
    Generic(String),

    /// Failed to acquire live lock.
    #[error("Failed to acquire live lock.")]
    LiveLockAcquireError,
}
