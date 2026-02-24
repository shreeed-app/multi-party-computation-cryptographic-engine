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
    #[error("Configuration error. {0}")]
    ConfigError(String),

    /// Unauthorized access: identity lacks necessary permissions.
    #[error("Unauthorized access.")]
    Unauthorized,

    /// Missing authorization: missing "authorization" metadata.
    #[error("Missing authorization. {0}")]
    MissingAuthorization(String),

    /// Invalid authorization encoding: failed to parse authorization header.
    #[error("Invalid authorization encoding.")]
    InvalidAuthorizationEncoding,

    /// Invalid authorization token: token does not match expected value.
    #[error("Invalid authorization token. {0}")]
    InvalidToken(String),

    /// Session not found: no session exists for the given ID.
    #[error("Invalid session ID. {0}")]
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
    #[error("Unsupported algorithm. {0}")]
    UnsupportedAlgorithm(String),

    /// Invalid protocol initialization parameters.
    #[error("Invalid protocol initialization parameters. {0}")]
    InvalidProtocolInit(String),

    /// Invalid key share: provided key share is malformed.
    #[error("Invalid key share. {0}")]
    InvalidKeyShare(String),

    /// Invalid protocol state: operation not allowed in current protocol
    /// state.
    #[error("Invalid protocol state. {0}")]
    InvalidState(String),

    /// Invalid round number: round number is out of expected range.
    #[error("Invalid round number. {0}")]
    InvalidRound(u32),

    /// Invalid message: message is malformed or unexpected.
    #[error("Invalid message. {0}")]
    InvalidMessage(String),

    /// Invalid signature: produced signature is malformed.
    #[error("Invalid signature. {0}")]
    InvalidSignature(String),

    /// Invalid participant: participant identifier is not recognized.
    #[error("Invalid participant. {0}")]
    InvalidParticipant(String),

    /// Invalid argument: the provided argument is invalid.
    #[error("Invalid argument. {0}")]
    InvalidArgument(String),

    /// Failed to sign: protocol failed to produce a valid signature.
    #[error("Failed to sign. {0}")]
    FailedToSign(String),

    /// Invalid threshold: threshold value is invalid.
    #[error("Invalid threshold, expected {0} got {1}.")]
    InvalidThreshold(u32, u32),

    /// Vault configuration error: invalid vault configuration.
    #[error("Vault configuration error. {0}")]
    VaultConfigError(String),

    /// Vault error: error occurred while interacting with the vault.
    #[error("Vault error. {0}")]
    VaultError(String),

    /// Protocol aborted: the protocol has been aborted.
    #[error("Protocol aborted. {0}")]
    Aborted(String),

    /// Internal error: an unexpected internal error occurred.
    #[error("Internal error. {0}")]
    Internal(String),

    /// Generic error: a generic error with a message.
    #[error("Error. {0}")]
    Generic(String),

    /// Failed to acquire live lock.
    #[error("Failed to acquire live lock. {0}")]
    LiveLockAcquireError(String),
}
