//! gRPC error conversions.

use strum::ParseError;
use tonic::{Code, Status};

use crate::transport::errors::Errors;

/// Convert canonical errors into gRPC statuses. This mapping defines how
/// errors are exposed over gRPC, without redefining error messages.
impl From<Errors> for Status {
    /// Map an `Error` into a gRPC `Status`.
    ///
    /// # Arguments
    /// * `error` (`Error`) - Canonical error to convert.
    ///
    /// # Returns
    /// * `Status` - Corresponding gRPC status.
    fn from(error: Errors) -> Self {
        let code: Code = match error {
            Errors::InvalidArgument(_) => Code::InvalidArgument,

            Errors::MissingAuthorization
            | Errors::Unauthorized
            | Errors::InvalidAuthorizationEncoding
            | Errors::InvalidToken => Code::Unauthenticated,

            Errors::SessionNotFound(_) | Errors::KeyNotFound => Code::NotFound,

            Errors::SessionStateInitialized(_)
            | Errors::SessionStateInProgress(_, _)
            | Errors::SessionStateFinalized
            | Errors::SessionStateNotFinalized
            | Errors::InvalidKeyShare
            | Errors::InvalidState(_)
            | Errors::InvalidRound(_)
            | Errors::InvalidParticipant
            | Errors::InvalidThreshold
            | Errors::InvalidProtocolInit
            | Errors::InvalidMessage => Code::FailedPrecondition,

            Errors::UnsupportedAlgorithm(_) => Code::Unimplemented,

            Errors::Aborted => Code::Aborted,

            Errors::Internal(_)
            | Errors::Generic(_)
            | Errors::FailedToSign
            | Errors::InvalidSignature
            | Errors::VaultTokenMissing
            | Errors::VaultConfigError
            | Errors::VaultError
            | Errors::LiveLockAcquireError
            | Errors::ConfigError(_) => Code::Internal,
        };

        Status::new(code, error.to_string())
    }
}

impl From<ParseError> for Errors {
    /// Map a `strum::ParseError` into an `Error::InvalidArgument`.
    ///
    /// # Arguments
    /// * `error` (`ParseError`) - The parse error to convert.
    ///
    /// # Returns
    /// * `Error` - The corresponding `Error::InvalidArgument`.
    fn from(error: ParseError) -> Self {
        Errors::InvalidArgument(error.to_string())
    }
}
