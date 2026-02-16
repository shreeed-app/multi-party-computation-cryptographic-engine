//! gRPC error conversions.

use strum::ParseError;
use tonic::{Code, Status};

use crate::transport::error::Error;

/// Convert canonical errors into gRPC statuses. This mapping defines how
/// errors are exposed over gRPC, without redefining error messages.
impl From<Error> for Status {
    /// Map an `Error` into a gRPC `Status`.
    ///
    /// # Arguments
    /// * `error` (`Error`) - Canonical error to convert.
    ///
    /// # Returns
    /// * `Status` - Corresponding gRPC status.
    fn from(error: Error) -> Self {
        let code: Code = match error {
            Error::InvalidArgument(_) => Code::InvalidArgument,

            Error::MissingAuthorization
            | Error::Unauthorized
            | Error::InvalidAuthorizationEncoding
            | Error::InvalidToken => Code::Unauthenticated,

            Error::SessionNotFound(_) | Error::KeyNotFound => Code::NotFound,

            Error::SessionStateInitialized(_)
            | Error::SessionStateInProgress(_, _)
            | Error::SessionStateFinalized
            | Error::SessionStateNotFinalized
            | Error::InvalidKeyShare
            | Error::InvalidState(_)
            | Error::InvalidRound(_)
            | Error::InvalidParticipant
            | Error::InvalidThreshold
            | Error::InvalidProtocolInit
            | Error::InvalidMessage => Code::FailedPrecondition,

            Error::UnsupportedAlgorithm(_) => Code::Unimplemented,

            Error::Aborted => Code::Aborted,

            Error::Internal(_)
            | Error::Generic(_)
            | Error::FailedToSign
            | Error::InvalidSignature
            | Error::VaultTokenMissing
            | Error::VaultConfigError
            | Error::VaultError
            | Error::LiveLockAcquireError
            | Error::ConfigError(_) => Code::Internal,
        };

        Status::new(code, error.to_string())
    }
}

impl From<ParseError> for Error {
    /// Map a `strum::ParseError` into an `Error::InvalidArgument`.
    ///
    /// # Arguments
    /// * `error` (`ParseError`) - The parse error to convert.
    ///
    /// # Returns
    /// * `Error` - The corresponding `Error::InvalidArgument`.
    fn from(error: ParseError) -> Self {
        Error::InvalidArgument(error.to_string())
    }
}
