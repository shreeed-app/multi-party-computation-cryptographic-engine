//! gRPC error conversions.

use tonic::{Code, Status};

use crate::messages::error::Error;

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
            Error::MissingAuthorization
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
            | Error::InvalidMessage => Code::FailedPrecondition,

            Error::UnsupportedAlgorithm(_) => Code::Unimplemented,

            Error::ThresholdNotMet(_) => Code::InvalidArgument,
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
