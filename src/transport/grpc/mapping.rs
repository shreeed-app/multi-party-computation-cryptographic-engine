//! gRPC error conversions.

use tonic::{Code, Status, transport::Error};

use crate::transport::errors::Errors;

/// Convert canonical errors into gRPC statuses. This mapping defines how
/// errors are exposed over gRPC, without redefining error messages.
impl From<Errors> for Status {
    /// Map an `Errors` into a gRPC `Status`.
    ///
    /// # Arguments
    /// * `error` (`Errors`) - Canonical error to convert.
    ///
    /// # Returns
    /// * `Status` - Corresponding gRPC status.
    fn from(error: Errors) -> Self {
        let code: Code = match error {
            Errors::InvalidArgument(_) => Code::InvalidArgument,

            Errors::MissingAuthorization(_)
            | Errors::Unauthorized
            | Errors::InvalidAuthorizationEncoding
            | Errors::InvalidToken(_) => Code::Unauthenticated,

            Errors::SessionNotFound(_) => Code::NotFound,

            Errors::SessionStateInitialized(_)
            | Errors::SessionStateInProgress(_, _)
            | Errors::SessionStateFinalized
            | Errors::SessionStateNotFinalized
            | Errors::InvalidKeyShare(_)
            | Errors::InvalidState(_)
            | Errors::InvalidRound(_)
            | Errors::InvalidParticipant(_)
            | Errors::InvalidThreshold(_, _)
            | Errors::InvalidProtocolInit(_)
            | Errors::InvalidMessage(_) => Code::FailedPrecondition,

            Errors::UnsupportedAlgorithm(_) => Code::Unimplemented,

            Errors::Aborted(_) => Code::Aborted,

            Errors::Internal(_)
            | Errors::Generic(_)
            | Errors::FailedToSign(_)
            | Errors::InvalidSignature(_)
            | Errors::VaultConfigError(_)
            | Errors::VaultError(_)
            | Errors::LiveLockAcquireError(_)
            | Errors::ConfigError(_) => Code::Internal,
        };

        Status::new(code, error.to_string())
    }
}

impl From<Error> for Errors {
    /// Map a `tonic::transport::Error` into an `Error::Internal`.
    ///
    /// # Arguments
    /// * `error` (`Error`) - The transport error to convert.
    ///
    /// # Returns
    /// * `Error` - The corresponding `Error::Internal`.
    fn from(error: Error) -> Self {
        Errors::Internal(error.to_string())
    }
}
