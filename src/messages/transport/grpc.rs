//! gRPC error conversions.

use tonic::Status;

use crate::messages::error::Error;

/// Convert canonical errors into gRPC statuses.
///
/// This mapping defines how errors are exposed over gRPC,
/// without redefining error messages.
impl From<Error> for Status {
    fn from(error: Error) -> Self {
        match error {
            Error::MissingAuthorization
            | Error::InvalidAuthorizationEncoding
            | Error::InvalidToken
            | Error::Unauthorized => {
                Status::unauthenticated(error.to_string())
            }

            Error::SessionNotFound => Status::not_found(error.to_string()),

            Error::InvalidSessionState => {
                Status::failed_precondition(error.to_string())
            }

            Error::PolicyViolation => {
                Status::permission_denied(error.to_string())
            }

            Error::UnsupportedAlgorithm => {
                Status::invalid_argument(error.to_string())
            }

            Error::Internal => Status::internal(error.to_string()),
        }
    }
}
