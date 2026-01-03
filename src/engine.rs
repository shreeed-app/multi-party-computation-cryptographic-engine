//!! MPC Signer Engine API

use crate::auth::session::identifier::SessionId;
use crate::messages::error::Error;

/// Public engine interface exposed to the IPC layer.
pub trait EngineApi: Send + Sync + 'static {
    /// Start a new MPC signing session.
    ///
    /// # Arguments
    /// * `key_id` (`&str`) - Identifier of the key to use for signing.
    /// * `algorithm` (`&str`) - Signing algorithm.
    /// * `threshold` (`u32`) - Minimum number of participants required.
    /// * `participants` (`u32`) - Total number of participants.
    /// * `message` (`&[u8]`) - Message to be signed.
    ///
    /// # Errors
    /// * `Error` - Returns an error if session creation fails.
    ///
    /// # Returns
    /// * `SessionId` - Identifier of the newly created session.
    fn start_session(
        &self,
        key_id: &str,
        algorithm: &str,
        threshold: u32,
        participants: u32,
        message: &[u8],
    ) -> Result<SessionId, Error>;

    /// Submit a round message for an existing MPC session.
    ///
    /// # Arguments
    /// * `session_id` (`&str`) - Identifier of the session.
    /// * `round` (`u32`) - Round number.
    /// * `payload` (`&[u8]`) - Round message payload.
    ///
    /// # Errors
    /// * `Error` - Returns an error if submission fails.
    ///
    /// # Returns
    /// * `(Vec<u8>, bool)` - Tuple containing the response payload and
    ///   a boolean indicating if the session is finalized.
    fn submit_round(
        &self,
        session_id: &str,
        round: u32,
        payload: &[u8],
    ) -> Result<(Vec<u8>, bool), Error>;

    /// Finalize an MPC signing session.
    ///
    /// # Arguments
    /// * `session_id` (`&str`) - Identifier of the session.
    ///
    /// # Errors
    /// * `Error` - Returns an error if finalization fails.
    ///
    /// # Returns
    /// * `Vec<u8>` - The final signature.
    fn finalize_session(&self, session_id: &str) -> Result<Vec<u8>, Error>;

    /// Abort an MPC signing session.
    ///
    /// # Arguments
    /// * `session_id` (`&str`) - Identifier of the session.
    ///
    /// # Errors
    /// * `Error` - Returns an error if abortion fails.
    ///
    /// # Returns
    /// * `()` - Returns unit on success.
    fn abort_session(&self, session_id: &str) -> Result<(), Error>;
}
