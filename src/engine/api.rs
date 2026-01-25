//! Signer engine API definitions.

use crate::{
    auth::session::identifier::SessionId,
    messages::error::Error,
    protocols::types::{
        ProtocolInit,
        RoundMessage,
        Signature,
    },
};

/// Public engine interface exposed to the IPC layer.
pub trait EngineApi: Send + Sync + 'static {
    /// Start a new signing session.
    ///
    /// # Arguments
    /// * `init` (`ProtocolInit`) - Fully validated protocol initialization
    ///   context.
    ///
    /// # Errors
    /// * `Error` - If session creation or protocol initialization fails.
    ///
    /// # Returns
    /// * `(SessionId, RoundMessage)` - Session identifier and round 0 message.
    fn start_session(
        &self,
        init: ProtocolInit,
    ) -> Result<(SessionId, RoundMessage), Error>;

    /// Submit a round message for an existing session.
    ///
    /// # Arguments
    /// * `session_id` (`SessionId`) - Target session.
    /// * `message` (`RoundMessage`) - Incoming round message.
    ///
    /// # Errors
    /// * `Error` - If session does not exist, round is invalid, or protocol
    ///   fails.
    ///
    /// # Returns
    /// * `RoundMessage` - Next outgoing round message.
    fn submit_round(
        &self,
        session_id: SessionId,
        message: RoundMessage,
    ) -> Result<RoundMessage, Error>;

    /// Finalize a signing session.
    ///
    /// # Arguments
    /// * `session_id` (`SessionId`) - Target session.
    ///
    /// # Errors
    /// * `Error` - If session is not in a final state.
    ///
    /// # Returns
    /// * `Signature` - Final signature output.
    fn finalize(&self, session_id: SessionId) -> Result<Signature, Error>;

    /// Abort a signing session.
    ///
    /// # Arguments
    /// * `session_id` (`SessionId`) - Target session.
    ///
    /// # Errors
    /// * `Error` - If session does not exist.
    ///
    /// # Returns
    /// * `()` - Unit.
    fn abort(&self, session_id: SessionId) -> Result<(), Error>;
}
