//! Signer engine API definitions.

use async_trait::async_trait;

use crate::{
    auth::session::identifier::SessionId,
    protocols::types::{ProtocolInit, ProtocolOutput, RoundMessage},
    transport::error::Error,
};

/// Public engine interface exposed to the IPC layer.
#[async_trait]
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
    async fn start_session(
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
    async fn submit_round(
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
    /// * `ProtocolOutput` - Final signature output.
    async fn finalize(
        &self,
        session_id: SessionId,
    ) -> Result<ProtocolOutput, Error>;

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
    async fn abort(&self, session_id: SessionId) -> Result<(), Error>;
}
