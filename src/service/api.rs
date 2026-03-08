//! Service engine definitions.

use async_trait::async_trait;

use crate::{
    auth::session::identifier::SessionIdentifier,
    proto::signer::v1::RoundMessage,
    protocols::types::{ProtocolInit, ProtocolOutput},
    transport::errors::Errors,
};

/// Engine API trait. Implemented by both controller and node engines.
#[async_trait]
pub trait EngineApi: Send + Sync + 'static {
    /// Start a distributed session.
    ///
    /// # Arguments
    /// * `init` (`ProtocolInit`) - Protocol initialization context.
    ///
    /// # Errors
    /// * `Errors` - If any error occurs during session start.
    ///
    /// # Returns
    /// * `(SessionId, Vec<RoundMessage>)` - Session identifier and initial
    ///   round messages (empty for controller since it executes
    ///   synchronously).
    async fn start_session(
        &self,
        init: ProtocolInit,
    ) -> Result<(SessionIdentifier, Vec<RoundMessage>), Errors>;

    /// Submit a round message to the session.
    ///
    /// # Arguments
    /// * `session_id` (`SessionId`) - Identifier of the session to which the
    ///   message belongs.
    /// * `message` (`RoundMessage`) - Message received from another node.
    ///
    /// # Errors
    /// * `Errors` - If any error occurs during message submission.
    ///
    /// # Returns
    /// * `Vec<RoundMessage>` - Messages to broadcast for the next round after
    ///   processing the submitted message.
    async fn submit_round(
        &self,
        session_id: SessionIdentifier,
        message: RoundMessage,
    ) -> Result<Vec<RoundMessage>, Errors>;

    /// Collect round messages from all participants for the current round.
    ///
    /// # Errors
    /// * `Errors` - If any error occurs during message collection.
    ///
    /// # Returns
    /// * `(Vec<RoundMessage>, bool)` - Collected messages for the current
    ///   round and a boolean indicating if the round is complete (i.e., all
    ///   expected messages have been collected).
    async fn collect_round(
        &self,
        session_id: SessionIdentifier,
    ) -> Result<(Vec<RoundMessage>, bool), Errors>;

    /// Collect round messages from all participants for the current round.
    ///
    /// # Arguments
    /// * `session_id` (`SessionId`) - Identifier of the session for which to
    ///   collect messages.
    ///
    /// # Errors
    /// * `Errors` - If any error occurs during message collection.
    ///
    /// # Returns
    /// * `ProtocolOutput` - Collected messages for the current round.
    async fn finalize(
        &self,
        session_id: SessionIdentifier,
    ) -> Result<ProtocolOutput, Errors>;

    /// Abort an ongoing session.
    /// # Arguments
    /// * `session_id` (`SessionId`) - Identifier of the session to abort.
    ///
    /// # Errors
    /// * `Errors` - If any error occurs during session abortion.
    ///
    /// # Returns
    /// * `()` - On successful abortion.
    async fn abort(&self, session_id: SessionIdentifier)
    -> Result<(), Errors>;
}
