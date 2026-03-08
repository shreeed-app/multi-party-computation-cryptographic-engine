//! Protocol trait definitions.

use async_trait::async_trait;

use crate::{
    proto::signer::v1::RoundMessage,
    protocols::{
        algorithm::Algorithm,
        types::{ProtocolOutput, Round},
    },
    transport::errors::Errors,
};

/// Trait implemented by all protocols. Each protocol instance corresponds
/// to a single session.
#[async_trait]
pub trait Protocol: Send + Sync {
    /// Return the algorithm identifier.
    ///
    /// # Returns
    /// * `Algorithm` - Algorithm identifier.
    fn algorithm(&self) -> Algorithm;

    /// Return the threshold required for operation.
    ///
    /// # Returns
    /// * `u32` - Threshold number of participants.
    fn threshold(&self) -> u32;

    /// Return the total number of participants.
    ///
    /// # Returns
    /// * `u32` - Total number of participants.
    fn participants(&self) -> u32;

    /// Return the current round number.
    ///
    /// # Returns
    /// * `Round` - Current round number.
    fn current_round(&self) -> Round;

    /// Process an incoming round message and advance the protocol state.
    ///
    /// # Arguments
    /// * `message` (`RoundMessage`) - Message received from another node.
    ///
    /// # Returns
    /// * `Option<RoundMessage>` - Message to broadcast for the next round.
    ///
    /// # Errors
    /// * `Errors` - If message processing fails.
    async fn handle_message(
        &mut self,
        message: RoundMessage,
    ) -> Result<Option<RoundMessage>, Errors>;

    /// Advance the protocol without receiving a message.
    /// Used to initiate round 0 or generate local contributions.
    ///
    /// # Returns
    /// * `Option<RoundMessage>` - Message to broadcast for the next round.
    ///
    /// # Errors
    /// * `Errors` - If advancing the round fails.
    async fn next_round(&mut self) -> Result<Option<RoundMessage>, Errors>;

    /// Finalize the protocol and return the result.
    /// This can only be called once the protocol is complete.
    ///
    /// # Returns
    /// * `ProtocolOutput` - Final output of the protocol.
    ///
    /// # Errors
    /// * `Errors` - If finalization fails.
    async fn finalize(&mut self) -> Result<ProtocolOutput, Errors>;

    /// Check if the protocol has completed all rounds and is ready for
    /// finalization. This method can be used to determine if the protocol
    /// is done without attempting to finalize it.
    ///
    /// # Returns
    /// * `bool` - `true` if the protocol is done, `false` otherwise.
    fn is_done(&self) -> bool {
        false
    }

    /// Abort the protocol.
    /// After calling this method, no further operations should be performed.
    ///
    /// # Returns
    /// * `()` - Nothing.
    fn abort(&mut self);
}
