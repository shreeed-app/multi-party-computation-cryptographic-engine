//! Signing protocol trait definitions.

use crate::{
    messages::error::Error,
    protocols::{
        algorithm::Algorithm,
        types::{Round, RoundMessage, Signature},
    },
};

/// Trait implemented by all protocols. Each protocol instance corresponds
/// to a single signing session.
pub trait SigningProtocol: Send {
    /// Return the algorithm identifier.
    ///
    /// # Returns
    /// * `Algorithm` - Algorithm identifier.
    fn algorithm(&self) -> Algorithm;

    /// Return the threshold required for signing.
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
    /// * `message` (`RoundMessage`) - Message received from another peer.
    ///
    /// # Returns
    /// * `Option<RoundMessage>` - Message to broadcast for the next round.
    ///
    /// # Errors
    /// * `Error` - If message processing fails.
    fn handle_message(
        &mut self,
        message: RoundMessage,
    ) -> Result<Option<RoundMessage>, Error>;

    /// Advance the protocol without receiving a message.
    /// Used to initiate round 0 or generate local contributions.
    ///
    /// # Returns
    /// * `Option<RoundMessage>` - Message to broadcast for the next round.
    ///
    /// # Errors
    /// * `Error` - If advancing the round fails.
    fn next_round(&mut self) -> Result<Option<RoundMessage>, Error>;

    /// Finalize the protocol and return the signature.
    /// This can only be called once the protocol is complete.
    ///
    /// # Returns
    /// * `Signature` - Final signature output.
    ///
    /// # Errors
    /// * `Error` - If finalization fails.
    fn finalize(self: Box<Self>) -> Result<Signature, Error>;

    /// Abort the protocol.
    /// After calling this method, no further operations should be performed.
    ///
    /// # Returns
    /// * `()` - Nothing.
    fn abort(&mut self);
}
