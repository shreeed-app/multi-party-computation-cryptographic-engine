//! Session state machine.

use crate::transport::errors::Errors;

/// This enforces valid transitions and prevents
/// replay, double-finalization, or invalid round ordering.
#[derive(Debug, Clone)]
pub enum SessionState {
    /// Session initialized, before any round.
    Initialized,

    /// Session is actively processing rounds.
    InProgress {
        /// Last successfully processed round.
        current_round: u32,
    },

    /// Session successfully finalized.
    Finalized,

    /// Session aborted (terminal state).
    Aborted,
}

impl SessionState {
    /// Validate that a given round number can be processed.
    ///
    /// # Arguments
    /// * `round` (`u32`) - Round number to validate.
    ///
    /// # Errors
    /// * `Errors` - Returns `InvalidSessionState` if the round is not valid.
    ///
    /// # Returns
    /// * `()` - Returns unit on success.
    pub fn validate_round(&self, round: u32) -> Result<(), Errors> {
        match self {
            // Initial state: only round 0 is valid, starting the session.
            SessionState::Initialized => {
                if round != 0 {
                    return Err(Errors::SessionStateInitialized(round));
                }
                Ok(())
            },

            // In-progress state: only the next round is valid.
            SessionState::InProgress { current_round } => {
                if round != *current_round + 1 {
                    return Err(Errors::SessionStateInProgress(
                        current_round + 1,
                        round,
                    ));
                }
                Ok(())
            },

            // Terminal states: no further rounds are valid.
            SessionState::Finalized | SessionState::Aborted => {
                Err(Errors::SessionStateFinalized)
            },
        }
    }

    /// Advance the session state after successfully processing a round.
    ///
    /// # Arguments
    /// * `round` (`u32`) - Round number that was just processed.
    ///
    /// # Returns
    /// * `()` - Returns unit on success.
    pub fn advance_round(&mut self, round: u32) {
        *self = SessionState::InProgress { current_round: round };
    }

    /// Mark the session as finalized.
    ///
    /// # Errors
    /// * `Errors` - Returns `InvalidSessionState` if the session is not in a
    ///   state that can be finalized.
    ///
    /// # Returns
    /// * `()` - Returns unit on success.
    pub fn finalize(&mut self) -> Result<(), Errors> {
        match self {
            SessionState::InProgress { .. } | SessionState::Initialized => {
                *self = SessionState::Finalized;
                Ok(())
            },
            _ => Err(Errors::SessionStateNotFinalized),
        }
    }

    /// Abort the session.
    ///
    /// # Returns
    /// * `()` - Returns unit on success.
    pub fn abort(&mut self) {
        *self = SessionState::Aborted;
    }
}
