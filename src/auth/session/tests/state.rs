//! Tests for session state machine.
use crate::auth::session::state::SessionState;
use crate::messages::error::Error;

/// Tests that the state machine enforces round order correctly.
///
/// # Panics
/// Panics if the state machine does not enforce round order correctly.
#[test]
pub fn enforces_round_order() {
    let mut state: SessionState = SessionState::Initialized;
    assert!(state.validate_round(0).is_ok());

    state.advance_round(0);
    assert!(state.validate_round(1).is_ok());

    state.advance_round(1);

    let error: Error = match state.validate_round(1) {
        Ok(_) => panic!("Expected error for duplicate round."),
        Err(error) => error,
    };

    assert_eq!(error, Error::SessionStateInProgress(2, 1));
}
