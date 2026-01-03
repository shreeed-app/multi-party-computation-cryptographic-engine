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
    assert_eq!(
        state.validate_round(1).unwrap_err(),
        Error::InvalidSessionState
    );
}
