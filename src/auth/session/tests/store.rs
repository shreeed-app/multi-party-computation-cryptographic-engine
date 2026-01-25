//! Tests for the session store.
use std::{
    thread::sleep,
    time::Duration,
};

use crate::{
    auth::session::{
        identifier::SessionId,
        store::SessionStore,
    },
    messages::error::Error,
};

/// Tests that a session can be created and accessed.
///
/// # Panics
/// Panics if the session cannot be created or accessed.
#[test]
pub fn expires_sessions_after_ttl() {
    let store: SessionStore = SessionStore::new(Duration::from_millis(10));
    let id: SessionId = store.create();

    sleep(Duration::from_millis(20));

    let error: Error = match store.with_session(id, |_| Ok(())) {
        Ok(_) => panic!("Expected session to be expired."),
        Err(error) => error,
    };

    assert_eq!(error, Error::SessionNotFound(id.to_string()));
}
