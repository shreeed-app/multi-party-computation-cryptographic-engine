//! In-memory session store.

use std::{
    collections::HashMap,
    sync::{
        RwLock,
        RwLockWriteGuard,
    },
    time::{
        Duration,
        Instant,
    },
};

use crate::{
    auth::session::{
        identifier::SessionId,
        state::SessionState,
    },
    messages::error::Error,
};

/// This store is process-local and not persistent.
/// Sessions are automatically expired after a TTL.
pub struct SessionStore {
    /// Mapping of session IDs to session entries.
    pub sessions: RwLock<HashMap<SessionId, SessionEntry>>,
    /// Session time-to-live duration.
    pub ttl: Duration,
}

/// A session entry held in the store.
pub struct SessionEntry {
    /// Current session state.
    pub state: SessionState,
    /// Last updated timestamp for TTL enforcement.
    pub last_updated: Instant,
}

impl SessionStore {
    /// Create a new session store with the given TTL.
    ///
    /// # Arguments
    /// * `ttl` (`Duration`) - Time-to-live for sessions.
    ///
    /// # Returns
    /// * `Self` - A new session store instance.
    pub fn new(ttl: Duration) -> Self {
        Self { sessions: RwLock::new(HashMap::new()), ttl }
    }

    /// Create a new session and return its ID.
    ///
    /// # Returns
    /// * `SessionId` - The identifier of the newly created session.
    pub fn create(&self) -> SessionId {
        let id: SessionId = SessionId::new();

        let entry: SessionEntry = SessionEntry {
            state: SessionState::Initialized,
            last_updated: Instant::now(),
        };

        let mut guard: RwLockWriteGuard<'_, HashMap<SessionId, SessionEntry>> =
            Self::write_guard(&self.sessions);
        guard.insert(id, entry);

        id
    }

    /// Execute a state transition on a session.
    ///
    /// This function guarantees atomic access to the session, TTL enforcement
    /// and valid error propagation.
    ///
    /// # Arguments
    /// * `id` (`SessionId`) - Session identifier.
    /// * `f` (`F`) - Closure that performs the state transition.
    ///
    /// # Errors
    /// * `Error` - Returns an error if the session is not found or the state
    ///   transition fails.
    ///
    /// # Returns
    /// * `R` - Returns the result of the closure on success.
    pub fn with_session<F, R>(&self, id: SessionId, f: F) -> Result<R, Error>
    where
        F: FnOnce(&mut SessionState) -> Result<R, Error>,
    {
        let mut guard: RwLockWriteGuard<'_, HashMap<SessionId, SessionEntry>> =
            Self::write_guard(&self.sessions);

        let entry: &mut SessionEntry = guard
            .get_mut(&id)
            .ok_or(Error::SessionNotFound(id.to_string()))?;

        if entry.last_updated.elapsed() > self.ttl {
            guard.remove(&id);
            return Err(Error::SessionNotFound(id.to_string()));
        }

        let result: R = f(&mut entry.state)?;
        entry.last_updated = Instant::now();

        Ok(result)
    }

    /// Remove a session explicitly.
    ///
    /// # Arguments
    /// * `id` (`SessionId`) - Session identifier to remove.
    ///
    /// # Returns
    /// * `()` - Returns unit on success.
    pub fn remove(&self, id: SessionId) {
        let mut guard: RwLockWriteGuard<'_, HashMap<SessionId, SessionEntry>> =
            Self::write_guard(&self.sessions);
        guard.remove(&id);
    }

    /// Obtain a write lock, recovering from poison if necessary.
    ///
    /// Poisoning is treated as non-fatal in this context, as session
    /// state can be safely recovered.
    ///
    /// # Arguments
    /// * `lock` (`&RwLock<T>`) - RwLock to lock.
    ///
    /// # Returns
    /// * `RwLockWriteGuard<'_, T>` - Write guard.
    pub fn write_guard<T>(lock: &RwLock<T>) -> RwLockWriteGuard<'_, T> {
        match lock.write() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        }
    }
}
