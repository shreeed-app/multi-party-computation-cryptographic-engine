//! Engine implementation.

use std::{
    collections::HashMap,
    sync::{
        Mutex,
        MutexGuard,
        RwLock,
        RwLockWriteGuard,
    },
    time::Duration,
};

use crate::{
    auth::session::{
        identifier::SessionId,
        state::SessionState,
        store::SessionStore,
    },
    engine::{
        api::EngineApi,
        entry::SessionEntry,
    },
    messages::error::Error,
    protocols::{
        factory::ProtocolFactory,
        signing::SigningProtocol,
        types::{
            ProtocolInit,
            RoundMessage,
            Signature,
        },
    },
};

/// Engine implementation.
pub struct Engine {
    /// Session store for managing session life cycles.
    pub sessions: SessionStore,
    /// Live sessions held in memory.
    pub live: RwLock<HashMap<SessionId, SessionEntry>>,
}

impl Engine {
    /// Create a new engine instance.
    ///
    /// # Arguments
    /// * `ttl` (`Duration`) - Session time-to-live.
    ///
    /// # Returns
    /// * `Self` - New engine instance.
    pub fn new(ttl: Duration) -> Self {
        Self {
            sessions: SessionStore::new(ttl),
            live: RwLock::new(HashMap::new()),
        }
    }

    /// Best-effort removal of a live session entry.
    ///
    /// # Arguments
    /// * `session_id` (`SessionId`) - Session identifier.
    ///
    /// # Returns
    /// * `()` - Nothing.
    fn remove_live(&self, session_id: SessionId) {
        if let Ok(mut live) = self.live.write() {
            live.remove(&session_id);
        }
    }
}

impl EngineApi for Engine {
    /// Start a new signing session.
    ///
    /// # Arguments
    /// * `init` (`ProtocolInit`) - Protocol initialization parameters.
    ///
    /// # Errors
    /// * `Error` - If starting the session fails.
    ///
    /// # Returns
    /// * `(SessionId, RoundMessage)` - New session ID and first round message.
    fn start_session(
        &self,
        init: ProtocolInit,
    ) -> Result<(SessionId, RoundMessage), Error> {
        let session_id: SessionId = self.sessions.create();

        let mut protocol: Box<dyn SigningProtocol> =
            match ProtocolFactory::create(init) {
                Ok(protocol) => protocol,
                Err(err) => {
                    self.sessions.remove(session_id);
                    return Err(err);
                },
            };

        let round: RoundMessage = match protocol.next_round() {
            Ok(Some(message)) => message,
            Ok(None) => {
                self.sessions.remove(session_id);
                return Err(Error::InvalidState(session_id.to_string()));
            },
            Err(error) => {
                self.sessions.remove(session_id);
                return Err(error);
            },
        };

        match self.sessions.with_session(
            session_id,
            |state: &mut SessionState| {
                state.advance_round(0);
                Ok(())
            },
        ) {
            Ok(_) => {},
            Err(error) => {
                self.sessions.remove(session_id);
                return Err(error);
            },
        }

        let entry: SessionEntry = SessionEntry {
            state: SessionState::Initialized,
            protocol: Mutex::new(protocol),
        };

        match self.live.write() {
            Ok(mut live) => live,
            Err(_) => {
                self.sessions.remove(session_id);
                return Err(Error::LiveLockAcquireError);
            },
        }
        .insert(session_id, entry);

        Ok((session_id, round))
    }

    /// Submit a round message.
    ///
    /// # Arguments
    /// * `session_id` (`SessionId`) - Session identifier.
    ///
    /// # Errors
    /// * `Error` - If submitting the round fails.
    ///
    /// # Returns
    /// * `RoundMessage` - Response round message.
    fn submit_round(
        &self,
        session_id: SessionId,
        message: RoundMessage,
    ) -> Result<RoundMessage, Error> {
        let result: Result<RoundMessage, Error> = self.sessions.with_session(
            session_id,
            |state: &mut SessionState| {
                match state.validate_round(message.round) {
                    Ok(_) => {},
                    Err(error) => return Err(error),
                }

                let mut live: RwLockWriteGuard<
                    '_,
                    HashMap<SessionId, SessionEntry>,
                > = match self.live.write() {
                    Ok(guard) => guard,
                    Err(_) => {
                        return Err(Error::LiveLockAcquireError);
                    },
                };

                let entry: &mut SessionEntry = match live.get_mut(&session_id)
                {
                    Some(entry) => entry,
                    None => {
                        return Err(Error::SessionNotFound(
                            session_id.to_string(),
                        ));
                    },
                };

                let mut protocol: MutexGuard<
                    '_,
                    Box<dyn SigningProtocol + 'static>,
                > = match entry.protocol.lock() {
                    Ok(guard) => guard,
                    Err(_) => return Err(Error::LiveLockAcquireError),
                };

                let response: RoundMessage =
                    match protocol.handle_message(message) {
                        Ok(Some(message)) => message,
                        Ok(None) => {
                            return Err(Error::InvalidState(
                                session_id.to_string(),
                            ));
                        },
                        Err(_) => {
                            return Err(Error::InvalidState(
                                session_id.to_string(),
                            ));
                        },
                    };

                state.advance_round(response.round);
                Ok(response)
            },
        );

        if matches!(result, Err(Error::SessionNotFound(_))) {
            self.remove_live(session_id);
        }

        result
    }

    /// Finalize a session.
    ///
    /// # Arguments
    /// * `session_id` (`SessionId`) - Session identifier.
    ///
    /// # Errors
    /// * `Error` - If finalization fails.
    ///
    /// # Returns
    /// * `Signature` - Final signature.
    fn finalize(&self, session_id: SessionId) -> Result<Signature, Error> {
        let result: Result<Signature, Error> = self.sessions.with_session(
            session_id,
            |state: &mut SessionState| {
                match state.finalize() {
                    Ok(_) => {},
                    Err(error) => return Err(error),
                }

                let entry: SessionEntry = match match self.live.write() {
                    Ok(mut live) => live,
                    Err(_) => return Err(Error::LiveLockAcquireError),
                }
                .remove(&session_id)
                {
                    Some(entry) => entry,
                    None => {
                        return Err(Error::SessionNotFound(
                            session_id.to_string(),
                        ));
                    },
                };

                let protocol: Box<dyn SigningProtocol> =
                    match entry.protocol.into_inner() {
                        Ok(protocol) => protocol,
                        Err(_) => return Err(Error::LiveLockAcquireError),
                    };

                protocol.finalize()
            },
        );

        if matches!(result, Err(Error::SessionNotFound(_))) {
            self.remove_live(session_id);
        }

        result
    }

    /// Abort a session.
    ///
    /// # Arguments
    /// * `session_id` (`SessionId`) - Session identifier.
    ///
    /// # Errors
    /// * `Error` - If aborting the session fails.
    ///
    /// # Returns
    /// * `()` - Nothing.
    fn abort(&self, session_id: SessionId) -> Result<(), Error> {
        let result: Result<(), Error> = self.sessions.with_session(
            session_id,
            |state: &mut SessionState| {
                if let Ok(mut live) = self.live.write()
                    && let Some(entry) = live.get_mut(&session_id)
                    && let Ok(mut protocol) = entry.protocol.lock()
                {
                    protocol.abort();
                }

                state.abort();
                Ok(())
            },
        );

        self.remove_live(session_id);
        result
    }
}
