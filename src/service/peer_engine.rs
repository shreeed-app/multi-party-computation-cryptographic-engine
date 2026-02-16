//! Engine implementation.

use std::{
    collections::HashMap,
    sync::{RwLock, RwLockWriteGuard},
    time::Duration,
};

use async_trait::async_trait;

use crate::{
    auth::session::{
        identifier::SessionId,
        state::SessionState,
        store::SessionStore,
    },
    protocols::{
        factory::ProtocolFactory,
        protocol::Protocol,
        types::{ProtocolInit, ProtocolOutput, RoundMessage},
    },
    service::{api::EngineApi, entry::SessionEntry},
    transport::error::Error,
};

/// Engine implementation.
pub struct PeerEngine {
    /// Session store for managing session life cycles.
    pub sessions: SessionStore,
    /// Live sessions held in memory.
    pub live: RwLock<HashMap<SessionId, SessionEntry>>,
}

impl PeerEngine {
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

#[async_trait]
impl EngineApi for PeerEngine {
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
    async fn start_session(
        &self,
        init: ProtocolInit,
    ) -> Result<(SessionId, RoundMessage), Error> {
        let session_id: SessionId = self.sessions.create();

        let mut protocol: Box<dyn Protocol> = ProtocolFactory::create(init)
            .inspect_err(|_| {
                self.sessions.remove(session_id);
            })?;

        let round: RoundMessage =
            protocol.next_round().await?.ok_or_else(|| {
                self.sessions.remove(session_id);
                Error::InvalidState(session_id.to_string())
            })?;

        self.sessions.with_session(
            session_id,
            |state: &mut SessionState| {
                state.advance_round(0);
                Ok(())
            },
        )?;

        let entry: SessionEntry = SessionEntry {
            state: SessionState::Initialized,
            protocol: Some(protocol),
        };

        self.live
            .write()
            .map_err(|_| Error::LiveLockAcquireError)?
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
    async fn submit_round(
        &self,
        session_id: SessionId,
        message: RoundMessage,
    ) -> Result<RoundMessage, Error> {
        self.sessions
            .with_session(session_id, |state: &mut SessionState| {
                state.validate_round(message.round)
            })?;

        let mut protocol: Box<dyn Protocol> = {
            let mut live: RwLockWriteGuard<
                '_,
                HashMap<SessionId, SessionEntry>,
            > = self.live.write().map_err(|_| Error::LiveLockAcquireError)?;

            let entry: &mut SessionEntry =
                live.get_mut(&session_id).ok_or_else(|| {
                    Error::SessionNotFound(session_id.to_string())
                })?;

            entry.protocol.take().ok_or_else(|| {
                Error::InvalidState("Protocol missing.".into())
            })?
        };

        let response: RoundMessage =
            protocol
                .handle_message(message)
                .await?
                .ok_or_else(|| Error::InvalidState(session_id.to_string()))?;

        let mut live: RwLockWriteGuard<'_, HashMap<SessionId, SessionEntry>> =
            self.live.write().map_err(|_| Error::LiveLockAcquireError)?;

        let entry: &mut SessionEntry = live
            .get_mut(&session_id)
            .ok_or_else(|| Error::SessionNotFound(session_id.to_string()))?;

        entry.protocol = Some(protocol);

        self.sessions.with_session(
            session_id,
            |state: &mut SessionState| {
                state.advance_round(response.round);
                Ok(())
            },
        )?;

        Ok(response)
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
    /// * `ProtocolOutput` - Final signature.
    async fn finalize(
        &self,
        session_id: SessionId,
    ) -> Result<ProtocolOutput, Error> {
        self.sessions
            .with_session(session_id, |state: &mut SessionState| {
                state.finalize()
            })?;

        let mut protocol: Box<dyn Protocol> = {
            let mut live: RwLockWriteGuard<
                '_,
                HashMap<SessionId, SessionEntry>,
            > = self.live.write().map_err(|_| Error::LiveLockAcquireError)?;

            let entry: SessionEntry =
                live.remove(&session_id).ok_or_else(|| {
                    Error::SessionNotFound(session_id.to_string())
                })?;

            entry.protocol.ok_or_else(|| {
                Error::InvalidState("Protocol missing.".into())
            })?
        };

        let output: ProtocolOutput = protocol.finalize().await?;

        Ok(output)
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
    async fn abort(&self, session_id: SessionId) -> Result<(), Error> {
        self.sessions.with_session(
            session_id,
            |state: &mut SessionState| {
                state.abort();
                Ok(())
            },
        )?;

        if let Ok(mut live) = self.live.write()
            && let Some(entry) = live.get_mut(&session_id)
            && let Some(mut protocol) = entry.protocol.take()
        {
            protocol.abort();
        }

        self.remove_live(session_id);

        Ok(())
    }
}
