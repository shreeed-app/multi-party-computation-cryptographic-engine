//! Controller-side engine implementing EngineApi.
//!
//! Unlike the peer engine, the controller executes the full
//! distributed protocol inside `start_session` and stores
//! the final result in-memory until `finalize` is called.

use std::{collections::HashMap, sync::RwLock};

use async_trait::async_trait;

use crate::{
    auth::session::identifier::SessionId,
    protocols::{
        factory::ProtocolFactory,
        protocol::Protocol,
        types::{ProtocolInit, ProtocolOutput, RoundMessage},
    },
    service::api::EngineApi,
    transport::error::Error,
};

/// Controller engine.
pub struct ControllerEngine {
    /// Completed session outputs.
    /// Since controller executes fully in start_session,
    /// we only need to store the result until finalize.
    outputs: RwLock<HashMap<SessionId, ProtocolOutput>>,
}

impl Default for ControllerEngine {
    fn default() -> Self {
        Self { outputs: RwLock::new(HashMap::new()) }
    }
}

#[async_trait]
impl EngineApi for ControllerEngine {
    /// Start a distributed session.
    ///
    /// # Arguments
    /// * `init` (`ProtocolInit`) - Protocol initialization context.
    /// # Errors
    /// * `Error::UnsupportedAlgorithm` if the algorithm is not supported.
    /// * `Error::InvalidProtocolInit` if the protocol initialization context
    ///   is invalid.
    /// * `Error::LiveLockAcquireError` if the engine fails to acquire lock on
    ///  internal storage.
    ///
    /// # Returns
    /// * `(SessionId, RoundMessage)` - Session identifier and initial round
    ///   message (empty for controller since it executes synchronously).
    async fn start_session(
        &self,
        init: ProtocolInit,
    ) -> Result<(SessionId, RoundMessage), Error> {
        let mut protocol: Box<dyn Protocol> = ProtocolFactory::create(init)?;

        // Execute full orchestration
        protocol.next_round().await?;

        let output: ProtocolOutput = protocol.finalize().await?;
        let session_id: SessionId = SessionId::new();

        self.outputs
            .write()
            .map_err(|_| Error::LiveLockAcquireError)?
            .insert(session_id, output);

        // Controller does not use RoundMessage.
        Ok((
            session_id,
            RoundMessage { round: 0, from: None, to: None, payload: vec![] },
        ))
    }

    /// Controller does not support incremental rounds.
    ///
    /// # Arguments
    /// * `_session_id` (`SessionId`) - Target session.
    /// * `_message` (`RoundMessage`) - Incoming round message.
    /// # Errors
    /// * `Error::UnsupportedAlgorithm` since controller runs synchronously and
    ///   does not support incremental rounds.
    async fn submit_round(
        &self,
        _session_id: SessionId,
        _message: RoundMessage,
    ) -> Result<RoundMessage, Error> {
        Err(Error::UnsupportedAlgorithm(
            "Controller does not support incremental rounds.".into(),
        ))
    }

    /// Return stored output.
    ///
    /// # Arguments
    /// * `session_id` (`SessionId`) - Target session.
    /// # Errors
    ///
    /// * `Error::SessionNotFound` if session ID does not exist.
    /// * `Error::LiveLockAcquireError` if the engine fails to acquire lock on
    ///   internal storage.
    /// * `Error::InvalidProtocolOutput` if the stored output is invalid.
    ///
    /// # Returns
    /// * `ProtocolOutput` - Final protocol output stored from start_session.
    async fn finalize(
        &self,
        session_id: SessionId,
    ) -> Result<ProtocolOutput, Error> {
        self.outputs
            .write()
            .map_err(|_| Error::LiveLockAcquireError)?
            .remove(&session_id)
            .ok_or_else(|| Error::SessionNotFound(session_id.to_string()))
    }

    /// Abort removes stored output.
    ///
    /// # Arguments
    /// * `session_id` (`SessionId`) - Target session.
    ///
    /// # Errors
    /// * `Error::SessionNotFound` if session ID does not exist.
    /// * `Error::LiveLockAcquireError` if the engine fails to acquire lock on
    ///   internal storage.
    ///
    /// # Returns
    /// * `()` - Unit.
    async fn abort(&self, session_id: SessionId) -> Result<(), Error> {
        self.outputs
            .write()
            .map_err(|_| Error::LiveLockAcquireError)?
            .remove(&session_id);

        Ok(())
    }
}
