//! Controller-side engine implementing EngineApi.

use std::{
    collections::HashMap,
    sync::{PoisonError, RwLock, RwLockWriteGuard},
};

use async_trait::async_trait;
use tracing::instrument;

use crate::{
    auth::session::identifier::SessionIdentifier,
    proto::signer::v1::RoundMessage,
    protocols::{
        factory::ProtocolFactory,
        protocol::Protocol,
        types::{ProtocolInit, ProtocolOutput},
    },
    service::api::EngineApi,
    transport::errors::Errors,
};

/// Controller engine implementation. The controller executes the protocol
/// synchronously and stores the final output in memory for retrieval upon
/// finalization. It does not support incremental rounds since it executes the
/// protocol in a single run.
pub struct ControllerEngine {
    /// Stored outputs for completed sessions.
    outputs: RwLock<HashMap<SessionIdentifier, ProtocolOutput>>,
}

impl Default for ControllerEngine {
    /// Create a new controller engine with default settings.
    ///
    /// # Returns
    /// * `Self` - New controller engine instance.
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
    ///
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
    #[instrument(skip(self, init))]
    async fn start_session(
        &self,
        init: ProtocolInit,
    ) -> Result<(SessionIdentifier, Vec<RoundMessage>), Errors> {
        tracing::debug!(?init, "Starting protocol session.");

        let mut protocol: Box<dyn Protocol> = ProtocolFactory::create(init)?;
        protocol.next_round().await?;

        let output: ProtocolOutput = protocol.finalize().await?;
        let session_id: SessionIdentifier = SessionIdentifier::new();

        self.outputs
            .write()
            .map_err(
                |error: PoisonError<
                    RwLockWriteGuard<
                        '_,
                        HashMap<SessionIdentifier, ProtocolOutput>,
                    >,
                >| {
                    Errors::LiveLockAcquireError(format!(
                        "Failed to acquire live lock: {}.",
                        error
                    ))
                },
            )?
            .insert(session_id, output);

        // Controller does not use RoundMessage.
        Ok((
            session_id,
            vec![RoundMessage {
                round: 0,
                from: None,
                to: None,
                payload: vec![],
            }],
        ))
    }

    /// Controller does not support incremental rounds.
    ///
    /// # Arguments
    /// * `_session_id` (`SessionId`) - Target session.
    /// * `_message` (`RoundMessage`) - Incoming round message.
    ///
    /// # Errors
    /// * `Error::InvalidState` since controller runs synchronously and does
    ///   not support incremental rounds.
    async fn submit_round(
        &self,
        _session_id: SessionIdentifier,
        _message: RoundMessage,
    ) -> Result<Vec<RoundMessage>, Errors> {
        Err(Errors::InvalidState(
            "Controller does not support `submit_round()`.".into(),
        ))
    }

    /// Controller does not support incremental rounds.
    ///
    /// # Arguments
    /// * `_session_id` (`SessionId`) - Target session.
    ///
    /// # Errors
    /// * `Error::InvalidState` since controller runs synchronously and does
    ///   not support incremental rounds.
    async fn collect_round(
        &self,
        _session_id: SessionIdentifier,
    ) -> Result<(Vec<RoundMessage>, bool), Errors> {
        Err(Errors::InvalidState(
            "Controller does not support `collect_round()`.".into(),
        ))
    }

    /// Return stored output.
    ///
    /// # Arguments
    /// * `session_id` (`SessionId`) - Target session.
    /// # Errors
    ///
    /// * `Error::SessionNotFound` if session identifier does not exist.
    /// * `Error::LiveLockAcquireError` if the engine fails to acquire lock on
    ///   internal storage.
    /// * `Error::InvalidProtocolOutput` if the stored output is invalid.
    ///
    /// # Returns
    /// * `ProtocolOutput` - Final protocol output stored from start_session.
    #[instrument(skip(self), fields(session_id = %session_id))]
    async fn finalize(
        &self,
        session_id: SessionIdentifier,
    ) -> Result<ProtocolOutput, Errors> {
        tracing::debug!(?session_id, "Finalizing protocol session.");

        self.outputs
            .write()
            .map_err(
                |error: PoisonError<
                    RwLockWriteGuard<
                        '_,
                        HashMap<SessionIdentifier, ProtocolOutput>,
                    >,
                >| {
                    Errors::LiveLockAcquireError(format!(
                        "Failed to acquire live lock: {}.",
                        error
                    ))
                },
            )?
            .remove(&session_id)
            .ok_or_else(|| Errors::SessionNotFound(session_id.to_string()))
    }

    /// Abort removes stored output.
    ///
    /// # Arguments
    /// * `session_id` (`SessionId`) - Target session.
    ///
    /// # Errors
    /// * `Error::SessionNotFound` if session identifier does not exist.
    /// * `Error::LiveLockAcquireError` if the engine fails to acquire lock on
    ///   internal storage.
    ///
    /// # Returns
    /// * `()` - Unit.
    #[instrument(skip(self), fields(session_id = %session_id))]
    async fn abort(
        &self,
        session_id: SessionIdentifier,
    ) -> Result<(), Errors> {
        tracing::debug!(?session_id, "Aborting protocol session.");

        self.outputs
            .write()
            .map_err(
                |error: PoisonError<
                    RwLockWriteGuard<
                        '_,
                        HashMap<SessionIdentifier, ProtocolOutput>,
                    >,
                >| {
                    Errors::LiveLockAcquireError(format!(
                        "Failed to acquire live lock: {}.",
                        error
                    ))
                },
            )?
            .remove(&session_id);

        Ok(())
    }
}
