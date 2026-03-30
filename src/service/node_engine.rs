//! Engine implementation (thread-safe per session).

use std::{collections::HashMap, sync::Arc, time::Duration};

use async_trait::async_trait;
use tokio::{
    sync::{Mutex, MutexGuard, Notify},
    task::yield_now,
};
use tracing::instrument;

use crate::{
    auth::session::{
        identifier::SessionIdentifier,
        state::SessionState,
        store::SessionStore,
    },
    proto::signer::v1::{self as proto, RoundMessage},
    protocols::{
        factory::ProtocolFactory,
        protocol::Protocol,
        types::{ProtocolInit, ProtocolOutput},
    },
    service::{api::EngineApi, entry::SessionEntry},
    transport::errors::Errors,
};

/// Node engine. Each session is executed in-memory and protected by a mutex to
/// guarantee single-threaded execution per session. Sessions are automatically
/// expired after a TTL.
pub struct NodeEngine {
    /// In-memory session store for lifecycle management.
    pub sessions: SessionStore,
    /// Live session entries for active sessions.
    pub live: Mutex<HashMap<SessionIdentifier, Arc<Mutex<SessionEntry>>>>,
}

impl NodeEngine {
    /// Create a new node engine with the given session TTL.
    ///
    /// # Arguments
    /// * `ttl` (`Duration`) - Time-to-live for sessions.
    ///
    /// # Returns
    /// * `Self` - A new node engine instance.
    pub fn new(ttl: Duration) -> Self {
        Self {
            sessions: SessionStore::new(ttl),
            live: Mutex::new(HashMap::new()),
        }
    }

    /// Helper to retrieve a live session entry by ID.
    ///
    /// # Arguments
    /// * `session_id` (`SessionId`) - Target session identifier.
    ///
    /// # Errors
    /// * `Errors::SessionNotFound` if the session ID does not exist in live
    ///   sessions.
    ///
    /// # Returns
    /// * `Arc<Mutex<SessionEntry>>` - The live session entry wrapped in an
    ///   `Arc<Mutex<>>` for thread-safe access.
    async fn get_entry(
        &self,
        session_identifier: SessionIdentifier,
    ) -> Result<Arc<Mutex<SessionEntry>>, Errors> {
        self.live.lock().await.get(&session_identifier).cloned().ok_or_else(
            || Errors::SessionNotFound(session_identifier.to_string()),
        )
    }
}

#[async_trait]
impl EngineApi for NodeEngine {
    #[instrument(skip(self, init))]
    /// Start a distributed session.
    ///
    /// # Arguments
    /// * `init` (`ProtocolInit`) - Protocol initialization context.
    ///
    /// # Errors
    /// * `Errors::UnsupportedAlgorithm` if the algorithm is not supported.
    /// * `Errors::InvalidProtocolInit` if the protocol initialization context
    ///   is invalid.
    /// * `Errors::LiveLockAcquireError` if the engine fails to acquire lock on
    ///  internal storage.
    ///
    /// # Returns
    /// * `(SessionId, Vec<RoundMessage>)` - Session identifier and initial
    ///   round messages (empty for controller since it executes
    ///   synchronously).
    async fn start_session(
        &self,
        init: ProtocolInit,
    ) -> Result<(SessionIdentifier, Vec<RoundMessage>), Errors> {
        let session_identifier: SessionIdentifier = self.sessions.create();

        let mut protocol: Box<dyn Protocol> = ProtocolFactory::create(init)
            .inspect_err(|error: &Errors| {
                tracing::error!(
                    "Failed to create protocol instance for session {}: {}",
                    session_identifier,
                    error
                );

                self.sessions.remove(session_identifier);
            })?;

        // Since the controller executes the protocol synchronously, we can
        // call `next_round()` until the protocol is done to collect
        // all produced messages for the first round before returning.
        let mut messages: Vec<RoundMessage> = Vec::new();
        loop {
            match protocol.next_round().await {
                Ok(Some(message)) => messages.push(message),
                Ok(None) => break,
                Err(error) => {
                    // Clean up the session store entry so the orphaned session
                    // doesn't linger until TTL.
                    self.sessions.remove(session_identifier);
                    return Err(error);
                },
            }
        }

        self.live.lock().await.insert(
            session_identifier,
            Arc::new(Mutex::new(SessionEntry {
                state: SessionState::Initialized,
                protocol: Some(protocol),
            })),
        );

        Ok((session_identifier, messages))
    }

    /// Submit a round message to the session.
    ///
    /// # Arguments
    /// * `session_identifier` (`SessionIdentifier`) - Identifier of the
    ///   session to which the message belongs.
    /// * `message` (`RoundMessage`) - Message received from another node.
    ///
    /// # Errors
    /// * `Errors::InvalidState` if the session is not in a valid state to
    ///   accept messages.
    ///
    /// # Returns
    /// * `Vec<RoundMessage>` - Messages to broadcast for the next round after
    ///   processing the submitted message.
    #[instrument(skip(self, message), fields(session_identifier = %session_identifier))]
    async fn submit_round(
        &self,
        session_identifier: SessionIdentifier,
        message: proto::RoundMessage,
    ) -> Result<Vec<RoundMessage>, Errors> {
        tracing::debug!(
            "Submitting round message for session {}: {:?}",
            session_identifier,
            message
        );

        let entry: Arc<Mutex<SessionEntry>> =
            self.get_entry(session_identifier).await?;
        let mut entry: MutexGuard<'_, SessionEntry> = entry.lock().await;

        let protocol: &mut Box<dyn Protocol + 'static> = entry
            .protocol
            .as_mut()
            .ok_or_else(|| Errors::InvalidState("Protocol missing.".into()))?;

        let round: u32 = message.round;
        let mut produced: Vec<RoundMessage> = Vec::new();

        if let Some(message) = protocol.handle_message(message).await? {
            tracing::debug!(
                "Message produced after handling round message for session {}: {:?}",
                session_identifier,
                message
            );
            produced.push(message);
        }

        entry.state.advance_round(round);
        Ok(produced)
    }

    /// Collect round messages produced by the worker for the current round.
    ///
    /// Polls the protocol until at least one outgoing message is available or
    /// the protocol signals completion. The mutex is released between polls to
    /// allow concurrent `submit_round` calls to deliver incoming messages to
    /// the worker — which is what unblocks message production.
    ///
    /// # Why the retry loop?
    /// The worker runs on a separate OS thread and produces outgoing messages
    /// asynchronously. When `collect_round` is called, the worker may not have
    /// had time to process the last incoming message and flush its outgoing
    /// batch yet. Returning immediately with an empty result would cause the
    /// controller to stall — it would see no messages and loop forever without
    /// making progress.
    ///
    /// Releasing the mutex before `yield_now()` is critical: holding it while
    /// waiting would block `submit_round` from delivering incoming messages to
    /// the worker, deadlocking the protocol.
    ///
    /// # Arguments
    /// * `session_identifier` (`SessionIdentifier`) - Target session
    ///   identifier.
    ///
    /// # Errors
    /// * `Errors::SessionNotFound` if the session does not exist.
    /// * `Errors::InvalidState` if the protocol is missing from the session.
    /// * Any error propagated from `Protocol::next_round`.
    ///
    /// # Returns
    /// * `(Vec<RoundMessage>, bool)` - Outgoing messages produced for this
    ///   round, and a boolean indicating whether the protocol is complete.
    #[instrument(skip(self), fields(session_identifier = %session_identifier))]
    async fn collect_round(
        &self,
        session_identifier: SessionIdentifier,
    ) -> Result<(Vec<proto::RoundMessage>, bool), Errors> {
        tracing::debug!(
            "Collecting round messages for session {}.",
            session_identifier
        );

        let entry: Arc<Mutex<SessionEntry>> =
            self.get_entry(session_identifier).await?;

        loop {
            // Acquire the mutex, drain all messages the worker has produced so
            // far, then release it before waiting. Releasing before the wait
            // is critical — holding the mutex while waiting would
            // block `submit_round` from delivering incoming
            // messages to the worker, which is the only thing that
            // can unblock message production.
            let (produced, done, notify): (
                Vec<RoundMessage>,
                bool,
                Option<Arc<Notify>>,
            ) = {
                let mut entry: MutexGuard<'_, SessionEntry> =
                    entry.lock().await;

                let protocol: &mut Box<dyn Protocol + 'static> =
                    entry.protocol.as_mut().ok_or_else(|| {
                        Errors::InvalidState("Protocol missing.".into())
                    })?;

                // Drain all messages currently available from the worker. Each
                // call to `next_round` pops one message from the pending queue
                // (which was populated by `drain_pending` from the worker's
                // outgoing channel). Loop until the queue is empty.
                let mut produced: Vec<RoundMessage> = Vec::new();
                while let Some(message) = protocol.next_round().await? {
                    tracing::debug!(
                        "Message produced for session {}: {:?}",
                        session_identifier,
                        message
                    );
                    produced.push(message);
                }

                // Clone the notify handle before releasing the mutex so we
                // can await it without holding the lock.
                let notify: Option<Arc<Notify>> = protocol.activity_notify();

                (produced, protocol.is_done(), notify)
            }; // mutex released here — submit_round can now acquire it.

            if !produced.is_empty() || done {
                tracing::debug!(
                    "Collected round messages for session {}: {:?}",
                    session_identifier,
                    produced
                );

                return Ok((produced, done));
            }

            // Nothing produced yet and protocol not done — the worker is still
            // processing the last incoming message batch. Wait for the worker
            // to signal activity before retrying. Using `notified().await`
            // instead of `yield_now()` is critical on slow hardware:
            // `yield_now` keeps the threads spinning and starves
            // the worker OS threads of CPU time. `notified().
            // await` suspends the task so the Tokio thread goes
            // idle, letting the OS scheduler run the worker threads.
            match notify {
                Some(notify) => notify.notified().await,
                None => {
                    tracing::debug!(
                        "No notify handle provided by protocol for session \
                        {} — falling back to yield_now polling.",
                        session_identifier
                    );
                    yield_now().await
                },
            }
        }
    }

    /// Collect round messages from all participants for the current round.
    ///
    /// # Arguments
    /// * `session_identifier` (`SessionIdentifier`) - Identifier of the
    ///   session for which to collect messages.
    ///
    /// # Errors
    /// * `Errors::InvalidState` if the session is not in a valid state to
    ///   finalize.
    ///
    /// # Returns
    /// * `ProtocolOutput` - Collected messages for the current round.
    #[instrument(skip(self), fields(session_identifier = %session_identifier))]
    async fn finalize(
        &self,
        session_identifier: SessionIdentifier,
    ) -> Result<ProtocolOutput, Errors> {
        tracing::debug!("Finalizing session {}.", session_identifier);

        self.sessions
            .with_session(session_identifier, |state: &mut SessionState| {
                state.finalize()
            })?;

        let entry: Arc<Mutex<SessionEntry>> = {
            self.live.lock().await.remove(&session_identifier).ok_or_else(
                || Errors::SessionNotFound(session_identifier.to_string()),
            )?
        };

        let mut entry: MutexGuard<'_, SessionEntry> = entry.lock().await;
        let protocol: &mut Box<dyn Protocol + 'static> = entry
            .protocol
            .as_mut()
            .ok_or_else(|| Errors::InvalidState("Protocol missing.".into()))?;

        Ok(protocol.finalize().await?)
    }

    /// Start a distributed signing session.
    ///
    /// # Arguments
    /// * `session_identifier` (`SessionIdentifier`) - Identifier of the
    ///   session to abort.
    ///
    /// # Errors
    /// * `Status` - If the algorithm is unsupported, protocol initialization
    ///   fails, or if finalization fails.
    ///
    /// # Returns
    /// * `GenerateKeyResponse` - The response containing the generated key.
    #[instrument(skip(self), fields(session_identifier = %session_identifier))]
    async fn abort(
        &self,
        session_identifier: SessionIdentifier,
    ) -> Result<(), Errors> {
        tracing::debug!("Aborting session {}.", session_identifier);

        self.sessions.with_session(
            session_identifier,
            |state: &mut SessionState| {
                state.abort();
                Ok(())
            },
        )?;

        let entry: Option<Arc<Mutex<SessionEntry>>> =
            self.live.lock().await.remove(&session_identifier);

        if let Some(entry) = entry {
            let mut entry: MutexGuard<'_, SessionEntry> = entry.lock().await;
            if let Some(protocol) = entry.protocol.as_mut() {
                protocol.abort();
            }
        }

        Ok(())
    }
}
