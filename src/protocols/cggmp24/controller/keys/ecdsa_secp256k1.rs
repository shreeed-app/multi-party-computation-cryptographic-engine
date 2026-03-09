//! CGGMP24 controller-side key generation protocol implementation.

use std::collections::VecDeque;

use async_trait::async_trait;
use futures::future::join_all;
use tokio::task::yield_now;
use tonic::Status;

use crate::{
    proto::signer::v1::{
        CollectRoundResponse,
        FinalizeSessionResponse,
        RoundMessage,
        StartKeyGenerationSessionRequest,
        StartSessionResponse,
        SubmitRoundRequest,
        SubmitRoundResponse,
        finalize_session_response::FinalOutput,
    },
    protocols::{
        algorithm::Algorithm,
        protocol::Protocol,
        types::{
            ControllerKeyGenerationInit,
            KeyGenerationInit,
            ProtocolInit,
            ProtocolOutput,
            Round,
        },
    },
    transport::{
        errors::{Errors, map_status},
        grpc::node_client::NodeIpcClient,
    },
};

/// CGGMP24 ECDSA Secp256k1 controller-side key generation protocol.
///
/// Drives the full DKG session lifecycle: starts sessions on all nodes,
/// routes messages between participants across rounds, and finalizes all
/// sessions once every worker signals completion.
pub struct Cggmp24EcdsaSecp256k1ControllerKeyGeneration {
    /// Algorithm identifier for this protocol instance.
    algorithm: Algorithm,
    /// Unique identifier for the key being generated, used for session
    /// management and output association.
    key_identifier: String,
    /// Threshold number of participants required to complete the protocol.
    threshold: u32,
    /// Total number of participants in the protocol.
    participants: u32,
    /// gRPC clients for communicating with participant nodes, indexed by
    /// participant order.
    nodes: Vec<NodeIpcClient>,
    /// Active session identifiers returned by each node at session start,
    /// indexed by participant order.
    sessions: Vec<String>,
    /// Final protocol output, populated by `run_protocol` and consumed by
    /// `finalize`.
    output: Option<ProtocolOutput>,
    /// Current protocol round, incremented after each batch of messages is
    /// dispatched.
    round: Round,
    /// Whether the protocol has been aborted.
    aborted: bool,
}

impl Cggmp24EcdsaSecp256k1ControllerKeyGeneration {
    /// Construct a new instance from the provided protocol initialization
    /// context.
    ///
    /// # Arguments
    /// * `protocol_init` (`ProtocolInit`) - Initialization context, must be
    ///   `KeyGeneration(Controller(...))`.
    ///
    /// # Errors
    /// * `Errors::InvalidProtocolInit` if the variant does not match.
    ///
    /// # Returns
    /// * `Result<Self, Errors>` - Initialized instance or error.
    pub fn try_new(protocol_init: ProtocolInit) -> Result<Self, Errors> {
        let init: ControllerKeyGenerationInit = match protocol_init {
            ProtocolInit::KeyGeneration(KeyGenerationInit::Controller(
                init,
            )) => init,
            _ => {
                return Err(Errors::InvalidProtocolInit(
                    "Expected KeyGeneration(Controller(...)) init.".into(),
                ));
            },
        };

        Ok(Self {
            algorithm: Algorithm::Cggmp24EcdsaSecp256k1,
            key_identifier: init.common.key_identifier,
            threshold: init.common.threshold,
            participants: init.common.participants,
            nodes: init.nodes,
            sessions: Vec::new(),
            round: 0,
            output: None,
            aborted: false,
        })
    }

    /// Start key generation sessions on all nodes sequentially and collect
    /// the initial outgoing messages from each.
    ///
    /// Sessions are started sequentially to ensure `self.sessions` is
    /// populated in order before any message routing begins.
    ///
    /// # Errors
    /// * `Errors::Generic` if any gRPC session start request fails.
    ///
    /// # Returns
    /// * `Result<VecDeque<RoundMessage>, Errors>` - Initial message queue.
    async fn start_sessions(
        &mut self,
    ) -> Result<VecDeque<RoundMessage>, Errors> {
        tracing::debug!("Starting sessions on all nodes.");

        let mut queue: VecDeque<RoundMessage> = VecDeque::new();

        for (identifier, node) in self.nodes.iter().enumerate() {
            let response: StartSessionResponse = node
                .start_key_generation(StartKeyGenerationSessionRequest {
                    key_identifier: self.key_identifier.clone(),
                    algorithm: self.algorithm.as_str().to_string(),
                    threshold: self.threshold,
                    participants: self.participants,
                    identifier: identifier as u32,
                })
                .await
                .map_err(map_status)?;

            self.sessions.push(response.session_identifier);

            for mut message in response.messages {
                message.from = Some(identifier as u32);
                queue.push_back(message);
            }
        }

        Ok(queue)
    }

    /// Build the list of `SubmitRoundRequest`s for a batch of outgoing
    /// messages.
    ///
    /// Broadcast messages (no `to` field) are fanned out to all participants
    /// except the sender. Point-to-point messages are delivered only to their
    /// target.
    fn build_submit_requests(
        &self,
        batch: &[RoundMessage],
    ) -> Result<Vec<(usize, SubmitRoundRequest)>, Errors> {
        let mut requests: Vec<(usize, SubmitRoundRequest)> = Vec::new();

        for message in batch {
            let from: u32 = match message.from {
                Some(from) => from,
                None => continue,
            };

            let targets: Vec<u32> = match message.to {
                Some(identifier) => vec![identifier],
                None => (0..self.participants)
                    .filter(|identifier: &u32| *identifier != from)
                    .collect(),
            };

            for node_id in targets {
                let node_index: usize = node_id as usize;
                // Skip if the target node index is out of bounds — this can
                // happen if a message is mis-routed to a non-existent
                // participant, but we don't want to fail the entire batch in
                // that case.
                if node_index >= self.sessions.len() {
                    continue;
                }

                let session_identifier: String =
                    match self.sessions.get(node_index) {
                        Some(session_id) => session_id.clone(),
                        None => {
                            return Err(Errors::InvalidMessage(format!(
                                "No session found for target node {}: {:?}",
                                node_id, self.sessions
                            )));
                        },
                    };

                requests.push((
                    node_index,
                    SubmitRoundRequest {
                        session_identifier,
                        round: message.round,
                        from: message.from,
                        to: message.to,
                        payload: message.payload.clone(),
                    },
                ));
            }
        }

        Ok(requests)
    }

    /// Submit a batch of round messages to the target nodes in parallel.
    ///
    /// # Errors
    /// * `Errors::Generic` if any submission gRPC call fails.
    async fn submit_batch(
        &self,
        batch: Vec<RoundMessage>,
    ) -> Result<(), Errors> {
        if batch.is_empty() {
            return Ok(());
        }

        let requests: Vec<(usize, SubmitRoundRequest)> =
            self.build_submit_requests(&batch)?;

        join_all(requests.into_iter().filter_map(
            |(index, request): (usize, SubmitRoundRequest)| {
                self.nodes
                    .get(index)
                    .map(|node: &NodeIpcClient| node.submit_round(request))
            },
        ))
        .await
        .into_iter()
        .collect::<Result<Vec<SubmitRoundResponse>, Status>>()
        .map_err(map_status)?;

        Ok(())
    }

    /// Poll all active node sessions for outgoing messages, retrying until at
    /// least one node produces output or all nodes signal completion.
    ///
    /// Yields to the Tokio runtime between polls to avoid busy-waiting.
    ///
    /// # Errors
    /// * `Errors::Generic` if any collect gRPC call fails.
    ///
    /// # Returns
    /// * `Result<(VecDeque<RoundMessage>, Vec<bool>), Errors>` - Collected
    ///   messages and updated completion flags.
    async fn collect_round(
        &self,
        all_done: &mut [bool],
    ) -> Result<VecDeque<RoundMessage>, Errors> {
        tracing::debug!("Collecting round messages from all nodes.");

        let mut queue: VecDeque<RoundMessage> = VecDeque::new();

        // Loop until at least one node produces output or all nodes are done.
        loop {
            let responses: Vec<(usize, Result<CollectRoundResponse, Status>)> =
                join_all(
                    self.sessions
                        .iter()
                        .enumerate()
                        .filter(|(index, _): &(usize, &String)| {
                            all_done
                                .get(*index)
                                .copied()
                                .is_some_and(|done: bool| !done)
                        })
                        .filter_map(
                            |(index, session_id): (usize, &String)| {
                                self.nodes.get(index).map(
                                    |node: &NodeIpcClient| {
                                        let future: impl Future<
                                            Output = Result<
                                                CollectRoundResponse,
                                                Status,
                                            >,
                                        > = node
                                            .collect_round(session_id.clone());
                                        async move { (index, future.await) }
                                    },
                                )
                            },
                        ),
                )
                .await;

            let mut got_something: bool = false;

            for (index, result) in responses {
                let response: CollectRoundResponse =
                    result.map_err(map_status)?;

                if response.done
                    && let Some(slot) = all_done.get_mut(index)
                {
                    *slot = true;
                }

                // Enqueue any messages returned by this node, tagging them
                // with the sender identifier for routing in `submit_batch`.
                for message in response.messages {
                    got_something = true;
                    queue.push_back(message);
                }
            }

            // Exit the loop if we got any messages or if all nodes are done —
            // if something was received, we want to process it immediately
            // without waiting for the next poll interval, and if all nodes are
            // done we want to exit regardless of whether we got something to
            // avoid waiting indefinitely.
            if got_something || all_done.iter().all(|done: &bool| *done) {
                break;
            }

            yield_now().await;
        }

        Ok(queue)
    }

    /// Drive the full protocol execution loop.
    ///
    /// Starts sessions, then alternates between submitting outgoing messages
    /// and collecting incoming messages until all node workers signal
    /// completion and the message queue is empty.
    ///
    /// Stores the final output in `self.output` on success.
    ///
    /// # Errors
    /// * Any error propagated from `start_sessions`, `submit_batch`,
    ///   `collect_round`, or `finalize_all`.
    async fn run_protocol(&mut self) -> Result<(), Errors> {
        tracing::debug!("Starting protocol execution.");

        let mut queue: VecDeque<RoundMessage> = self.start_sessions().await?;
        let mut all_done: Vec<bool> = vec![false; self.nodes.len()];

        loop {
            // Submit all queued messages to their target nodes.
            let batch: Vec<RoundMessage> = queue.drain(..).collect();
            self.submit_batch(batch).await?;

            // Collect responses — retry until output or all done.
            queue = self.collect_round(&mut all_done).await?;

            // Exit once all workers are done and nothing left to send.
            if all_done.iter().all(|done: &bool| *done) && queue.is_empty() {
                break;
            }

            self.round += 1;
        }

        self.output = Some(self.finalize_all().await?);

        Ok(())
    }

    /// Finalize all node sessions in parallel and extract the key generation
    /// output.
    ///
    /// All sessions are finalized concurrently to avoid dropping node channels
    /// while other workers are still active.
    ///
    /// # Errors
    /// * `Errors::Generic` if any finalize gRPC call fails.
    /// * `Errors::InvalidMessage` if any node returns an unexpected output
    ///   variant or no output is received.
    ///
    /// # Returns
    /// * `Result<ProtocolOutput, Errors>` - Key generation output or error.
    async fn finalize_all(&mut self) -> Result<ProtocolOutput, Errors> {
        tracing::debug!("Finalizing all sessions and collecting output.");

        let futures: Vec<
            impl Future<Output = Result<FinalizeSessionResponse, Errors>>,
        > = self
            .sessions
            .iter()
            .enumerate()
            .filter_map(|(index, session_identifier): (usize, &String)| {
                // Finalize each session concurrently — since the controller
                // runs the protocol synchronously, we can safely finalize all
                // sessions at the same time without worrying about message
                // routing or session state.
                self.nodes.get(index).map(|node: &NodeIpcClient| {
                    let session_identifier: String =
                        session_identifier.clone();
                    async move {
                        node.finalize(session_identifier)
                            .await
                            .map_err(map_status)
                    }
                })
            })
            .collect();

        // Await all finalize responses and collect results.
        let responses: Vec<FinalizeSessionResponse> = join_all(futures)
            .await
            .into_iter()
            .collect::<Result<Vec<_>, _>>()?;

        let mut result_output: Option<ProtocolOutput> = None;

        for response in responses {
            match response.final_output {
                Some(FinalOutput::KeyGeneration(kg)) => {
                    if result_output.is_none() {
                        result_output = Some(ProtocolOutput::KeyGeneration {
                            key_identifier: self.key_identifier.clone(),
                            key_share: None,
                            public_key: kg.public_key,
                            public_key_package: kg.public_key_package,
                        });
                    }
                },
                Some(other) => {
                    return Err(Errors::InvalidMessage(format!(
                        "Unexpected finalize output variant: {:?}",
                        other
                    )));
                },
                None => {
                    return Err(Errors::InvalidMessage(
                        "Node returned empty finalize output.".into(),
                    ));
                },
            }
        }

        result_output.ok_or_else(|| {
            Errors::InvalidMessage("No finalize output received.".into())
        })
    }
}

#[async_trait]
impl Protocol for Cggmp24EcdsaSecp256k1ControllerKeyGeneration {
    fn algorithm(&self) -> Algorithm {
        self.algorithm
    }

    fn threshold(&self) -> u32 {
        self.threshold
    }

    fn participants(&self) -> u32 {
        self.participants
    }

    fn current_round(&self) -> Round {
        self.round
    }

    /// Trigger protocol execution on the first call.
    ///
    /// CGGMP24 controller drives the full session lifecycle internally —
    /// the engine calls `next_round` once to start execution, then
    /// `finalize` to retrieve the output.
    ///
    /// # Errors
    /// * `Errors::Generic` if any error occurs during protocol execution.
    ///
    /// # Returns
    /// * `Result<Option<RoundMessage>, Errors>` - Always returns `Ok(None)`
    ///   since the controller does not produce messages for the engine to
    ///   route.
    async fn next_round(&mut self) -> Result<Option<RoundMessage>, Errors> {
        if self.round != 0 {
            return Ok(None);
        }

        self.run_protocol().await?;

        Ok(None)
    }

    /// No-op — the CGGMP24 controller does not process individual inbound
    /// messages. All message routing is handled internally by `run_protocol`.
    ///
    /// # Errors
    /// * `Errors::Generic` if any error occurs during message handling, though
    ///   since this implementation does not process messages, it always
    ///   returns `Ok(None)`.
    ///
    /// # Returns
    /// * `Result<Option<RoundMessage>, Errors>` - Always returns `Ok(None)`
    ///   since the controller does not produce messages for the engine to
    ///   route.
    async fn handle_message(
        &mut self,
        _message: RoundMessage,
    ) -> Result<Option<RoundMessage>, Errors> {
        Ok(None)
    }

    /// Consume and return the final protocol output.
    ///
    /// # Errors
    /// * `Errors::InvalidState` if called before `next_round` has completed.
    ///
    /// # Returns
    /// * `Result<ProtocolOutput, Errors>` - Final protocol output or error.
    async fn finalize(&mut self) -> Result<ProtocolOutput, Errors> {
        self.output.take().ok_or_else(|| {
            Errors::InvalidState(
                "Protocol output not available — next_round must complete \
                before finalize."
                    .into(),
            )
        })
    }

    fn abort(&mut self) {
        self.aborted = true;
    }
}
