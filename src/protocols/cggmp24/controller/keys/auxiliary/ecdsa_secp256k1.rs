//! CGGMP24 ECDSA Secp256k1 controller-side auxiliary info generation protocol.
//!
//! Orchestrates the aux gen session lifecycle across all participant nodes:
//! starts sessions in parallel (each node generates Paillier primes
//! concurrently), routes messages across rounds, and finalizes all sessions
//! to produce complete key shares in Vault.

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
        StartAuxiliaryGenerationSessionRequest,
        StartSessionResponse,
        SubmitRoundRequest,
        SubmitRoundResponse,
        finalize_session_response::FinalOutput,
    },
    protocols::{
        algorithm::Algorithm,
        protocol::Protocol,
        types::{
            AuxiliaryGenerationInit,
            ControllerAuxiliaryGenerationInit,
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

/// CGGMP24 ECDSA Secp256k1 controller-side auxiliary info generation protocol.
///
/// Drives the full aux gen session lifecycle: starts sessions on all nodes in
/// parallel (allowing concurrent Paillier prime generation), routes messages
/// between participants across rounds, and finalizes all sessions once every
/// worker signals completion.
pub struct Cggmp24EcdsaSecp256k1ControllerAuxiliaryGeneration {
    /// Algorithm identifier for this protocol instance.
    algorithm: Algorithm,
    /// Unique identifier for the key whose aux info is being generated.
    key_identifier: String,
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

impl Cggmp24EcdsaSecp256k1ControllerAuxiliaryGeneration {
    /// Construct a new instance from the provided protocol initialization
    /// context.
    ///
    /// # Arguments
    /// * `protocol_init` (`ProtocolInit`) - Initialization context, must be
    ///   `AuxiliaryGeneration(Controller(...))`.
    ///
    /// # Errors
    /// * `Errors::InvalidProtocolInit` - If the variant does not match.
    ///
    /// # Returns
    /// * `Self` - Initialized instance ready to run.
    pub fn try_new(protocol_init: ProtocolInit) -> Result<Self, Errors> {
        let init: ControllerAuxiliaryGenerationInit = match protocol_init {
            ProtocolInit::AuxiliaryGeneration(
                AuxiliaryGenerationInit::Controller(init),
            ) => init,
            _ => {
                return Err(Errors::InvalidProtocolInit(
                    "Invalid protocol initialization context for CGGMP24 \
                    auxiliary key generation."
                        .into(),
                ));
            },
        };

        Ok(Self {
            algorithm: init.common.algorithm,
            key_identifier: init.common.key_identifier,
            participants: init.common.participants,
            nodes: init.nodes,
            sessions: Vec::new(),
            output: None,
            round: 0,
            aborted: false,
        })
    }

    /// Start auxiliary generation sessions on all nodes in parallel and
    /// collect the initial outgoing messages from each.
    ///
    /// Sessions are started concurrently so that each node generates its
    /// Paillier primes simultaneously — reduces total wall time from
    /// O(n * prime_gen) to O(prime_gen).
    ///
    /// # Errors
    /// * `Errors::Generic` - If any gRPC session start request fails.
    ///
    /// # Returns
    /// * `VecDeque<RoundMessage>` - Initial message queue from all nodes.
    async fn start_sessions(
        &mut self,
    ) -> Result<VecDeque<RoundMessage>, Errors> {
        tracing::debug!(
            "Starting auxiliary generation sessions on all nodes in parallel."
        );

        let futures: impl Iterator<
            Item = impl Future<
                Output = (usize, Result<StartSessionResponse, Status>),
            >,
        > = self.nodes.iter().enumerate().map(
            |(index, node): (usize, &NodeIpcClient)| {
                let request: StartAuxiliaryGenerationSessionRequest =
                    StartAuxiliaryGenerationSessionRequest {
                        key_identifier: self.key_identifier.clone(),
                        algorithm: self.algorithm.as_str().to_string(),
                        participants: self.participants,
                        identifier: index as u32,
                    };
                async move {
                    (index, node.start_auxiliary_generation(request).await)
                }
            },
        );

        let mut responses: Vec<(usize, Result<StartSessionResponse, Status>)> =
            join_all(futures).await;

        // Sort by index to ensure sessions are registered in participant
        // order.
        responses.sort_by_key(
            |(index, _): &(usize, Result<StartSessionResponse, Status>)| {
                *index
            },
        );

        responses.into_iter().try_fold(
            VecDeque::new(),
            |mut queue: VecDeque<RoundMessage>,
             (index, result): (
                usize,
                Result<StartSessionResponse, Status>,
            )| {
                let response: StartSessionResponse =
                    result.map_err(map_status)?;

                self.sessions.push(response.session_identifier);

                queue.extend(response.messages.into_iter().map(
                    |mut message: RoundMessage| {
                        message.from = Some(index as u32);
                        message
                    },
                ));
                Ok(queue)
            },
        )
    }

    /// Build the list of `SubmitRoundRequest`s for a batch of outgoing
    /// messages.
    ///
    /// Broadcast messages (no `to` field) are fanned out to all participants
    /// except the sender. Point-to-point messages are delivered only to their
    /// target.
    ///
    /// # Errors
    /// * `Errors::InvalidMessage` - If a session identifier cannot be found
    ///   for a target node.
    fn build_submit_requests(
        &self,
        batch: &[RoundMessage],
    ) -> Result<Vec<(usize, SubmitRoundRequest)>, Errors> {
        batch
            .iter()
            // Skip messages with no sender — cannot route without origin.
            .filter_map(|message: &RoundMessage| {
                message.from.map(|from: u32| (from, message))
            })
            .flat_map(|(from, message): (u32, &RoundMessage)| {
                // Fan out broadcast messages to all participants except the
                // sender, deliver P2P messages only to their designated
                // target.
                let targets: Vec<u32> = match message.to {
                    Some(identifier) => vec![identifier],
                    None => (0..self.participants)
                        .filter(|identifier: &u32| *identifier != from)
                        .collect(),
                };

                targets
                    .into_iter()
                    .map(move |identifier: u32| (identifier, message))
            })
            .map(|(node_identifier, message): (u32, &RoundMessage)| {
                let node_index: usize = node_identifier as usize;

                let session_identifier: String = self
                    .sessions
                    .get(node_index)
                    .ok_or_else(|| {
                        Errors::InvalidMessage(format!(
                            "No session found for target node {}: {:?}",
                            node_identifier, self.sessions
                        ))
                    })?
                    .clone();

                Ok((
                    node_index,
                    SubmitRoundRequest {
                        session_identifier,
                        round: message.round,
                        from: message.from,
                        to: message.to,
                        payload: message.payload.clone(),
                    },
                ))
            })
            .collect()
    }

    /// Submit a batch of round messages to the target nodes in parallel.
    ///
    /// # Errors
    /// * `Errors::Generic` - If any submission gRPC call fails.
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

    /// Poll all active node sessions for outgoing messages, yielding to the
    /// Tokio runtime between polls until at least one node produces output or
    /// all nodes signal completion.
    ///
    /// # Arguments
    /// * `all_done` (`&mut [bool]`) - Completion flags per node, updated
    ///   in-place as nodes signal done.
    ///
    /// # Errors
    /// * `Errors::Generic` - If any collect_round gRPC call fails.
    ///
    /// # Returns
    /// * `VecDeque<RoundMessage>` - Collected messages from all nodes.
    async fn collect_round(
        &self,
        all_done: &mut [bool],
    ) -> Result<VecDeque<RoundMessage>, Errors> {
        let mut queue: VecDeque<RoundMessage> = VecDeque::new();

        loop {
            let responses: Vec<(usize, Result<CollectRoundResponse, Status>)> =
                join_all(
                    self.sessions
                        .iter()
                        .enumerate()
                        // Skip nodes that have already signaled completion.
                        .filter(|(index, _): &(usize, &String)| {
                            !all_done.get(*index).copied().unwrap_or(true)
                        })
                        .filter_map(
                            |(index, session_identifier): (usize, &String)| {
                                self.nodes.get(index).map(
                                    |node: &NodeIpcClient| {
                                        let future: impl Future<
                                            Output = Result<
                                                CollectRoundResponse,
                                                Status,
                                            >,
                                        > = node.collect_round(
                                            session_identifier.clone(),
                                        );
                                        async move { (index, future.await) }
                                    },
                                )
                            },
                        ),
                )
                .await;

            responses.into_iter().try_for_each(
                |(index, result): (
                    usize,
                    Result<CollectRoundResponse, Status>,
                )| {
                    let response: CollectRoundResponse =
                        result.map_err(map_status)?;

                    // Mark the node as done if it signals completion.
                    if response.done
                        && let Some(slot) = all_done.get_mut(index)
                    {
                        *slot = true;
                    }

                    queue.extend(response.messages);
                    Ok::<(), Errors>(())
                },
            )?;

            // Break if any messages were collected or all nodes are done.
            if !queue.is_empty() || all_done.iter().all(|done: &bool| *done) {
                break;
            }

            // Yield to the tokio runtime before retrying — avoids
            // busy-waiting while allowing other tasks to make progress.
            yield_now().await;
        }

        Ok(queue)
    }

    /// Finalize all node sessions in parallel and verify that all nodes
    /// completed aux gen successfully.
    ///
    /// Unlike keygen, aux gen produces no public output — all key material
    /// is stored privately in Vault by each node. This method simply verifies
    /// that all sessions completed with the expected output variant.
    ///
    /// # Errors
    /// * `Errors::InvalidMessage` - If any node returns an unexpected output
    ///   variant or no output is received.
    ///
    /// # Returns
    /// * `ProtocolOutput::AuxiliaryGeneration` - Completion signal with the
    ///   scoped key identifier.
    async fn finalize_all(&mut self) -> Result<ProtocolOutput, Errors> {
        tracing::debug!("Finalizing all auxiliary generation sessions.");

        let responses: Vec<FinalizeSessionResponse> =
            join_all(self.sessions.iter().enumerate().filter_map(
                |(index, session_identifier): (usize, &String)| {
                    self.nodes.get(index).map(|node: &NodeIpcClient| {
                        let session_identifier: String =
                            session_identifier.clone();
                        async move {
                            node.finalize(session_identifier)
                                .await
                                .map_err(map_status)
                        }
                    })
                },
            ))
            .await
            .into_iter()
            .collect::<Result<Vec<FinalizeSessionResponse>, Errors>>()?;

        // Verify all nodes returned the expected AuxiliaryGeneration output —
        // key material is stored in Vault by each node, so no public output
        // needs to be extracted here.
        responses.into_iter().try_for_each(
            |response: FinalizeSessionResponse| match response.final_output {
                Some(FinalOutput::AuxiliaryGeneration(_)) => Ok(()),
                Some(other) => Err(Errors::InvalidMessage(format!(
                    "Unexpected finalize output variant: {:?}",
                    other
                ))),
                None => Err(Errors::InvalidMessage(
                    "Node returned empty finalize output.".into(),
                )),
            },
        )?;

        Ok(ProtocolOutput::AuxiliaryGeneration {
            key_identifier: self.key_identifier.clone(),
            key_share: None,
        })
    }

    /// Drive the full protocol execution loop until all nodes complete.
    ///
    /// Starts all sessions, then alternates between submitting outgoing
    /// messages and collecting responses until all nodes signal done and the
    /// message queue is empty.
    ///
    /// # Errors
    /// * Any error propagated from `start_sessions`, `submit_batch`,
    ///   `collect_round`, or `finalize_all`.
    async fn run_protocol(&mut self) -> Result<(), Errors> {
        tracing::debug!("Starting auxiliary generation protocol execution.");

        let mut queue: VecDeque<RoundMessage> = self.start_sessions().await?;
        let mut all_done: Vec<bool> = vec![false; self.nodes.len()];

        loop {
            // Submit all pending outgoing messages to their target nodes.
            self.submit_batch(queue.drain(..).collect()).await?;

            // Collect responses — blocks until at least one node produces
            // output or all nodes are done.
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
}

#[async_trait]
impl Protocol for Cggmp24EcdsaSecp256k1ControllerAuxiliaryGeneration {
    fn algorithm(&self) -> Algorithm {
        self.algorithm
    }

    fn threshold(&self) -> u32 {
        // Aux gen requires all participants — threshold equals participants.
        self.participants
    }

    fn participants(&self) -> u32 {
        self.participants
    }

    fn current_round(&self) -> Round {
        self.round
    }

    /// Trigger protocol execution on the first call.
    ///
    /// The CGGMP24 controller drives the full session lifecycle internally —
    /// the engine calls `next_round` once to start execution, then `finalize`
    /// to retrieve the output. Subsequent calls return `Ok(None)`.
    ///
    /// # Errors
    /// * `Errors::Aborted` - If the protocol has been aborted.
    /// * `Errors::Generic` - If any error occurs during protocol execution.
    async fn next_round(&mut self) -> Result<Option<RoundMessage>, Errors> {
        if self.aborted {
            return Err(Errors::Aborted("Protocol has been aborted.".into()));
        }

        if self.round != 0 {
            return Ok(None);
        }

        self.run_protocol().await?;

        Ok(None)
    }

    /// No-op — the CGGMP24 controller orchestrates all message routing
    /// internally via `run_protocol` and does not process individual inbound
    /// messages from the engine.
    async fn handle_message(
        &mut self,
        _message: RoundMessage,
    ) -> Result<Option<RoundMessage>, Errors> {
        Ok(None)
    }

    /// Consume and return the final protocol output.
    ///
    /// Consumes the output — calling `finalize` twice will return an error.
    ///
    /// # Errors
    /// * `Errors::InvalidState` - If called before `next_round` has completed.
    ///
    /// # Returns
    /// * `ProtocolOutput::AuxiliaryGeneration` - Completion signal with the
    ///   scoped key identifier.
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
