//! CGGMP24 ECDSA Secp256k1 controller-side signing protocol implementation.

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
        StartSessionResponse,
        StartSigningSessionRequest,
        SubmitRoundRequest,
        SubmitRoundResponse,
        finalize_session_response::FinalOutput,
        signature_result::FinalSignature,
    },
    protocols::{
        algorithm::Algorithm,
        protocol::Protocol,
        types::{
            ControllerSigningInit,
            ProtocolInit,
            ProtocolOutput,
            Round,
            SigningInit,
        },
    },
    transport::{
        errors::{Errors, map_status},
        grpc::node_client::NodeIpcClient,
    },
};

/// CGGMP24 ECDSA Secp256k1 controller-side signing protocol.
///
/// Drives the full signing session lifecycle: starts sessions on all nodes
/// in parallel, routes messages between participants across rounds, and
/// finalizes all sessions once every worker signals completion.
pub struct Cggmp24EcdsaSecp256k1ControllerSigning {
    /// Algorithm identifier for this protocol instance.
    algorithm: Algorithm,
    /// Unique identifier for the key being signed with.
    key_identifier: String,
    /// Threshold number of participants required to complete the protocol.
    threshold: u32,
    /// Total number of participants in the protocol.
    participants: u32,
    /// Message to be signed.
    message: Vec<u8>,
    /// gRPC clients for communicating with participant nodes.
    nodes: Vec<NodeIpcClient>,
    /// Active session identifiers returned by each node at session start,
    /// indexed by participant order.
    sessions: Vec<String>,
    /// Final protocol output, populated by `run_protocol` and consumed by
    /// `finalize`.
    output: Option<ProtocolOutput>,
    /// Current protocol round.
    round: Round,
    /// Whether the protocol has been aborted.
    aborted: bool,
}

impl Cggmp24EcdsaSecp256k1ControllerSigning {
    /// Construct a new instance from the provided protocol initialization
    /// context.
    ///
    /// # Arguments
    /// * `protocol_init` (`ProtocolInit`) - Initialization context, must be
    ///   `Signing(Controller(...))`.
    ///
    /// # Errors
    /// * `Errors::InvalidProtocolInit` - If the variant does not match.
    ///
    /// # Returns
    /// * `Self` - Initialized instance ready to run.
    pub fn try_new(protocol_init: ProtocolInit) -> Result<Self, Errors> {
        let init: ControllerSigningInit = match protocol_init {
            ProtocolInit::Signing(SigningInit::Controller(init)) => init,
            _ => {
                return Err(Errors::InvalidProtocolInit(
                    "Invalid protocol initialization context for CGGMP24 \
                    controller signing."
                        .into(),
                ));
            },
        };

        Ok(Self {
            algorithm: init.common.algorithm,
            key_identifier: init.common.key_identifier,
            threshold: init.common.threshold,
            participants: init.common.participants,
            message: init.common.message,
            nodes: init.nodes,
            sessions: Vec::new(),
            round: 0,
            output: None,
            aborted: false,
        })
    }

    /// Start signing sessions on all nodes in parallel and collect the
    /// initial outgoing messages from each.
    ///
    /// Each node receives a scoped key identifier
    /// (`<key_id>/<participant_index>`) to locate its key share in Vault.
    ///
    /// # Errors
    /// * `Errors::Generic` - If any gRPC session start request fails.
    ///
    /// # Returns
    /// * `VecDeque<RoundMessage>` - Initial message queue from all nodes.
    async fn start_sessions(
        &mut self,
    ) -> Result<VecDeque<RoundMessage>, Errors> {
        tracing::debug!("Starting signing sessions on all nodes.");

        // Start all sessions in parallel — avoids sequential latency for
        // n nodes.
        let futures: impl Iterator<
            Item = impl Future<
                Output = (usize, Result<StartSessionResponse, Status>),
            >,
        > = self.nodes.iter().enumerate().map(
            |(identifier, node): (usize, &NodeIpcClient)| {
                let request: StartSigningSessionRequest =
                    StartSigningSessionRequest {
                        // Scope the key identifier per participant to locate
                        // the correct key share in Vault.
                        key_identifier: format!(
                            "{}/{}",
                            self.key_identifier.trim_end_matches('/'),
                            identifier
                        ),
                        algorithm: self.algorithm.as_str().to_string(),
                        threshold: self.threshold,
                        participants: self.participants,
                        message: self.message.clone(),
                    };
                async move { (identifier, node.start_signing(request).await) }
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
                targets.into_iter().map(move |node_identifier: u32| {
                    (node_identifier, message)
                })
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

        // Submit all messages in parallel — avoids sequential latency for n
        // nodes. Each node receives a batch of messages targeted to it in the
        // same round, reducing the number of gRPC calls per round.
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

    /// Poll all active node sessions for outgoing messages, backing off until
    /// at least one node produces output or all nodes signal completion.
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
            // Poll all nodes in parallel — avoids sequential latency for n
            // nodes and allows us to react as soon as the first node produces
            // output instead of waiting for sequential round-trips per node.
            // Skip nodes that have already signaled completion to avoid
            // unnecessary gRPC calls.
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

            // Yield to the tokio runtime before retrying — avoids busy-waiting
            // while allowing other tasks to make progress.
            yield_now().await;
        }

        Ok(queue)
    }

    /// Drive the full protocol execution loop until all nodes complete.
    ///
    /// Starts all sessions, then alternates between submitting outgoing
    /// messages and collecting responses until all nodes signal done.
    ///
    /// # Errors
    /// * `Errors::Generic` - If any gRPC call fails during the protocol.
    async fn run_protocol(&mut self) -> Result<(), Errors> {
        tracing::debug!("Starting signing protocol execution.");

        let mut queue: VecDeque<RoundMessage> = self.start_sessions().await?;
        let mut all_done: Vec<bool> = vec![false; self.nodes.len()];

        loop {
            // Submit all pending outgoing messages to their target nodes.
            let batch: Vec<RoundMessage> = queue.drain(..).collect();
            self.submit_batch(batch).await?;

            // Collect responses — blocks until at least one node produces
            // output or all nodes are done.
            queue = self.collect_round(&mut all_done).await?;

            if all_done.iter().all(|done: &bool| *done) && queue.is_empty() {
                break;
            }

            self.round += 1;
        }

        self.output = Some(self.finalize_all().await?);

        Ok(())
    }

    /// Finalize all node sessions in parallel and extract the signing output.
    ///
    /// All nodes should produce the same signature — only the first is used
    /// since CGGMP24 guarantees deterministic output across participants.
    ///
    /// # Errors
    /// * `Errors::InvalidMessage` - If any node returns an unexpected output.
    ///
    /// # Returns
    /// * `ProtocolOutput` - The final signature output.
    async fn finalize_all(&mut self) -> Result<ProtocolOutput, Errors> {
        tracing::debug!("Finalizing all signing sessions.");

        let futures: impl Iterator<
            Item = impl Future<Output = Result<FinalizeSessionResponse, Errors>>,
        > = self.sessions.iter().enumerate().filter_map(
            |(index, session_identifier): (usize, &String)| {
                self.nodes.get(index).map(|node: &NodeIpcClient| async move {
                    node.finalize(session_identifier.clone())
                        .await
                        .map_err(map_status)
                })
            },
        );

        let responses: Vec<FinalizeSessionResponse> = join_all(futures)
            .await
            .into_iter()
            .collect::<Result<Vec<FinalizeSessionResponse>, Errors>>()?;

        // All nodes produce the same output — take the first valid signature.
        let final_signature: FinalOutput = responses
            .into_iter()
            .find_map(|response: FinalizeSessionResponse| {
                response.final_output
            })
            .ok_or_else(|| {
                Errors::InvalidMessage("No finalize output received.".into())
            })?;

        match final_signature {
            FinalOutput::Signature(result) => {
                let signature: FinalSignature =
                    result.final_signature.ok_or_else(|| {
                        Errors::InvalidMessage(
                            "Node returned signing output without final \
                            signature."
                                .into(),
                        )
                    })?;
                Ok(ProtocolOutput::Signature(signature))
            },
            other => Err(Errors::InvalidMessage(format!(
                "Unexpected finalize output variant: {:?}",
                other
            ))),
        }
    }
}

#[async_trait]
impl Protocol for Cggmp24EcdsaSecp256k1ControllerSigning {
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

    /// Drive the full signing protocol to completion.
    ///
    /// Called once at round 0 — orchestrates all node communication
    /// internally via `run_protocol`. Subsequent calls return `Ok(None)`.
    ///
    /// # Errors
    /// * `Errors::Aborted` - If the protocol has been aborted.
    /// * `Errors::Generic` - If any gRPC call fails during execution.
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

    /// No-op — the controller DKG protocol is fully orchestrated within
    /// `next_round` and does not handle individual messages.
    async fn handle_message(
        &mut self,
        _message: RoundMessage,
    ) -> Result<Option<RoundMessage>, Errors> {
        Ok(None)
    }

    /// Return the final signing output produced by `next_round`.
    ///
    /// Consumes the output — calling `finalize` twice will return an error.
    ///
    /// # Errors
    /// * `Errors::InvalidState` - If `next_round` has not completed yet.
    ///
    /// # Returns
    /// * `ProtocolOutput` - The final aggregated signature.
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
