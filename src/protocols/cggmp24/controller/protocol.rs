//! Generic CGGMP24 controller protocol driver.
//!
//! Handles the common session lifecycle shared across all CGGMP24 controller
//! protocols (key generation, auxiliary generation, signing).
//! Protocol-specific session startup and output finalization are delegated to
//! `C`.

use std::collections::VecDeque;

use futures::future::join_all;
use tokio::task::yield_now;
use tonic::Status;

use crate::{
    proto::signer::v1::{
        CollectRoundResponse,
        FinalizeSessionResponse,
        RoundMessage,
        SubmitRoundRequest,
        SubmitRoundResponse,
    },
    protocols::types::ProtocolOutput,
    transport::{
        errors::{Errors, map_status},
        grpc::node_client::NodeIpcClient,
    },
};

/// Abstracts over CGGMP24 controller protocol variants (key generation,
/// auxiliary generation, signing). Each variant implements this trait to
/// provide its concrete session startup and output finalization logic.
pub trait CggmpControllerProtocol: Send + 'static {
    /// Protocol-specific data needed for session startup and finalization
    /// (e.g. key identifier, message, threshold).
    type Data: Send + 'static;

    /// Total number of participants in the protocol.
    ///
    /// # Arguments
    /// * `data` (`&Self::Data`) - Protocol-specific data.
    ///
    /// # Returns
    /// * `u32` - The number of participants.
    fn participants(data: &Self::Data) -> u32;

    /// Start a session on a single node and return its initial messages.
    ///
    /// Called in parallel across all nodes during `start_sessions`. The
    /// `index` parameter is the node's participant index in `[0, n)`.
    ///
    /// # Arguments
    /// * `data` (`&Self::Data`) - Protocol-specific data.
    /// * `index` (`usize`) - This node's participant index.
    /// * `node` (`&NodeIpcClient`) - The gRPC client for this node.
    ///
    /// # Errors
    /// * `Status` - If the gRPC call fails.
    ///
    /// # Returns
    /// * `(String, Vec<RoundMessage>, Vec<u32>)` - The session identifier,
    ///   initial outgoing messages, and the signer set derived by the node
    ///   (empty for non-signing protocols or non-CGGMP24 algorithms).
    fn start_session(
        data: &Self::Data,
        index: usize,
        node: &NodeIpcClient,
    ) -> impl Future<
        Output = Result<(String, Vec<RoundMessage>, Vec<u32>), Status>,
    > + Send;

    /// Finalize all node sessions and extract the protocol output.
    ///
    /// Called once after all nodes have signaled completion. Receives the
    /// full list of finalize responses from all nodes.
    ///
    /// # Arguments
    /// * `data` (`&Self::Data`) - Protocol-specific data.
    /// * `responses` (`Vec<FinalizeSessionResponse>`) - Finalize responses
    ///   from all nodes, in participant order.
    ///
    /// # Errors
    /// * `Errors::InvalidMessage` - If any node returns an unexpected output.
    ///
    /// # Returns
    /// * `ProtocolOutput` - The final protocol output.
    fn finalize_output(
        data: &Self::Data,
        responses: Vec<FinalizeSessionResponse>,
    ) -> Result<ProtocolOutput, Errors>;
}

/// Generic CGGMP24 controller protocol driver.
///
/// Handles the common session lifecycle shared across all CGGMP24 controller
/// protocols. Protocol-specific session startup and output finalization are
/// delegated to `C`.
pub struct Cggmp24ControllerProtocol<C: CggmpControllerProtocol> {
    /// Protocol-specific data (key identifier, threshold, message, etc.)
    pub data: C::Data,
    /// gRPC clients for communicating with participant nodes, indexed by
    /// participant order.
    nodes: Vec<NodeIpcClient>,
    /// Active session identifiers returned by each node at session start,
    /// indexed by participant order.
    sessions: Vec<String>,
    /// Final protocol output, populated by `run` and consumed by
    /// `take_output`.
    output: Option<ProtocolOutput>,
    /// Current protocol round, incremented after each batch of messages is
    /// dispatched.
    pub round: u32,
    /// Whether the protocol has been aborted.
    pub aborted: bool,
}

impl<C: CggmpControllerProtocol> Cggmp24ControllerProtocol<C> {
    /// Create a new controller protocol driver.
    ///
    /// # Arguments
    /// * `data` (`C::Data`) - Protocol-specific data.
    /// * `nodes` (`Vec<NodeIpcClient>`) - gRPC clients for all participant
    ///   nodes, indexed by participant order.
    pub fn new(data: C::Data, nodes: Vec<NodeIpcClient>) -> Self {
        Self {
            data,
            nodes,
            sessions: Vec::new(),
            output: None,
            round: 0,
            aborted: false,
        }
    }

    /// Start sessions on all nodes in parallel and collect initial outgoing
    /// messages from each.
    ///
    /// Responses are sorted by participant index before registering sessions
    /// to guarantee a consistent ordering in `self.sessions`.
    ///
    /// For CGGMP24 signing, each node reports the signer set it derived
    /// locally. This function verifies that all reported sets are identical —
    /// a mismatch indicates a configuration inconsistency that would cause the
    /// protocol to fail non-deterministically.
    ///
    /// # Errors
    /// * `Errors::Generic` - If any gRPC session start request fails.
    /// * `Errors::InvalidParticipant` - If nodes derived inconsistent signer
    ///   sets.
    ///
    /// # Returns
    /// * `VecDeque<RoundMessage>` - Initial message queue from all nodes.
    async fn start_sessions(
        &mut self,
    ) -> Result<VecDeque<RoundMessage>, Errors> {
        // Start all sessions in parallel — avoids sequential latency for
        // n nodes.
        let futures: impl Iterator<
            Item = impl Future<
                Output = (
                    usize,
                    Result<(String, Vec<RoundMessage>, Vec<u32>), Status>,
                ),
            >,
        > = self.nodes.iter().enumerate().map(
            |(index, node): (usize, &NodeIpcClient)| {
                let future: impl Future<
                    Output = Result<
                        (String, Vec<RoundMessage>, Vec<u32>),
                        Status,
                    >,
                > = C::start_session(&self.data, index, node);
                async move { (index, future.await) }
            },
        );

        let mut responses: Vec<(
            usize,
            Result<(String, Vec<RoundMessage>, Vec<u32>), Status>,
        )> = join_all(futures).await;

        // Sort by index to ensure sessions are registered in participant
        // order.
        responses.sort_by_key(
            |(index, _): &(
                usize,
                Result<(String, Vec<RoundMessage>, Vec<u32>), Status>,
            )| { *index },
        );

        let (queue, signer_sets): (VecDeque<RoundMessage>, Vec<Vec<u32>>) =
            responses.into_iter().try_fold(
                (VecDeque::new(), Vec::new()),
                |(mut queue, mut signer_sets): (
                    VecDeque<RoundMessage>,
                    Vec<Vec<u32>>,
                ),
                 (index, result): (
                    usize,
                    Result<(String, Vec<RoundMessage>, Vec<u32>), Status>,
                )| {
                    let (session_identifier, messages, signer_set): (
                        String,
                        Vec<RoundMessage>,
                        Vec<u32>,
                    ) = result.map_err(map_status)?;

                    // Register the session identifier for this node — used by
                    // submit_batch and collect_round to route messages.
                    self.sessions.push(session_identifier);

                    // Tag each message with the sender's participant index —
                    // required for routing in build_submit_requests.
                    queue.extend(messages.into_iter().map(
                        |mut message: RoundMessage| {
                            message.from = Some(index as u32);
                            message
                        },
                    ));

                    // Collect non-empty signer sets for consistency
                    // verification after all sessions are started.
                    if !signer_set.is_empty() {
                        signer_sets.push(signer_set);
                    }

                    Ok::<(VecDeque<RoundMessage>, Vec<Vec<u32>>), Errors>((
                        queue,
                        signer_sets,
                    ))
                },
            )?;

        // Verify all nodes derived the same signer set. A mismatch means at
        // least one node used different inputs (e.g. different key_identifier
        // or participant count) and would fail the protocol with an opaque
        // error rather than a clear diagnostic.
        if let Some(first) = signer_sets.first()
            && !signer_sets.iter().all(|set: &Vec<u32>| set == first)
        {
            return Err(Errors::InvalidParticipant(
                "Nodes computed inconsistent signer sets — verify that \
                    all nodes share the same key_identifier, threshold, and \
                    participant count."
                    .into(),
            ));
        }

        Ok(queue)
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
        let participants: u32 = C::participants(&self.data);

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
                    None => (0..participants)
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

            // Yield to the Tokio runtime before retrying — avoids busy-waiting
            // while allowing other tasks to make progress.
            yield_now().await;
        }

        Ok(queue)
    }

    /// Finalize all node sessions in parallel and collect responses.
    ///
    /// # Errors
    /// * `Errors::Generic` - If any finalize gRPC call fails.
    ///
    /// # Returns
    /// * `Vec<FinalizeSessionResponse>` - Finalize responses from all nodes,
    ///   in participant order.
    async fn finalize_sessions(
        &self,
    ) -> Result<Vec<FinalizeSessionResponse>, Errors> {
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
        .collect::<Result<Vec<FinalizeSessionResponse>, Errors>>()
    }

    /// Drive the full protocol execution loop until all nodes complete, then
    /// finalize and store the output.
    ///
    /// Starts all sessions, then alternates between submitting outgoing
    /// messages and collecting responses until all nodes signal done and the
    /// message queue is empty.
    ///
    /// # Errors
    /// * Any error propagated from `start_sessions`, `submit_batch`,
    ///   `collect_round`, or `C::finalize_output`.
    pub async fn run(&mut self) -> Result<(), Errors> {
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

        // Finalize all sessions and delegate output extraction to the
        // protocol-specific implementation.
        let responses: Vec<FinalizeSessionResponse> =
            self.finalize_sessions().await?;

        self.output = Some(C::finalize_output(&self.data, responses)?);

        Ok(())
    }

    /// Consume and return the final protocol output.
    ///
    /// Returns `None` if `run` has not completed yet.
    ///
    /// # Returns
    /// * `Option<ProtocolOutput>` - The final protocol output if available.
    pub fn take_output(&mut self) -> Option<ProtocolOutput> {
        self.output.take()
    }
}
