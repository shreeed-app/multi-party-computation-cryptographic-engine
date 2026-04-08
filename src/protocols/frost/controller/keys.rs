//! FROST controller-side key generation task.

use std::collections::{BTreeMap, HashMap};

use async_trait::async_trait;
use futures::stream::{FuturesUnordered, StreamExt};

use crate::{
    proto::engine::v1::{
        Algorithm,
        FinalizeSessionResponse,
        RoundMessage,
        StartKeyGenerationSessionRequest,
        StartSessionResponse,
        SubmitRoundRequest,
        SubmitRoundResponse,
        finalize_session_response::FinalOutput,
    },
    protocols::{
        codec::{decode_wire, encode_wire},
        frost::wire::FrostWire,
        protocol::Protocol,
        types::{
            ControllerKeyGenerationInit,
            KeyGenerationInit,
            ProtocolInit,
            ProtocolOutput,
            Round,
        },
    },
    secrets::vault::key_path::scoped,
    transport::{
        errors::{Errors, map_status},
        grpc::node_client::NodeIpcClient,
    },
};

/// Controller-side FROST key generation protocol instance.
///
/// Orchestrates the 3-round DKG across all nodes:
/// - Round 0: start sessions, collect round 1 packages from nodes.
/// - Round 1: broadcast all round 1 packages to each node, collect round 2
///   packages in response.
/// - Round 2: deliver each node's round 2 packages, then finalize.
pub struct FrostControllerKeyGeneration {
    /// Algorithm (FROST).
    algorithm: Algorithm,
    /// Unique key identifier.
    key_identifier: String,
    /// Threshold number of participants required to reconstruct the key.
    threshold: u32,
    /// Total number of participants in the protocol.
    participants: u32,
    /// Node clients representing the participants.
    nodes: Vec<NodeIpcClient>,
    /// Current protocol round.
    round: Round,
    /// Mapping of participant identifier to session identifier for each node
    /// client.
    sessions: HashMap<u32, String>,
    /// Round 1 packages received from nodes, indexed by participant
    /// identifier.
    round1_packages: BTreeMap<u32, Vec<u8>>,
    /// Round 2 packages received from nodes, indexed by (from, to)
    /// participant identifiers.
    /// Outer key = recipient participant identifier.
    /// Inner key = sender participant identifier.
    round2_packages: BTreeMap<u32, BTreeMap<u32, Vec<u8>>>,
    /// Final protocol output, set after successful completion of the
    /// protocol.
    output: Option<ProtocolOutput>,
    /// Flag indicating whether the protocol has been aborted.
    aborted: bool,
}

impl FrostControllerKeyGeneration {
    /// Try to create a new FROST controller key generation protocol
    /// instance from the given initialization context.
    ///
    /// # Arguments
    /// * `protocol_init` (`ProtocolInit`) - The protocol initialization
    ///   context.
    ///
    /// # Errors
    /// * `Errors::InvalidProtocolInit` - If the initialization context is
    ///   invalid for this protocol.
    pub fn try_new(protocol_init: ProtocolInit) -> Result<Self, Errors> {
        let init: ControllerKeyGenerationInit = match protocol_init {
            ProtocolInit::KeyGeneration(KeyGenerationInit::Controller(
                init,
            )) => init,
            _ => {
                return Err(Errors::InvalidProtocolInit(
                    "Invalid protocol initialization context for FROST \
                    controller key generation."
                        .into(),
                ));
            },
        };

        Ok(Self {
            algorithm: init.common.algorithm,
            key_identifier: init.common.key_identifier,
            threshold: init.common.threshold,
            participants: init.common.participants,
            nodes: init.nodes,
            round: 0,
            sessions: HashMap::new(),
            round1_packages: BTreeMap::new(),
            round2_packages: BTreeMap::new(),
            output: None,
            aborted: false,
        })
    }

    /// Extract participant identifiers from node clients and ensure they match
    /// the expected number of participants.
    ///
    /// # Errors
    /// * `Errors::InvalidParticipant` - If participant identifiers cannot be
    ///   extracted or if the number of node clients does not match the
    ///   expected number of participants.
    ///
    /// # Returns
    /// * `Vec<u32>` - Sorted list of participant identifiers.
    fn node_identifiers(&self) -> Result<Vec<u32>, Errors> {
        let mut identifiers: Vec<u32> = self
            .nodes
            .iter()
            .map(|node: &NodeIpcClient| {
                node.participant_id().ok_or(Errors::InvalidParticipant(
                    "Failed to extract participant identifier from node \
                    client."
                        .into(),
                ))
            })
            .collect::<Result<Vec<u32>, Errors>>()?;

        identifiers.sort();

        // Ensure the number of node clients matches the expected number of
        // participants. If not, the protocol cannot proceed.
        if identifiers.len() != self.participants as usize {
            return Err(Errors::InvalidParticipant(
                "Number of node clients does not match number of participants."
                    .into(),
            ));
        }

        Ok(identifiers)
    }

    /// Get a cloned node client for the given participant identifier.
    ///
    /// Cloned to allow use inside async closures without holding a mutable
    /// reference across await points.
    ///
    /// # Errors
    /// * `Errors::InvalidParticipant` - If no node with the given identifier
    ///   is found.
    ///
    /// # Returns
    /// * `NodeIpcClient` - A clone of the node client corresponding to the
    ///   given participant identifier.
    fn node_clone(&self, identifier: u32) -> Result<NodeIpcClient, Errors> {
        self.nodes
            .iter()
            .find(|node: &&NodeIpcClient| {
                node.participant_id() == Some(identifier)
            })
            .cloned()
            .ok_or_else(|| {
                Errors::InvalidParticipant(format!(
                    "Participant identifier {} not found among node clients.",
                    identifier
                ))
            })
    }

    /// Decode a `FrostWire::DkgRound1Package` message and return the typed
    /// identifier-package pair.
    ///
    /// Extracted to keep `collect_round1` free of inline match arms.
    ///
    /// # Arguments
    /// * `payload` (`&[u8]`) - Raw wire payload from the round 0 response.
    ///
    /// # Errors
    /// * `Errors::InvalidMessage` - If the wire message cannot be decoded or
    ///   is not of the expected `DkgRound1Package` variant.
    ///
    /// # Returns
    /// * `(u32, Vec<u8>)` - The identifier-package pair extracted from the
    ///   wire message.
    fn decode_round1_package(
        payload: &[u8],
    ) -> Result<(u32, Vec<u8>), Errors> {
        match decode_wire(payload).map_err(|error: Errors| {
            Errors::InvalidMessage(format!(
                "Failed to decode FROST wire message: {}.",
                error
            ))
        })? {
            FrostWire::DkgRound1Package { identifier, package } => {
                Ok((identifier, package))
            },
            _ => Err(Errors::InvalidMessage(
                "Unexpected FROST wire message in round 1.".into(),
            )),
        }
    }

    /// Decode a `FrostWire::DkgRound2PackagesOutput` message and return the
    /// list of (recipient, package) pairs.
    ///
    /// Extracted to keep `broadcast_round1` free of inline match arms.
    ///
    /// # Arguments
    /// * `payload` (`&[u8]`) - Raw wire payload from the round 1 response.
    ///
    /// # Errors
    /// * `Errors::InvalidMessage` - If the wire message cannot be decoded or
    ///   is not of the expected `DkgRound2PackagesOutput` variant.
    ///
    /// # Returns
    /// * `Vec<(u32, Vec<u8>)>` - The list of (recipient, package) pairs
    ///   extracted from the wire message.
    fn decode_round2_packages_output(
        payload: &[u8],
    ) -> Result<Vec<(u32, Vec<u8>)>, Errors> {
        match decode_wire(payload).map_err(|error: Errors| {
            Errors::InvalidMessage(format!(
                "Failed to decode FROST wire message: {}",
                error
            ))
        })? {
            FrostWire::DkgRound2PackagesOutput { packages } => Ok(packages),
            _ => Err(Errors::InvalidMessage(
                "Unexpected FROST wire message in round 2 output.".into(),
            )),
        }
    }

    /// Start key generation sessions on all nodes in parallel and collect
    /// their round 1 packages.
    ///
    /// Each node is started with a distinct key identifier
    /// (`<key_id>/<participant_id>`) to avoid Vault collisions when
    /// storing key shares.
    ///
    /// # Errors
    /// * `Errors::InvalidMessage` - If decoding messages from nodes fails or
    ///   the expected round 1 package is missing.
    async fn collect_round1(&mut self) -> Result<(), Errors> {
        let futures: FuturesUnordered<_> = self
            .node_identifiers()?
            .into_iter()
            .map(|identifier: u32| {
                let node: NodeIpcClient = self.node_clone(identifier)?;

                // Each node stores its key share under
                // "<key_id>/<participant_id>" to avoid collisions in Vault.
                let request: StartKeyGenerationSessionRequest =
                    StartKeyGenerationSessionRequest {
                        key_identifier: scoped(
                            &self.key_identifier,
                            identifier,
                        ),
                        algorithm: self.algorithm.into(),
                        threshold: self.threshold,
                        participants: self.participants,
                        identifier,
                    };

                Ok(async move {
                    let response: StartSessionResponse = node
                        .start_key_generation(request)
                        .await
                        .map_err(map_status)?;

                    Ok::<(u32, StartSessionResponse), Errors>((
                        identifier, response,
                    ))
                })
            })
            .collect::<Result<FuturesUnordered<_>, Errors>>()?;

        // Collect round 1 packages from all nodes as they complete. Each node
        // must return exactly one round 1 package. If not, the protocol cannot
        // proceed.
        let results: Vec<(u32, StartSessionResponse)> = futures
            .collect::<Vec<Result<_, _>>>()
            .await
            .into_iter()
            .collect::<Result<Vec<_>, _>>()?;

        self.sessions = results
            .iter()
            .map(|(identifier, response): &(u32, StartSessionResponse)| {
                (*identifier, response.session_identifier.clone())
            })
            .collect();

        self.round1_packages = results
            .iter()
            .map(|(_, response): &(u32, StartSessionResponse)| {
                let payload: &[u8] = &response
                    .messages
                    .first()
                    .ok_or(Errors::InvalidMessage(
                        "Missing round 1 message in start session response."
                            .into(),
                    ))?
                    .payload;
                Self::decode_round1_package(payload)
            })
            .collect::<Result<BTreeMap<_, _>, _>>()?;

        Ok(())
    }

    /// Broadcast all round 1 packages to each node in parallel and collect
    /// their round 2 packages in response.
    ///
    /// The controller aggregates all round 1 packages received from all nodes
    /// and delivers them as a single batch to each node. Each node then
    /// computes its round 2 packages (one per other participant) and returns
    /// them.
    ///
    /// # Errors
    /// * `Errors::InvalidMessage` - If decoding messages from nodes fails or
    ///   the expected round 2 package output is missing.
    async fn broadcast_round1(&mut self) -> Result<(), Errors> {
        // Aggregate all round 1 packages into a single batch payload.
        let packages: Vec<(u32, Vec<u8>)> = self
            .round1_packages
            .iter()
            .map(|(identifier, package): (&u32, &Vec<u8>)| {
                (*identifier, package.clone())
            })
            .collect();

        let payload: Vec<u8> =
            encode_wire(&FrostWire::DkgRound1Packages { packages })?;

        let futures: FuturesUnordered<_> = self
            .sessions
            .iter()
            .map(|(&identifier, session_identifier): (&u32, &String)| {
                let node: NodeIpcClient = self.node_clone(identifier)?;
                let payload: Vec<u8> = payload.clone();
                let session_identifier: String = session_identifier.clone();

                Ok(async move {
                    let response: SubmitRoundResponse = node
                        .submit_round(SubmitRoundRequest {
                            session_identifier,
                            round: 1,
                            from: None,
                            to: Some(identifier),
                            payload,
                        })
                        .await
                        .map_err(map_status)?;

                    let payload: &[u8] = &response
                        .messages
                        .first()
                        .ok_or(Errors::InvalidMessage(
                            "Missing round 2 message in submit round response."
                                .into(),
                        ))?
                        .payload;

                    let packages: Vec<(u32, Vec<u8>)> =
                        Self::decode_round2_packages_output(payload)?;

                    Ok::<(u32, Vec<(u32, Vec<u8>)>), Errors>((
                        identifier, packages,
                    ))
                })
            })
            .collect::<Result<FuturesUnordered<_>, Errors>>()?;

        // Collect round 2 packages from all nodes as they complete. Each node
        // must return exactly one round 2 package output. If not, the protocol
        // cannot proceed.
        let results: Vec<(u32, Vec<(u32, Vec<u8>)>)> = futures
            .collect::<Vec<Result<_, _>>>()
            .await
            .into_iter()
            .collect::<Result<Vec<_>, _>>()?;

        // Store packages keyed by (recipient, sender) for targeted delivery
        // in broadcast_round2.
        results
            .into_iter()
            .flat_map(|(sender, packages): (u32, Vec<(u32, Vec<u8>)>)| {
                packages.into_iter().map(
                    move |(recipient, package): (u32, Vec<u8>)| {
                        (recipient, sender, package)
                    },
                )
            })
            .for_each(|(recipient, sender, package): (u32, u32, Vec<u8>)| {
                self.round2_packages
                    .entry(recipient)
                    .or_default()
                    .insert(sender, package);
            });

        Ok(())
    }

    /// Deliver each node's round 2 packages to their intended recipients in
    /// parallel.
    ///
    /// Each node must receive exactly `participants - 1` packages — one from
    /// each other participant. If any are missing, the round 1 broadcast was
    /// incomplete.
    ///
    /// # Errors
    /// * `Errors::InvalidState` - If expected round 2 packages are missing for
    ///   any node.
    /// * `Errors::InvalidMessage` - If sending requests to nodes fails.
    async fn broadcast_round2(&mut self) -> Result<(), Errors> {
        let expected: usize = (self.participants as usize).saturating_sub(1);

        let futures: FuturesUnordered<_> = self
            .sessions
            .iter()
            .map(|(&identifier, session_identifier): (&u32, &String)| {
                let packages_for_node: Vec<(u32, Vec<u8>)> = self
                    .round2_packages
                    .get(&identifier)
                    .map(|senders: &BTreeMap<u32, Vec<u8>>| {
                        senders
                            .iter()
                            .map(|(from_id, package): (&u32, &Vec<u8>)| {
                                (*from_id, package.clone())
                            })
                            .collect()
                    })
                    .unwrap_or_default();

                // Each node must receive exactly one package from each other
                // participant — if not, round 1 broadcast was incomplete.
                if packages_for_node.len() != expected {
                    return Err(Errors::InvalidState(format!(
                        "Node {} expected {} round 2 packages, got {}.",
                        identifier,
                        expected,
                        packages_for_node.len()
                    )));
                }

                let payload: Vec<u8> =
                    encode_wire(&FrostWire::DkgRound2Packages {
                        packages: packages_for_node,
                    })?;

                let node: NodeIpcClient = self.node_clone(identifier)?;
                let session_identifier: String = session_identifier.clone();

                Ok(async move {
                    node.submit_round(SubmitRoundRequest {
                        session_identifier,
                        round: 2,
                        from: None,
                        to: Some(identifier),
                        payload,
                    })
                    .await
                    .map_err(map_status)?;

                    Ok::<(), Errors>(())
                })
            })
            .collect::<Result<FuturesUnordered<_>, Errors>>()?;

        // Wait for all round 2 broadcasts to complete. If any fail, the
        // protocol cannot proceed to finalization.
        futures
            .collect::<Vec<Result<_, _>>>()
            .await
            .into_iter()
            .collect::<Result<Vec<_>, _>>()?;

        Ok(())
    }

    /// Finalize all node sessions in parallel, verify that all nodes produced
    /// the same public key and public key package, then store the output.
    ///
    /// # Errors
    /// * `Errors::InvalidMessage` - If finalization responses are unexpected.
    /// * `Errors::InvalidState` - If public keys or packages are inconsistent
    ///   across nodes, or if no outputs were received.
    async fn collect_finalize(&mut self) -> Result<(), Errors> {
        let futures: FuturesUnordered<_> = self
            .sessions
            .iter()
            .map(|(&identifier, session_identifier): (&u32, &String)| {
                let node: NodeIpcClient = self.node_clone(identifier)?;
                let session_identifier: String = session_identifier.clone();

                Ok(async move {
                    let response: FinalizeSessionResponse = node
                        .finalize(session_identifier)
                        .await
                        .map_err(map_status)?;

                    match response.final_output {
                        Some(FinalOutput::KeyGeneration(result)) => {
                            Ok((result.public_key, result.public_key_package))
                        },
                        _ => Err(Errors::InvalidMessage(
                            "Unexpected final output from node.".into(),
                        )),
                    }
                })
            })
            .collect::<Result<FuturesUnordered<_>, Errors>>()?;

        let results: Vec<(Vec<u8>, Vec<u8>)> = futures
            .collect::<Vec<Result<_, _>>>()
            .await
            .into_iter()
            .collect::<Result<Vec<_>, _>>()?;

        let public_keys: Vec<&Vec<u8>> =
            results.iter().map(|(pk, _): &(Vec<u8>, Vec<u8>)| pk).collect();

        let public_key_packages: Vec<&Vec<u8>> =
            results.iter().map(|(_, pkg): &(Vec<u8>, Vec<u8>)| pkg).collect();

        // All nodes must produce the same public key and public key package —
        // any mismatch indicates a protocol error or tampering.
        if !public_keys.windows(2).all(|window: &[&Vec<u8>]| {
            match (window.first(), window.get(1)) {
                (Some(a), Some(b)) => a == b,
                _ => false, // This case is impossible.
            }
        }) {
            return Err(Errors::InvalidState(
                "Public key mismatch across nodes.".into(),
            ));
        }

        if !public_key_packages.windows(2).all(|window: &[&Vec<u8>]| {
            match (window.first(), window.get(1)) {
                (Some(a), Some(b)) => a == b,
                _ => false, // This case is impossible.
            }
        }) {
            return Err(Errors::InvalidState(
                "Public key package mismatch across nodes.".into(),
            ));
        }

        let (public_key, public_key_package): (Vec<u8>, Vec<u8>) =
            results.into_iter().next().ok_or(Errors::InvalidState(
                "No finalization outputs received.".into(),
            ))?;

        self.output = Some(ProtocolOutput::KeyGeneration {
            key_identifier: self.key_identifier.clone(),
            key_share: None,
            public_key,
            public_key_package,
        });

        Ok(())
    }
}

#[async_trait]
impl Protocol for FrostControllerKeyGeneration {
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

    /// Drive the full DKG protocol to completion synchronously.
    ///
    /// Called once by the controller engine at round 0. Orchestrates all
    /// node communication internally and returns `None` — the controller
    /// protocol produces no outgoing round messages itself.
    async fn next_round(&mut self) -> Result<Option<RoundMessage>, Errors> {
        if self.aborted {
            return Err(Errors::Aborted("Protocol has been aborted.".into()));
        }

        if self.round != 0 {
            return Ok(None);
        }

        self.round = 1;

        self.collect_round1().await?;
        self.broadcast_round1().await?;
        self.broadcast_round2().await?;
        self.collect_finalize().await?;

        self.round = 2;

        Ok(None)
    }

    async fn handle_message(
        &mut self,
        _message: RoundMessage,
    ) -> Result<Option<RoundMessage>, Errors> {
        // The controller DKG protocol is fully orchestrated within
        // `next_round` — `handle_message` and `finalize` are never
        // called concurrently and do not need abort checks.
        Ok(None)
    }

    async fn finalize(&mut self) -> Result<ProtocolOutput, Errors> {
        // See `handle_message` — abort is only checked in `next_round`.
        self.output
            .take()
            .ok_or(Errors::InvalidState("Protocol not finished.".into()))
    }

    fn abort(&mut self) {
        self.aborted = true;
    }
}
