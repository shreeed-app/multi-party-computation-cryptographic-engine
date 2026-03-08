//! FROST controller-side key generation task.

use std::collections::{BTreeMap, HashMap};

use async_trait::async_trait;
use futures::stream::{FuturesUnordered, StreamExt};

use crate::{
    proto::signer::v1::{
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
    /// participant identifiers.identifier
    /// Outer key = sender participant identifier.
    /// Inner key = recipient participant identifier.
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

    /// Get a mutable reference to the node client corresponding to the given
    /// participant identifier.
    ///
    /// # Arguments
    /// * `identifier` (`u32`) - Participant identifier.
    ///
    /// # Errors
    /// * `Errors::InvalidParticipant` - If no node client with the given
    ///   participant identifier is found.
    ///
    /// # Returns
    /// * `&mut NodeIpcClient` - Mutable reference to the corresponding node
    ///   client.
    fn node_mut(
        &mut self,
        identifier: u32,
    ) -> Result<&mut NodeIpcClient, Errors> {
        self.nodes
            .iter_mut()
            .find(|node: &&mut NodeIpcClient| {
                node.participant_id() == Some(identifier)
            })
            .ok_or(Errors::InvalidParticipant(format!(
                "Participant identifer {} not found among node clients.",
                identifier
            )))
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
        let identifiers: Vec<u32> = self.node_identifiers()?;

        let mut futures: FuturesUnordered<
            impl Future<Output = Result<(u32, StartSessionResponse), Errors>>,
        > = FuturesUnordered::new();

        for identifier in identifiers {
            let node: NodeIpcClient = self.node_mut(identifier)?.clone();

            // Each node stores its key share under "<key_id>/<participant_id>"
            // to avoid collisions in Vault.
            let request: StartKeyGenerationSessionRequest =
                StartKeyGenerationSessionRequest {
                    key_identifier: format!(
                        "{}/{}",
                        self.key_identifier, identifier
                    ),
                    algorithm: self.algorithm.as_str().to_string(),
                    threshold: self.threshold,
                    participants: self.participants,
                    identifier,
                };

            futures.push(async move {
                let response: StartSessionResponse = node
                    .start_key_generation(request)
                    .await
                    .map_err(map_status)?;

                Ok::<(u32, StartSessionResponse), Errors>((
                    identifier, response,
                ))
            });
        }

        // Collect round 1 packages from all nodes as they complete. Each node
        // must return exactly one round 1 package. If not, the protocol cannot
        // proceed.
        while let Some(result) = futures.next().await {
            let (identifier, response): (u32, StartSessionResponse) = result?;

            self.sessions.insert(identifier, response.session_identifier);

            let wire: FrostWire = decode_wire(
                &response
                    .messages
                    .first()
                    .ok_or(Errors::InvalidMessage(
                        "Missing round 1 message in start session response."
                            .into(),
                    ))?
                    .payload,
            )
            .map_err(|error: Errors| {
                Errors::InvalidMessage(format!(
                    "Failed to decode FROST wire message: {}.",
                    error
                ))
            })?;

            match wire {
                FrostWire::DkgRound1Package { identifier, package } => {
                    self.round1_packages.insert(identifier, package);
                },
                _ => {
                    return Err(Errors::InvalidMessage(
                        "Unexpected FROST wire message in round 1.".into(),
                    ));
                },
            }
        }

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

        let mut futures: FuturesUnordered<
            impl Future<Output = Result<(u32, SubmitRoundResponse), Errors>>,
        > = FuturesUnordered::new();

        for (identifier, session_identifier) in self.sessions.clone() {
            let node: NodeIpcClient = self.node_mut(identifier)?.clone();
            let payload: Vec<u8> = payload.clone();

            futures.push(async move {
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
                Ok::<_, Errors>((identifier, response))
            });
        }

        // Collect round 2 packages from all nodes as they complete. Each node
        // must return exactly one round 2 package output. If not, the protocol
        // cannot proceed.
        while let Some(result) = futures.next().await {
            let (identifier, response): (u32, SubmitRoundResponse) = result?;

            let wire: FrostWire = decode_wire(
                &response
                    .messages
                    .first()
                    .ok_or(Errors::InvalidMessage(
                        "Missing round 2 message in submit round response."
                            .into(),
                    ))?
                    .payload,
            )
            .map_err(|error: Errors| {
                Errors::InvalidMessage(format!(
                    "Failed to decode FROST wire message: {}",
                    error
                ))
            })?;

            match wire {
                FrostWire::DkgRound2PackagesOutput { packages } => {
                    // Store packages keyed by (sender, recipient) for
                    // targeted delivery in broadcast_round2.
                    let from_packages =
                        self.round2_packages.entry(identifier).or_default();
                    for (to_id, package) in packages {
                        from_packages.insert(to_id, package);
                    }
                },
                _ => {
                    return Err(Errors::InvalidMessage(
                        "Unexpected FROST wire message in round 2 output."
                            .into(),
                    ));
                },
            }
        }

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

        let mut futures: FuturesUnordered<
            impl Future<Output = Result<(), Errors>>,
        > = FuturesUnordered::new();

        for (identifier, session_identifier) in self.sessions.clone() {
            // Collect all packages destined for this node (one per sender).
            let mut packages_for_node: Vec<(u32, Vec<u8>)> = Vec::new();
            for (from_identifier, recipients) in &self.round2_packages {
                if let Some(package) = recipients.get(&identifier) {
                    packages_for_node
                        .push((*from_identifier, package.clone()));
                }
            }

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

            let node: NodeIpcClient = self.node_mut(identifier)?.clone();

            futures.push(async move {
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
            });
        }

        // Wait for all round 2 broadcasts to complete. If any fail, the
        // protocol cannot proceed to finalization.
        while let Some(result) = futures.next().await {
            result?;
        }

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
        let mut futures: FuturesUnordered<
            impl Future<Output = Result<(Vec<u8>, Vec<u8>), Errors>>,
        > = FuturesUnordered::new();

        for (identifier, session_identifier) in self.sessions.clone() {
            let node: NodeIpcClient = self.node_mut(identifier)?.clone();

            futures.push(async move {
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
            });
        }

        let mut public_keys: Vec<Vec<u8>> = Vec::new();
        let mut public_key_packages: Vec<Vec<u8>> = Vec::new();

        while let Some(result) = futures.next().await {
            let (public_key, public_key_package) = result?;
            public_keys.push(public_key);
            public_key_packages.push(public_key_package);
        }

        let first_public_key: Vec<u8> = public_keys
            .first()
            .ok_or(Errors::InvalidState("No public keys received.".into()))?
            .clone();

        let first_package: Vec<u8> = public_key_packages
            .first()
            .ok_or(Errors::InvalidState(
                "No public key packages received.".into(),
            ))?
            .clone();

        // All nodes must produce the same public key and public key package —
        // any mismatch indicates a protocol error or tampering.
        for (index, (public_key, package)) in
            public_keys.iter().zip(public_key_packages.iter()).enumerate()
        {
            if *public_key != first_public_key {
                return Err(Errors::InvalidState(format!(
                    "Public key mismatch at node index {}.",
                    index
                )));
            }
            if *package != first_package {
                return Err(Errors::InvalidState(format!(
                    "Public key package mismatch at node index {}.",
                    index
                )));
            }
        }

        self.output = Some(ProtocolOutput::KeyGeneration {
            key_identifier: self.key_identifier.clone(),
            key_share: None,
            public_key: first_public_key,
            public_key_package: first_package,
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
        Ok(None)
    }

    async fn finalize(&mut self) -> Result<ProtocolOutput, Errors> {
        self.output
            .take()
            .ok_or(Errors::InvalidState("Protocol not finished.".into()))
    }

    fn abort(&mut self) {
        self.aborted = true;
    }
}
