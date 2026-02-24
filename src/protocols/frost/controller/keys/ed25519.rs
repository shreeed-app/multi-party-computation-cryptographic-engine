//! FROST-ed25519 controller-side key generation task.

use std::collections::{BTreeMap, HashMap};

use async_trait::async_trait;
use futures::stream::{FuturesUnordered, StreamExt};

use crate::{
    proto::signer::v1::{
        FinalizeSessionResponse,
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

/// Controller-side FROST(ed25519) key generation protocol instance.
pub struct FrostEd25519ControllerKeyGeneration {
    /// Algorithm (FROST-ed25519).
    algorithm: Algorithm,
    /// Unique key identifier.
    key_id: String,
    /// Threshold number of participants required to reconstruct the key.
    threshold: u32,
    /// Total number of participants in the protocol.
    participants: u32,
    /// Node clients representing the participants.
    nodes: Vec<NodeIpcClient>,
    /// Current protocol round.
    round: Round,
    /// Mapping of participant identifier to session ID for each node client.
    sessions: HashMap<u32, String>,
    /// Round 1 packages received from nodes, indexed by participant
    /// identifier.
    round1_packages: BTreeMap<u32, Vec<u8>>,
    /// Round 2 packages received from nodes, indexed by (from, to)
    /// participant identifiers.
    round2_packages: BTreeMap<(u32, u32), Vec<u8>>,
    /// Final protocol output, set after successful completion of the
    /// protocol.
    output: Option<ProtocolOutput>,
    /// Flag indicating whether the protocol has been aborted.
    aborted: bool,
}

impl FrostEd25519ControllerKeyGeneration {
    /// Try to create a new FROST(ed25519) controller key generation protocol
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
            _ => return Err(Errors::InvalidProtocolInit(
                "Invalid protocol initialization context for FROST(ed25519) 
                controller key generation."
                    .into(),
            )),
        };

        Ok(Self {
            algorithm: Algorithm::FrostEd25519,
            key_id: init.common.key_id,
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
    /// * `Errors::InvalidParticipant` - If participant IDs cannot be extracted
    ///   or if the number of node clients does not match the expected number
    ///   of participants.
    ///
    /// # Returns
    /// * `Vec<u32>` - Sorted list of participant identifiers.
    fn node_identifiers(&self) -> Result<Vec<u32>, Errors> {
        let mut identifiers: Vec<u32> = self
            .nodes
            .iter()
            .map(|node: &NodeIpcClient| {
                node.participant_id().ok_or(Errors::InvalidParticipant(
                    "Failed to extract participant ID from node client."
                        .into(),
                ))
            })
            .collect::<Result<Vec<_>, _>>()?;

        identifiers.sort();

        if identifiers.len() != self.participants as usize {
            return Err(Errors::InvalidParticipant(
                "Number of node clients does not match number of 
                participants."
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
                "Participant ID {} not found among node clients.",
                identifier
            )))
    }

    /// Collect round 1 packages from all nodes by starting key generation
    /// sessions and sending the initial requests.
    ///
    /// # Errors
    /// * `Errors::Aborted` - If sending requests to nodes fails.
    /// * `Errors::InvalidMessage` - If decoding messages from nodes fails.
    ///
    /// # Returns
    /// * `()` - Empty result on success.
    async fn collect_round1(&mut self) -> Result<(), Errors> {
        let identifiers: Vec<u32> = self.node_identifiers()?;

        let mut futures: FuturesUnordered<
            impl Future<Output = Result<(u32, StartSessionResponse), Errors>>,
        > = FuturesUnordered::new();

        for id in identifiers {
            let mut node: NodeIpcClient = self.node_mut(id)?.clone();

            let request: StartKeyGenerationSessionRequest =
                StartKeyGenerationSessionRequest {
                    key_id: format!("{}/{}", self.key_id, id),
                    algorithm: self.algorithm.as_str().to_string(),
                    threshold: self.threshold,
                    participants: self.participants,
                    identifier: id,
                };

            futures.push(async move {
                let response: StartSessionResponse = node
                    .start_key_generation(request)
                    .await
                    .map_err(map_status)?;
                Ok::<_, Errors>((id, response))
            });
        }

        while let Some(result) = futures.next().await {
            let (_id, response): (u32, StartSessionResponse) = result?;

            self.sessions.insert(_id, response.session_id);

            let wire: FrostWire =
                decode_wire(&response.payload).map_err(|error: Errors| {
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
                        "Unexpected FROST wire message.".into(),
                    ));
                },
            }
        }

        Ok(())
    }

    /// Broadcast round 1 and round 2 packages to all nodes.
    ///
    /// # Errors
    /// * `Errors::Aborted` - If sending requests to nodes fails.
    /// * `Errors::InvalidMessage` - If decoding messages from nodes fails.
    /// * `Errors::InvalidState` - If expected round 2 packages are missing for
    ///   any node.
    ///
    /// # Returns
    /// * `()` - Empty result on success.
    async fn broadcast_round1(&mut self) -> Result<(), Errors> {
        let packages: Vec<(u32, Vec<u8>)> = self
            .round1_packages
            .iter()
            .map(|(identifier, package): (&u32, &Vec<u8>)| {
                (*identifier, package.clone())
            })
            .collect();

        let payload: Vec<u8> =
            encode_wire(&FrostWire::DkgRound1Packages { packages })?;

        for (id, session_id) in self.sessions.clone() {
            let node: &mut NodeIpcClient = self.node_mut(id)?;

            let response: SubmitRoundResponse = node
                .submit_round(SubmitRoundRequest {
                    session_id,
                    round: 1,
                    from: None,
                    to: Some(id),
                    payload: payload.clone(),
                })
                .await
                .map_err(map_status)?;

            let wire: FrostWire =
                decode_wire(&response.payload).map_err(|error: Errors| {
                    Errors::InvalidMessage(format!(
                        "Failed to decode FROST wire message: {}",
                        error
                    ))
                })?;

            match wire {
                FrostWire::DkgRound2PackagesOutput { packages } => {
                    for (to_identifier, package) in packages {
                        self.round2_packages
                            .insert((id, to_identifier), package);
                    }
                },
                _ => {
                    return Err(Errors::InvalidMessage(
                        "Unexpected FROST wire message.".into(),
                    ));
                },
            }
        }

        Ok(())
    }

    /// Broadcast round 2 packages to all nodes.
    ///
    /// # Errors
    /// * `Errors::Aborted` - If sending requests to nodes fails.
    /// * `Errors::InvalidMessage` - If decoding messages from nodes fails.
    /// * `Errors::InvalidState` - If expected round 2 packages are missing for
    ///   any node.
    ///
    /// # Returns
    /// * `()` - Empty result on success.
    async fn broadcast_round2(&mut self) -> Result<(), Errors> {
        for (id, session_id) in self.sessions.clone() {
            let mut packages_for_node: Vec<(u32, Vec<u8>)> = Vec::new();

            for ((from, to), pkg) in &self.round2_packages.clone() {
                if *to == id {
                    packages_for_node.push((*from, pkg.clone()));
                }
            }

            if packages_for_node.len() != (self.participants - 1) as usize {
                return Err(Errors::InvalidState(
                    "Missing round2 packages for node".into(),
                ));
            }

            let payload = encode_wire(&FrostWire::DkgRound2Packages {
                packages: packages_for_node,
            })?;

            let node: &mut NodeIpcClient = self.node_mut(id)?;

            node.submit_round(SubmitRoundRequest {
                session_id,
                round: 2,
                from: None,
                to: Some(id),
                payload,
            })
            .await
            .map_err(map_status)?;
        }

        Ok(())
    }

    /// Collect final outputs from all nodes, verify consistency, and set the
    /// final protocol output.
    ///
    /// # Errors
    /// * `Errors::Aborted` - If sending requests to nodes fails.
    /// * `Errors::InvalidMessage` - If decoding messages from nodes fails or
    ///   if the final outputs from nodes are inconsistent.
    /// * `Errors::InvalidState` - If no final outputs are received from nodes.
    ///
    /// # Returns
    /// * `()` - Empty result on success.
    async fn collect_finalize(&mut self) -> Result<(), Errors> {
        let mut public_keys: Vec<Vec<u8>> = Vec::new();
        let mut public_key_packages: Vec<Vec<u8>> = Vec::new();

        for (id, session_id) in self.sessions.clone() {
            let node: &mut NodeIpcClient = self.node_mut(id)?;

            let response: FinalizeSessionResponse =
                node.finalize(session_id).await.map_err(map_status)?;

            match response.final_output {
                Some(FinalOutput::KeyGeneration(result)) => {
                    public_keys.push(result.public_key);
                    public_key_packages.push(result.public_key_package);
                },
                _ => {
                    return Err(Errors::InvalidMessage(
                        "Unexpected final output from node.".into(),
                    ));
                },
            }
        }

        let first_public_key: Vec<u8> = public_keys
            .first()
            .ok_or(Errors::InvalidState("No public keys.".into()))?
            .clone();

        let first_package: Vec<u8> = public_key_packages
            .first()
            .ok_or(Errors::InvalidState("No public key package.".into()))?
            .clone();

        for public_key in &public_keys {
            if *public_key != first_public_key {
                return Err(Errors::InvalidState(
                    "Public keys mismatch.".into(),
                ));
            }
        }

        self.output = Some(ProtocolOutput::KeyGeneration {
            key_id: self.key_id.clone(),
            key_share: None,
            public_key: first_public_key,
            public_key_package: first_package,
        });

        Ok(())
    }
}

#[async_trait]
impl Protocol for FrostEd25519ControllerKeyGeneration {
    /// Get protocol algorithm.
    ///
    /// # Returns
    /// * `Algorithm` - The algorithm of the protocol (FROST-ed25519).
    fn algorithm(&self) -> Algorithm {
        self.algorithm
    }

    /// Get protocol threshold.
    ///
    /// # Returns
    /// * `u32` - The threshold number of participants required to reconstruct
    ///   the key.
    fn threshold(&self) -> u32 {
        self.threshold
    }

    /// Get protocol total number of participants.
    ///
    /// # Returns
    /// * `u32` - The total number of participants in the protocol.
    fn participants(&self) -> u32 {
        self.participants
    }

    /// Finalize the protocol and get the output.
    ///
    /// # Returns
    /// * `ProtocolOutput` - The output of the protocol, containing the
    ///   generated public key and public key package.
    fn current_round(&self) -> Round {
        self.round
    }

    /// Handle an incoming round message from a node, update protocol state,
    /// and return the next round message to be sent to nodes.
    ///
    /// # Arguments
    /// * `message` (`RoundMessage`) - The incoming round message from a node.
    ///
    /// # Errors
    /// * `Errors::Aborted` - If the protocol has been aborted.
    /// * `Errors::InvalidMessage` - If the incoming message is invalid or
    ///   cannot be processed in the current state.
    /// * `Errors::InvalidState` - If the protocol is not in a valid state to
    ///   process the incoming message.
    ///
    /// # Returns
    /// * `Option<RoundMessage>` - The next round message to be sent to nodes,
    ///   or `None` if no message needs to be sent at this time.
    async fn next_round(
        &mut self,
    ) -> Result<Option<crate::protocols::types::RoundMessage>, Errors> {
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

    /// Handle an incoming round message from a node, update protocol state,
    /// and return the next round message to be sent to nodes.
    ///
    /// # Arguments
    /// * `message` (`RoundMessage`) - The incoming round message from a node.
    ///
    /// # Errors
    /// * `Errors::Aborted` - If the protocol has been aborted.
    /// * `Errors::InvalidMessage` - If the incoming message is invalid or
    ///   cannot be processed in the current state.
    /// * `Errors::InvalidState` - If the protocol is not in a valid state to
    ///   process the incoming message.
    ///
    /// # Returns
    /// * `Option<RoundMessage>` - The next round message to be sent to nodes,
    ///   or `None` if no message needs to be sent at this time.
    async fn handle_message(
        &mut self,
        _message: crate::protocols::types::RoundMessage,
    ) -> Result<Option<crate::protocols::types::RoundMessage>, Errors> {
        Ok(None)
    }

    /// Finalize the protocol and get the output.
    ///
    /// # Errors
    /// * `Errors::Aborted` - If the protocol has been aborted.
    /// * `Errors::InvalidState` - If the protocol is not in a valid state to
    ///   be finalized or if the protocol output is not available.
    ///
    /// * `Errors::InvalidMessage` - If the protocol output is invalid.
    ///
    /// # Returns
    /// * `ProtocolOutput` - The output of the protocol, containing the
    ///   generated public key and public key package.
    async fn finalize(&mut self) -> Result<ProtocolOutput, Errors> {
        self.output
            .take()
            .ok_or(Errors::InvalidState("Protocol not finished.".into()))
    }

    /// Abort the protocol.
    ///
    /// # Returns
    /// * `()` - Empty result on success.
    fn abort(&mut self) {
        self.aborted = true;
    }
}
