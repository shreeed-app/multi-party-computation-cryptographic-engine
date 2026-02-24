//! FROST-ed25519 controller-side signing task.

use std::{
    collections::{BTreeMap, HashMap},
    num::TryFromIntError,
};

use async_trait::async_trait;
use frost_ed25519::{
    Error,
    Identifier,
    Signature,
    SigningPackage,
    aggregate,
    keys::PublicKeyPackage,
    round1::SigningCommitments,
    round2::SignatureShare,
};
use futures::stream::{FuturesUnordered, StreamExt};
use postcard::{Error as PostcardError, from_bytes, to_allocvec};

use crate::{
    proto::signer::v1::{
        StartSessionResponse,
        StartSigningSessionRequest,
        SubmitRoundRequest,
        SubmitRoundResponse,
        signature_result::FinalSignature,
    },
    protocols::{
        algorithm::Algorithm,
        codec::{decode_wire, encode_wire},
        frost::wire::FrostWire,
        protocol::Protocol,
        types::{
            ControllerSigningInit,
            ProtocolInit,
            ProtocolOutput,
            Round,
            RoundMessage,
            SigningInit,
        },
    },
    transport::{
        errors::{Errors, map_status},
        grpc::node_client::NodeIpcClient,
    },
};

/// Controller-side FROST(ed25519) signing protocol instance.
pub struct FrostEd25519ControllerSigning {
    /// Algorithm name.
    algorithm: Algorithm,
    /// Unique key identifier.
    key_id: String,
    /// Number of participants required to sign.
    threshold: u32,
    /// Total number of participants.
    participants: u32,
    /// Message to be signed.
    message: Vec<u8>,
    /// Node clients for participant communication.
    nodes: Vec<NodeIpcClient>,
    /// Public key package for signature verification.
    public_key_package: PublicKeyPackage,
    /// Current protocol round.
    round: Round,
    /// Mapping of participant identifier to signing session ID.
    sessions: HashMap<u32, String>,
    /// Commitments collected from participants in round 1.
    commitments: BTreeMap<Identifier, SigningCommitments>,
    /// Signature shares collected from participants in round 2.
    shares: BTreeMap<Identifier, SignatureShare>,
    /// Protocol output after successful signing.
    output: Option<ProtocolOutput>,
    /// Indicates if the protocol has been aborted.
    aborted: bool,
}

impl FrostEd25519ControllerSigning {
    /// Try to create a new FROST(ed25519) protocol instance.
    ///
    /// # Arguments
    /// * `protocol_init` (`ProtocolInit`) - Protocol initialization context.
    /// * `nodes` (`Vec<NodeIpcClient>`) - Node clients for participant
    ///   communication.
    ///
    /// # Errors
    /// * `Error::InvalidProtocolInit` - If the protocol initialization context
    ///   is invalid.
    /// * `Error::InvalidMessage` - If the public key package cannot be
    ///   decoded.
    ///
    /// # Returns
    /// * `FrostEd25519ControllerSigning` - Initialized protocol instance.
    pub fn try_new(protocol_init: ProtocolInit) -> Result<Self, Errors> {
        let init: ControllerSigningInit = match protocol_init {
            ProtocolInit::Signing(SigningInit::Controller(init)) => init,
            _ => return Err(Errors::InvalidProtocolInit(
                "Invalid protocol initialization context for FROST(ed25519) 
                controller signing."
                    .into(),
            )),
        };

        // Retrieve public key package from initialization context.
        let public_key_package: PublicKeyPackage = from_bytes(
            &init.public_key_package,
        )
        .map_err(|error: PostcardError| {
            Errors::InvalidMessage(format!(
                "Failed to decode public key package: {}",
                error
            ))
        })?;

        Ok(Self {
            algorithm: Algorithm::FrostEd25519,
            key_id: init.common.key_id,
            threshold: init.common.threshold,
            participants: init.common.participants,
            message: init.common.message,
            public_key_package,
            nodes: init.nodes,
            round: 0,
            sessions: HashMap::new(),
            commitments: BTreeMap::new(),
            shares: BTreeMap::new(),
            output: None,
            aborted: false,
        })
    }

    /// Helper method to extract participant IDs from node clients.
    ///
    /// # Errors
    /// * `Error::InvalidParticipant` - If a participant ID is invalid or if no
    ///   participants are found.
    ///
    /// # Returns
    /// * `Vec<u32>` - Sorted list of participant IDs.
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
                "Number of participant IDs does not match expected 
                participants."
                    .into(),
            ));
        }

        Ok(identifiers)
    }

    /// Helper method to get a mutable reference to a node client by
    /// participant ID.
    ///
    /// # Arguments
    /// * `id` (`u32`) - Participant ID.
    ///
    /// # Errors
    /// * `Error::InvalidParticipant` - If the participant ID is invalid or not
    ///   found.
    /// * `Error::InvalidState` - If the protocol is in an invalid state for
    ///   communication.
    ///
    /// # Returns
    /// * `&mut NodeIpcClient` - Mutable reference to the node client.
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

    /// Helper method to create a scoped key ID for participant communication.
    ///
    /// # Arguments
    /// * `base` (`&str`) - Base key ID.
    /// * `identifier` (`u32`) - Participant ID to scope the key ID for.
    ///
    /// # Returns
    /// * `String` - Scoped key ID in the format "{base}/{identifier}".
    fn scoped_key_identifier(base: &str, identifier: u32) -> String {
        format!("{}/{}", base.trim_end_matches('/'), identifier)
    }

    /// Collect commitments from participants in round 1.
    ///
    /// # Errors
    /// * `Error::InvalidParticipant` - If a participant ID is invalid.
    /// * `Error::InvalidMessage` - If a response message is invalid or cannot
    ///   be decoded.
    /// * `Error::InvalidSignature` - If a signature share is invalid.
    ///
    /// # Returns
    /// * `()` - Nothing, but updates internal state with collected
    ///   commitments.
    async fn collect_commitments(&mut self) -> Result<(), Errors> {
        let identifiers: Vec<u32> = self.node_identifiers()?;

        let mut futures: FuturesUnordered<
            impl Future<Output = Result<(u32, StartSessionResponse), Errors>>,
        > = FuturesUnordered::new();

        for identifier in identifiers {
            let mut node: NodeIpcClient = self
                .nodes
                .iter()
                .find(|node: &&NodeIpcClient| {
                    node.participant_id() == Some(identifier)
                })
                .ok_or(Errors::InvalidParticipant(format!(
                    "Participant ID {} not found among node clients.",
                    identifier
                )))?
                .clone();

            let request: StartSigningSessionRequest =
                StartSigningSessionRequest {
                    key_id: Self::scoped_key_identifier(
                        &self.key_id,
                        identifier,
                    ),
                    algorithm: self.algorithm.as_str().to_string(),
                    threshold: self.threshold,
                    participants: self.participants,
                    message: self.message.clone(),
                };

            futures.push(async move {
                let start: StartSessionResponse =
                    node.start_signing(request).await.map_err(map_status)?;
                Ok::<_, Errors>((identifier, start))
            });
        }

        // Collect commitments from all participants and store them in internal
        // state.
        while let Some(result) = futures.next().await {
            let (identifier, start): (u32, StartSessionResponse) = result?;

            self.sessions.insert(identifier, start.session_id);

            let wire: FrostWire =
                decode_wire(&start.payload).map_err(|error: Errors| {
                    Errors::InvalidMessage(format!(
                        "Failed to decode FROST wire message: {}",
                        error
                    ))
                })?;

            match wire {
                FrostWire::Commitments { identifier, commitments } => {
                    let identifier: Identifier = Identifier::try_from(
                        u16::try_from(identifier).map_err(
                            |error: TryFromIntError| {
                                Errors::InvalidParticipant(error.to_string())
                            },
                        )?,
                    )
                    .map_err(|error: Error| {
                        Errors::InvalidParticipant(error.to_string())
                    })?;

                    let commitments: SigningCommitments = from_bytes(
                        &commitments,
                    )
                    .map_err(|error: PostcardError| {
                        Errors::InvalidMessage(format!(
                            "Failed to decode signing commitments: {}",
                            error
                        ))
                    })?;

                    self.commitments.insert(identifier, commitments);
                },
                _ => {
                    return Err(Errors::InvalidMessage(
                        "Unexpected message type in round 1.".into(),
                    ));
                },
            }
        }

        Ok(())
    }

    /// Broadcast signing package to participants after collecting commitments.
    ///
    /// # Errors
    /// * `Error::InvalidMessage` - If the signing package cannot be encoded or
    ///   if a response message is invalid.
    /// * `Error::InvalidParticipant` - If a participant ID is invalid.
    /// * `Error::InvalidSignature` - If a signature share is invalid.
    ///
    /// # Returns
    /// * `()` - Nothing, but broadcasts the signing package to all
    ///   participants.
    async fn broadcast_signing_package(&mut self) -> Result<(), Errors> {
        let signing_package: SigningPackage =
            SigningPackage::new(self.commitments.clone(), &self.message);

        let signing_package_bytes: Vec<u8> = to_allocvec(&signing_package)
            .map_err(|error: PostcardError| {
                Errors::InvalidMessage(format!(
                    "Failed to encode signing package: {}",
                    error
                ))
            })?;

        let payload: Vec<u8> = encode_wire(&FrostWire::SigningPackage {
            signing_package: signing_package_bytes,
        })?;

        for (id, session_id) in self.sessions.clone() {
            let node: &mut NodeIpcClient = self.node_mut(id)?;

            node.submit_round(SubmitRoundRequest {
                session_id,
                round: 1,
                from: None,
                to: Some(id),
                payload: payload.clone(),
            })
            .await
            .map_err(map_status)?;
        }

        Ok(())
    }

    /// Collect signature shares from participants after broadcasting signing
    /// package.
    ///
    /// # Errors
    /// * `Error::InvalidParticipant` - If a participant ID is invalid.
    /// * `Error::InvalidMessage` - If a response message is invalid or cannot
    ///   be decoded.
    /// * `Error::InvalidSignature` - If a signature share is invalid.
    ///
    /// # Returns
    /// * `()` - Nothing, but updates internal state with collected signature
    ///   shares.
    async fn collect_signature_shares(&mut self) -> Result<(), Errors> {
        for (id, session_id) in self.sessions.clone() {
            let node: &mut NodeIpcClient = self.node_mut(id)?;

            // Request signature share from participant.
            let response: SubmitRoundResponse = node
                .submit_round(SubmitRoundRequest {
                    session_id,
                    round: 2,
                    from: None,
                    to: Some(id),
                    payload: vec![],
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
                FrostWire::SignatureShare { identifier, signature_share } => {
                    // Convert participant ID to FROST identifier and store
                    // signature share.
                    let identifier: Identifier = Identifier::try_from(
                        u16::try_from(identifier)
                            .map_err(|error: TryFromIntError| Errors::InvalidParticipant(error.to_string()))?,
                    )
                    .map_err(|error: Error| Errors::InvalidParticipant(format!("Failed to convert participant ID to FROST identifier: {}", error)))?;

                    let share: SignatureShare = from_bytes(&signature_share)
                        .map_err(
                        |error: PostcardError| {
                            Errors::InvalidMessage(format!(
                                "Failed to decode signature share: {}",
                                error
                            ))
                        },
                    )?;

                    self.shares.insert(identifier, share);
                },
                _ => {
                    return Err(Errors::InvalidMessage(
                        "Unexpected message type in round 2.".into(),
                    ));
                },
            }
        }

        Ok(())
    }

    /// Aggregate signature shares into final signature output.
    ///
    /// # Errors
    /// * `Error::InvalidSignature` - If signature aggregation fails.
    ///
    /// # Returns
    /// * `()` - Nothing, but updates internal state with final signature
    ///   output.
    fn aggregate(&mut self) -> Result<(), Errors> {
        let signing_package: SigningPackage =
            SigningPackage::new(self.commitments.clone(), &self.message);

        let signature: Signature = aggregate(
            &signing_package,
            &self.shares,
            &self.public_key_package,
        )
        .map_err(|error: Error| {
            Errors::InvalidSignature(format!(
                "Failed to aggregate signature shares: {}",
                error
            ))
        })?;

        self.output = Some(ProtocolOutput::Signature(FinalSignature::Raw(
            match signature.serialize() {
                Ok(bytes) => bytes.to_vec(),
                Err(error) => {
                    return Err(Errors::InvalidSignature(format!(
                        "Failed to serialize signature: {}",
                        error
                    )));
                },
            },
        )));

        Ok(())
    }
}

#[async_trait]
impl Protocol for FrostEd25519ControllerSigning {
    /// Return the algorithm of the protocol.
    ///
    /// # Returns
    /// * `Algorithm` - The algorithm of the protocol.
    fn algorithm(&self) -> Algorithm {
        self.algorithm
    }

    /// Return the signing threshold.
    ///
    /// # Returns
    /// * `u32` - The signing threshold.
    fn threshold(&self) -> u32 {
        self.threshold
    }

    /// Return the total number of participants.
    ///
    /// # Returns
    /// * `u32` - The total number of participants.
    fn participants(&self) -> u32 {
        self.participants
    }

    /// Return the current protocol round.
    ///
    /// # Returns
    /// * `Round` - The current protocol round.
    fn current_round(&self) -> Round {
        self.round
    }

    /// Proceed to the next protocol round.
    ///
    /// # Errors
    /// * `Error::Aborted` - If the protocol has been aborted.
    async fn next_round(&mut self) -> Result<Option<RoundMessage>, Errors> {
        if self.aborted {
            return Err(Errors::Aborted("Protocol has been aborted.".into()));
        }

        if self.round != 0 {
            return Ok(None);
        }

        // Move to round 1: collect commitments, broadcast signing package,
        // collect signature shares, aggregate, and finalize.
        self.round = 1;
        // The actual work is done in the finalize method after collecting all
        // shares, so we just return None here to indicate no message to send.
        self.collect_commitments().await?;
        self.broadcast_signing_package().await?;
        self.collect_signature_shares().await?;
        self.aggregate()?;
        // Move to round 2 to indicate signing is complete.
        self.round = 2;

        Ok(None)
    }

    /// Handle an incoming round message (not used in this protocol since the
    /// controller initiates all rounds).
    ///
    /// # Arguments
    /// * `message` (`RoundMessage`) - Incoming round message.
    ///
    /// # Errors
    /// * `Error::Aborted` - If the protocol has been aborted.
    /// * `Error::InvalidMessage` - If the message is invalid for the current
    ///   round.
    ///
    /// # Returns
    /// * `Option<RoundMessage>` - Message to send to controller, if any.
    async fn handle_message(
        &mut self,
        _message: RoundMessage,
    ) -> Result<Option<RoundMessage>, Errors> {
        Ok(None)
    }

    /// Finalize the protocol and produce the signature output.
    ///
    /// # Errors
    /// * `Error::Aborted` - If the protocol has been aborted.
    /// * `Error::InvalidState` - If the protocol is not in a finalizable
    ///   state.
    /// * `Error::InvalidSignature` - If signature aggregation fails.
    ///
    /// # Returns
    /// * `ProtocolOutput` - The final signature output.
    async fn finalize(&mut self) -> Result<ProtocolOutput, Errors> {
        self.output
            .take()
            .ok_or(Errors::InvalidState("Protocol not finished.".into()))
    }

    /// Abort the protocol, preventing any further progress.
    fn abort(&mut self) {
        self.aborted = true;
    }
}
