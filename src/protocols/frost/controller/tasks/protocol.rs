//! FROST controller-side signing protocol.
//!
//! A single generic implementation shared across all FROST curve variants.
//! Each curve implements the `FrostControllerSigningCurve` trait to provide
//! its concrete cryptographic types and serialization logic.

use std::{
    collections::{BTreeMap, HashMap},
    num::TryFromIntError,
};

use async_trait::async_trait;
use futures::stream::{FuturesUnordered, StreamExt};

use crate::{
    proto::signer::v1::{
        RoundMessage,
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
            SigningInit,
        },
    },
    transport::{
        errors::{Errors, map_status},
        grpc::node_client::NodeIpcClient,
    },
};

/// Abstracts over FROST curve variants for controller-side signing.
/// Implement this trait for each curve (ed25519, secp256k1) to plug into
/// the generic `FrostControllerSigning` implementation.
pub trait FrostControllerSigningCurve: Send + Sync + 'static {
    /// Curve-specific FROST identifier type.
    type Identifier: Ord + Copy + Send + Sync + 'static;
    /// Signing commitments produced by each participant in round 0.
    type SigningCommitments: Send + Sync + Clone + 'static;
    /// Signing package constructed by the controller and broadcast in round 1.
    type SigningPackage: Send + Sync + 'static;
    /// Signature share produced by each participant in round 1.
    type SignatureShare: Send + Sync + Clone + 'static;
    /// Public key package used for final signature aggregation.
    type PublicKeyPackage: Send + Sync + 'static;
    /// Aggregated signature produced by the controller.
    type Signature: Send + Sync + 'static;

    /// The algorithm identifier for this curve.
    ///
    /// # Returns
    /// * `Algorithm` - The algorithm enum variant corresponding to this curve.
    fn algorithm() -> Algorithm;

    /// Create a FROST Identifier from a u16.
    ///
    /// # Arguments
    /// * `identifier` (`u16`) - The identifier to convert.
    ///
    /// # Errors
    /// * `Errors::InvalidParticipant` - If the identifier cannot be converted
    ///   to a valid FROST Identifier for this curve.
    ///
    /// # Returns
    /// * `Self::Identifier` - The curve-specific FROST Identifier type.
    fn identifier_from_u16(
        identifier: u16,
    ) -> Result<Self::Identifier, Errors>;

    /// Deserialize a `PublicKeyPackage` from postcard bytes.
    ///
    /// # Arguments
    /// * `bytes` (`&[u8]`) - The serialized public key package.
    ///
    /// # Errors
    /// * `Errors::InvalidMessage` - If deserialization fails due to invalid
    ///   format.
    ///
    /// # Returns
    /// * `Self::PublicKeyPackage` - The deserialized public key package.
    fn deserialize_public_key_package(
        bytes: &[u8],
    ) -> Result<Self::PublicKeyPackage, Errors>;

    /// Deserialize `SigningCommitments` from postcard bytes.
    ///
    /// # Arguments
    /// * `bytes` (`&[u8]`) - The serialized signing commitments.
    ///
    /// # Errors
    /// * `Errors::InvalidMessage` - If deserialization fails due to invalid
    ///   format.
    ///
    /// # Returns
    /// * `Self::SigningCommitments` - The deserialized signing commitments.
    fn deserialize_commitments(
        bytes: &[u8],
    ) -> Result<Self::SigningCommitments, Errors>;

    /// Construct a `SigningPackage` from collected commitments and the
    /// message.
    ///
    /// # Arguments
    /// * `commitments` (`BTreeMap<Self::Identifier,
    ///   Self::SigningCommitments>`) - The commitments collected from all
    ///   participants in round 0.
    /// * `message` (`&[u8]`) - The message to be signed, embedded in the
    ///   signing package and verified by each node before signing.
    ///
    /// # Errors
    /// * `Errors::InvalidMessage` - If the signing package cannot be
    ///   constructed due to missing or invalid commitments.
    ///
    /// # Returns
    /// * `Self::SigningPackage` - The constructed signing package ready for
    ///   broadcast in round 1.
    fn build_signing_package(
        commitments: BTreeMap<Self::Identifier, Self::SigningCommitments>,
        message: &[u8],
    ) -> Result<Self::SigningPackage, Errors>;

    /// Serialize a `SigningPackage` to postcard bytes.
    ///
    /// # Arguments
    /// * `package` (`&Self::SigningPackage`) - The signing package to
    ///   serialize.
    ///
    /// # Errors
    /// * `Errors::InvalidMessage` - If serialization fails due to invalid
    ///   format.
    ///
    /// # Returns
    /// * `Vec<u8>` - The serialized signing package as bytes.
    fn serialize_signing_package(
        package: &Self::SigningPackage,
    ) -> Result<Vec<u8>, Errors>;

    /// Deserialize a `SignatureShare` from postcard bytes.
    ///
    /// # Arguments
    /// * `bytes` (`&[u8]`) - The serialized signature share.
    ///
    /// # Errors
    /// * `Errors::InvalidMessage` - If deserialization fails due to invalid
    ///   format.
    ///
    /// # Returns
    /// * `Self::SignatureShare` - The deserialized signature share.
    fn deserialize_signature_share(
        bytes: &[u8],
    ) -> Result<Self::SignatureShare, Errors>;

    /// Aggregate signature shares into a final signature.
    ///
    /// # Arguments
    /// * `signing_package` (`&Self::SigningPackage`) - The signing package
    ///   that was signed by the participants, used for verification during
    ///   aggregation.
    /// * `shares` (`&BTreeMap<Self::Identifier, Self::SignatureShare>`) - The
    ///   signature shares collected from all participants in round 1, mapped
    ///   by their identifiers.
    /// * `public_key_package` (`&Self::PublicKeyPackage`) - The public key
    ///   package used for verifying the signature shares during aggregation.
    ///
    /// # Errors
    /// * `Errors::InvalidSignature` - If any signature share is invalid during
    ///   aggregation, or if the final aggregated signature fails verification.
    ///
    /// # Returns
    /// * `Self::Signature` - The final aggregated signature produced by the
    ///   controller.
    fn aggregate(
        signing_package: &Self::SigningPackage,
        shares: &BTreeMap<Self::Identifier, Self::SignatureShare>,
        public_key_package: &Self::PublicKeyPackage,
    ) -> Result<Self::Signature, Errors>;

    /// Serialize the final aggregated signature to bytes.
    ///
    /// # Arguments
    /// * `signature` (`&Self::Signature`) - The final aggregated signature to
    ///   serialize.
    ///
    /// # Errors
    /// * `Errors::InvalidMessage` - If serialization fails due to invalid
    ///   format.
    ///
    /// # Returns
    /// * `Vec<u8>` - The serialized signature as bytes.
    fn serialize_signature(
        signature: &Self::Signature,
    ) -> Result<Vec<u8>, Errors>;
}

/// Controller-side FROST signing protocol instance.
///
/// Orchestrates the 2-round signing protocol across all nodes:
/// - Round 0: start sessions on all nodes in parallel, collect commitments.
/// - Round 1: broadcast signing package to all nodes in parallel, collect
///   signature shares, aggregate into final signature.
pub struct FrostControllerSigning<C: FrostControllerSigningCurve> {
    /// Algorithm variant for this instance.
    algorithm: Algorithm,
    /// Unique key identifier — scoped per node as
    /// `<key_id>/<participant_id>`.
    key_identifier: String,
    /// Minimum number of participants required to produce a valid signature.
    threshold: u32,
    /// Total number of participants.
    participants: u32,
    /// The message to be signed — embedded in the signing package and
    /// verified by each node before signing.
    message: Vec<u8>,
    /// Node clients for participant communication.
    nodes: Vec<NodeIpcClient>,
    /// Public key package used for final aggregation and verification.
    public_key_package: C::PublicKeyPackage,
    /// Current protocol round.
    round: Round,
    /// Mapping of participant identifier to session identifier.
    sessions: HashMap<u32, String>,
    /// Commitments collected from all participants in round 0.
    commitments: BTreeMap<C::Identifier, C::SigningCommitments>,
    /// Signature shares collected from all participants in round 1.
    shares: BTreeMap<C::Identifier, C::SignatureShare>,
    /// Final protocol output, set after successful aggregation.
    output: Option<ProtocolOutput>,
    /// True if the protocol has been aborted.
    aborted: bool,
}

impl<C: FrostControllerSigningCurve> FrostControllerSigning<C> {
    /// Try to create a new FROST controller signing protocol instance.
    ///
    /// Decodes the public key package from the initialization context.
    ///
    /// # Arguments
    /// * `protocol_init` (`ProtocolInit`) - Protocol initialization context.
    ///
    /// # Errors
    /// * `Errors::InvalidProtocolInit` - If the init context is invalid.
    /// * `Errors::InvalidMessage` - If the public key package cannot be
    ///   decoded.
    ///
    /// # Returns
    /// * `Self` - A new instance of the FROST controller signing protocol.
    pub fn try_new(protocol_init: ProtocolInit) -> Result<Self, Errors> {
        let init: ControllerSigningInit = match protocol_init {
            ProtocolInit::Signing(SigningInit::Controller(init)) => init,
            _ => {
                return Err(Errors::InvalidProtocolInit(
                    "Invalid protocol initialization context for FROST \
                    controller signing."
                        .into(),
                ));
            },
        };

        let public_key_package: C::PublicKeyPackage =
            C::deserialize_public_key_package(&init.public_key_package)?;

        Ok(Self {
            algorithm: C::algorithm(),
            key_identifier: init.common.key_identifier,
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

    /// Extract sorted participant identifiers from node clients.
    ///
    /// # Errors
    /// * `Errors::InvalidParticipant` - If any node is missing a participant
    ///   identifier or the count does not match `participants`.
    ///
    /// # Returns
    /// * `Vec<u32>` - Sorted list of participant identifiers extracted from
    ///   node clients.
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
        // Validate the count of unique identifiers matches the expected number
        // of participants.
        if identifiers.len() != self.participants as usize {
            return Err(Errors::InvalidParticipant(format!(
                "Expected {} participants, found {}.",
                self.participants,
                identifiers.len()
            )));
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

    /// Build the per-node key identifier used for Vault lookups.
    ///
    /// Each node stores its key share under
    /// `<key_identifier>/<participant_id>` to avoid collisions in Vault.
    ///
    /// # Arguments
    /// * `base` (`&str`) - The base key identifier from the protocol init
    ///   context.
    /// * `identifier` (`u32`) - The participant identifier to scope the key
    ///   identifier for.
    ///
    /// # Errors
    /// * `Errors::InvalidParticipant` - If the participant identifier is
    ///   invalid.
    ///
    /// # Returns
    /// * `String` - The scoped key identifier in the format
    ///   `<base>/<identifier>`.
    fn scoped_key_identifier(base: &str, identifier: u32) -> String {
        format!("{}/{}", base.trim_end_matches('/'), identifier)
    }

    /// Convert a u32 participant identifier to a curve-specific FROST
    /// Identifier.
    ///
    /// # Errors
    /// * `Errors::InvalidParticipant` - If conversion fails.
    ///
    /// # Returns
    /// * `C::Identifier` - The curve-specific FROST Identifier corresponding
    ///   to the given participant identifier.
    fn identifier_from_u32(identifier: u32) -> Result<C::Identifier, Errors> {
        C::identifier_from_u16(u16::try_from(identifier).map_err(
            |error: TryFromIntError| {
                Errors::InvalidParticipant(format!(
                    "Failed to convert participant identifier {} to u16: {}",
                    identifier, error
                ))
            },
        )?)
    }

    /// Start signing sessions on all nodes in parallel and collect their
    /// round 0 commitments.
    ///
    /// Each node generates nonces and returns its `SigningCommitments`. The
    /// controller stores these for use when building the signing package.
    ///
    /// # Errors
    /// * `Errors::InvalidParticipant` - If any participant identifier is
    ///   invalid.
    /// * `Errors::InvalidMessage` - If a response cannot be decoded.
    async fn collect_commitments(&mut self) -> Result<(), Errors> {
        let identifiers: Vec<u32> = self.node_identifiers()?;

        let mut futures: FuturesUnordered<
            impl Future<Output = Result<(u32, StartSessionResponse), Errors>>,
        > = FuturesUnordered::new();

        for identifier in identifiers {
            let node: NodeIpcClient = self.node_clone(identifier)?;

            let request: StartSigningSessionRequest =
                StartSigningSessionRequest {
                    // Scoped key identifier for Vault lookup on the node.
                    key_identifier: Self::scoped_key_identifier(
                        &self.key_identifier,
                        identifier,
                    ),
                    algorithm: self.algorithm.as_str().to_string(),
                    threshold: self.threshold,
                    participants: self.participants,
                    message: self.message.clone(),
                };

            futures.push(async move {
                let response: StartSessionResponse =
                    node.start_signing(request).await.map_err(map_status)?;
                Ok::<(u32, StartSessionResponse), Errors>((
                    identifier, response,
                ))
            });
        }

        while let Some(result) = futures.next().await {
            let (identifier, response): (u32, StartSessionResponse) = result?;

            self.sessions.insert(identifier, response.session_identifier);

            // Each node returns exactly one commitment in its round 0 message.
            let wire: FrostWire = decode_wire(
                &response
                    .messages
                    .first()
                    .ok_or_else(|| {
                        Errors::InvalidMessage(
                            "Missing round 0 message in start session \
                            response."
                                .into(),
                        )
                    })?
                    .payload,
            )
            .map_err(|error: Errors| {
                Errors::InvalidMessage(format!(
                    "Failed to decode FROST wire message: {}.",
                    error
                ))
            })?;

            match wire {
                FrostWire::Commitments { identifier: id_u32, commitments } => {
                    let frost_identifier: C::Identifier =
                        Self::identifier_from_u32(id_u32)?;
                    let commitments: C::SigningCommitments =
                        C::deserialize_commitments(&commitments)?;
                    self.commitments.insert(frost_identifier, commitments);
                },
                _ => {
                    return Err(Errors::InvalidMessage(
                        "Unexpected wire message type in round 0.".into(),
                    ));
                },
            }
        }

        Ok(())
    }

    /// Build the signing package from collected commitments and broadcast it
    /// to all nodes in parallel.
    ///
    /// The signing package embeds all commitments and the message. Each node
    /// verifies the message matches its own before signing.
    ///
    /// # Errors
    /// * `Errors::InvalidMessage` - If the signing package cannot be encoded
    ///   or if any node call fails.
    async fn broadcast_signing_package(&mut self) -> Result<(), Errors> {
        let signing_package: C::SigningPackage =
            C::build_signing_package(self.commitments.clone(), &self.message)?;

        let payload: Vec<u8> = encode_wire(&FrostWire::SigningPackage {
            signing_package: C::serialize_signing_package(&signing_package)?,
        })?;

        let mut futures: FuturesUnordered<
            impl Future<
                Output = Result<(C::Identifier, C::SignatureShare), Errors>,
            >,
        > = FuturesUnordered::new();

        for (identifier, session_identifier) in self.sessions.clone() {
            let node: NodeIpcClient = self.node_clone(identifier)?;
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

                let wire: FrostWire = decode_wire(
                    &response
                        .messages
                        .first()
                        .ok_or_else(|| {
                            Errors::InvalidMessage(
                            "Missing signature share in submit round response."
                                .into(),
                        )
                        })?
                        .payload,
                )
                .map_err(|error: Errors| {
                    Errors::InvalidMessage(format!(
                        "Failed to decode FROST wire message: {}",
                        error
                    ))
                })?;

                match wire {
                    FrostWire::SignatureShare {
                        identifier: id_u32,
                        signature_share,
                    } => {
                        let frost_identifier: C::Identifier =
                            Self::identifier_from_u32(id_u32)?;
                        let share: C::SignatureShare =
                            C::deserialize_signature_share(&signature_share)?;
                        Ok((frost_identifier, share))
                    },
                    _ => Err(Errors::InvalidMessage(
                        "Unexpected wire message type in round 1.".into(),
                    )),
                }
            });
        }

        while let Some(result) = futures.next().await {
            let (identifier, share): (C::Identifier, C::SignatureShare) =
                result?;
            self.shares.insert(identifier, share);
        }

        Ok(())
    }

    /// Aggregate all collected signature shares into a final signature and
    /// store the protocol output.
    ///
    /// Verifies the aggregated signature against the public key package before
    /// storing — `frost_*::aggregate` performs this check internally.
    ///
    /// # Errors
    /// * `Errors::InvalidSignature` - If aggregation or serialization fails.
    fn aggregate(&mut self) -> Result<(), Errors> {
        // Reconstruct the signing package with the same commitments used
        // during broadcast — required for deterministic aggregation.
        let signing_package: C::SigningPackage =
            C::build_signing_package(self.commitments.clone(), &self.message)?;

        let signature: C::Signature = C::aggregate(
            &signing_package,
            &self.shares,
            &self.public_key_package,
        )?;

        self.output = Some(ProtocolOutput::Signature(FinalSignature::Raw(
            C::serialize_signature(&signature)?,
        )));

        Ok(())
    }
}

#[async_trait]
impl<C: FrostControllerSigningCurve> Protocol for FrostControllerSigning<C> {
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

    /// Drive the full signing protocol to completion synchronously.
    ///
    /// Called once by the controller engine at round 0. Orchestrates all node
    /// communication internally and returns `None` — the controller protocol
    /// produces no outgoing round messages itself.
    ///
    /// # Errors
    /// * `Errors::Aborted` - If the protocol has been aborted.
    /// * `Errors::InvalidParticipant` - If any participant identifier is
    ///   invalid.
    /// * `Errors::InvalidMessage` - If any response cannot be decoded, or if
    ///   the signing package cannot be built or serialized.
    ///
    /// # Returns
    /// * `Option<RoundMessage>` - Always returns `Ok(None)` since the
    ///   controller protocol does not produce round messages.
    async fn next_round(&mut self) -> Result<Option<RoundMessage>, Errors> {
        if self.aborted {
            return Err(Errors::Aborted("Protocol has been aborted.".into()));
        }

        if self.round != 0 {
            return Ok(None);
        }

        self.round = 1;

        self.collect_commitments().await?;
        self.broadcast_signing_package().await?;
        self.aggregate()?;

        self.round = 2;

        Ok(None)
    }

    async fn handle_message(
        &mut self,
        _message: RoundMessage,
    ) -> Result<Option<RoundMessage>, Errors> {
        Ok(None)
    }

    /// Finalize the protocol and return the aggregated signature.
    ///
    /// Consumes the output — calling `finalize` twice will return an error.
    ///
    /// # Errors
    /// * `Errors::InvalidState` - If the protocol has not completed yet.
    /// * `Errors::InvalidSignature` - If the final aggregated signature is
    ///   missing due to an internal error in aggregation or serialization.
    ///
    /// # Returns
    /// * `ProtocolOutput` - The protocol output containing the final
    ///   aggregated signature, if the protocol completed successfully.
    async fn finalize(&mut self) -> Result<ProtocolOutput, Errors> {
        self.output
            .take()
            .ok_or(Errors::InvalidState("Protocol not finished.".into()))
    }

    fn abort(&mut self) {
        self.aborted = true;
    }
}
