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
use frost_core::{
    Ciphersuite,
    Error,
    Identifier as FrostIdentifier,
    Signature as FrostSignature,
    SigningPackage as FrostSigningPackage,
    aggregate,
    keys::PublicKeyPackage as FrostPublicKeyPackage,
    round1::SigningCommitments as FrostSigningCommitments,
    round2::SignatureShare as FrostSignatureShare,
};
use futures::stream::{FuturesUnordered, StreamExt};
use postcard::{Error as PostcardError, from_bytes, to_allocvec};

use crate::{
    proto::engine::v1::{
        Algorithm, RoundMessage, StartSessionResponse, StartSigningSessionRequest, SubmitRoundRequest, SubmitRoundResponse, signature_result::FinalSignature
    },
    protocols::{
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
    secrets::vault::key_path::scoped,
    transport::{
        errors::{Errors, map_status},
        grpc::node_client::NodeIpcClient,
    },
};

/// Abstracts over FROST curve variants for controller-side signing.
/// Implement this trait for each curve (ed25519, secp256k1) to plug into
/// the generic `FrostControllerSigning` implementation.
pub trait FrostControllerSigningCurve: Send + Sync + 'static {
    /// The frost_core Ciphersuite for this curve.
    type Curve: Ciphersuite + Send + Sync;

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
    /// * `FrostIdentifier<Self::Curve>` - The curve-specific FROST Identifier
    ///   type.
    fn identifier_from_u16(
        identifier: u16,
    ) -> Result<FrostIdentifier<Self::Curve>, Errors> {
        FrostIdentifier::<Self::Curve>::try_from(identifier).map_err(
            |error: Error<Self::Curve>| {
                Errors::InvalidParticipant(format!(
                    "Failed to create identifier from {}: {:?}",
                    identifier, error
                ))
            },
        )
    }

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
    /// * `FrostPublicKeyPackage<Self::Curve>` - The deserialized public key
    ///   package.
    fn deserialize_public_key_package(
        bytes: &[u8],
    ) -> Result<FrostPublicKeyPackage<Self::Curve>, Errors> {
        from_bytes(bytes).map_err(|error: PostcardError| {
            Errors::InvalidMessage(format!(
                "Failed to deserialize public key package: {}",
                error
            ))
        })
    }

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
    /// * `FrostSigningCommitments<Self::Curve>` - The deserialized signing
    ///   commitments.
    fn deserialize_commitments(
        bytes: &[u8],
    ) -> Result<FrostSigningCommitments<Self::Curve>, Errors> {
        from_bytes(bytes).map_err(|error: PostcardError| {
            Errors::InvalidMessage(format!(
                "Failed to deserialize signing commitments: {}",
                error
            ))
        })
    }

    /// Construct a `SigningPackage` from collected commitments and the
    /// message.
    ///
    /// # Arguments
    /// * `commitments` (`BTreeMap<FrostIdentifier<Self::Curve>,
    ///   FrostSigningCommitments<Self::Curve>>`) - The commitments collected
    ///   from all participants in round 0.
    /// * `message` (`&[u8]`) - The message to be signed, embedded in the
    ///   signing package and verified by each node before signing.
    ///
    /// # Errors
    /// * `Errors::InvalidMessage` - If the signing package cannot be
    ///   constructed due to missing or invalid commitments.
    ///
    /// # Returns
    /// * `FrostSigningPackage<Self::Curve>` - The constructed signing package
    ///   ready for broadcast in round 1.
    fn build_signing_package(
        commitments: BTreeMap<
            FrostIdentifier<Self::Curve>,
            FrostSigningCommitments<Self::Curve>,
        >,
        message: &[u8],
    ) -> Result<FrostSigningPackage<Self::Curve>, Errors> {
        Ok(FrostSigningPackage::new(commitments, message))
    }

    /// Serialize a `SigningPackage` to postcard bytes.
    ///
    /// # Arguments
    /// * `package` (`&FrostSigningPackage<Self::Curve>`) - The signing package
    ///   to serialize.
    ///
    /// # Errors
    /// * `Errors::InvalidMessage` - If serialization fails due to invalid
    ///   format.
    ///
    /// # Returns
    /// * `Vec<u8>` - The serialized signing package as bytes.
    fn serialize_signing_package(
        package: &FrostSigningPackage<Self::Curve>,
    ) -> Result<Vec<u8>, Errors> {
        to_allocvec(package).map(|value: Vec<u8>| value.to_vec()).map_err(
            |error: PostcardError| {
                Errors::InvalidMessage(format!(
                    "Failed to serialize signing package: {}",
                    error
                ))
            },
        )
    }

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
    /// * `FrostSignatureShare<Self::Curve>` - The deserialized signature
    ///   share.
    fn deserialize_signature_share(
        bytes: &[u8],
    ) -> Result<FrostSignatureShare<Self::Curve>, Errors> {
        from_bytes(bytes).map_err(|error: PostcardError| {
            Errors::InvalidMessage(format!(
                "Failed to deserialize signature share: {}",
                error
            ))
        })
    }

    /// Aggregate signature shares into a final signature.
    ///
    /// # Arguments
    /// * `signing_package` (`&FrostSigningPackage<Self::Curve>`) - The signing
    ///   package that was signed by the participants, used for verification
    ///   during aggregation.
    /// * `shares` (`&BTreeMap<FrostIdentifier<Self::Curve>,
    ///   FrostSignatureShare<Self::Curve>>`) - The signature shares collected
    ///   from all participants in round 1, mapped by their identifiers.
    /// * `public_key_package` (`&FrostPublicKeyPackage<Self::Curve>`) - The
    ///   public key package used for verifying the signature shares during
    ///   aggregation.
    ///
    /// # Errors
    /// * `Errors::InvalidSignature` - If any signature share is invalid during
    ///   aggregation, or if the final aggregated signature fails verification.
    ///
    /// # Returns
    /// * `FrostSignature<Self::Curve>` - The final aggregated signature
    ///   produced by the controller.
    fn aggregate(
        signing_package: &FrostSigningPackage<Self::Curve>,
        shares: &BTreeMap<
            FrostIdentifier<Self::Curve>,
            FrostSignatureShare<Self::Curve>,
        >,
        public_key_package: &FrostPublicKeyPackage<Self::Curve>,
    ) -> Result<FrostSignature<Self::Curve>, Errors> {
        aggregate(signing_package, shares, public_key_package).map_err(
            |error: Error<Self::Curve>| {
                Errors::InvalidSignature(format!(
                    "Failed to aggregate signature shares: {}",
                    error
                ))
            },
        )
    }

    /// Serialize the final aggregated signature to bytes.
    ///
    /// # Arguments
    /// * `signature` (`&FrostSignature<Self::Curve>`) - The final aggregated
    ///   signature to serialize.
    ///
    /// # Errors
    /// * `Errors::InvalidMessage` - If serialization fails due to invalid
    ///   format.
    ///
    /// # Returns
    /// * `Vec<u8>` - The serialized signature as bytes.
    fn serialize_signature(
        signature: &FrostSignature<Self::Curve>,
    ) -> Result<Vec<u8>, Errors> {
        signature.serialize().map_err(|error: Error<Self::Curve>| {
            Errors::InvalidSignature(format!(
                "Failed to serialize signature: {}",
                error
            ))
        })
    }
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
    public_key_package: FrostPublicKeyPackage<C::Curve>,
    /// Current protocol round.
    round: Round,
    /// Mapping of participant identifier to session identifier.
    sessions: HashMap<u32, String>,
    /// Commitments collected from all participants in round 0.
    commitments:
        BTreeMap<FrostIdentifier<C::Curve>, FrostSigningCommitments<C::Curve>>,
    /// Signature shares collected from all participants in round 1.
    shares: BTreeMap<FrostIdentifier<C::Curve>, FrostSignatureShare<C::Curve>>,
    /// Final protocol output, set after successful aggregation.
    output: Option<ProtocolOutput>,
    /// True if the protocol has been aborted.
    aborted: bool,
}

impl<C: FrostControllerSigningCurve> FrostControllerSigning<C>
where
    FrostIdentifier<C::Curve>: Send + Sync,
    FrostSigningCommitments<C::Curve>: Send + Sync,
    FrostSignatureShare<C::Curve>: Send + Sync,
    FrostPublicKeyPackage<C::Curve>: Send + Sync,
    FrostSigningPackage<C::Curve>: Send + Sync,
    FrostSignature<C::Curve>: Send + Sync,
{
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

        let public_key_package: FrostPublicKeyPackage<C::Curve> =
            C::deserialize_public_key_package(&init.public_key_package)?;

        Ok(Self {
            algorithm: init.common.algorithm,
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

    /// Convert a u32 participant identifier to a curve-specific FROST
    /// Identifier.
    ///
    /// # Errors
    /// * `Errors::InvalidParticipant` - If conversion fails.
    ///
    /// # Returns
    /// * `FrostIdentifier<C::Curve>` - The curve-specific FROST Identifier
    ///   corresponding to the given participant identifier.
    fn identifier_from_u32(
        identifier: u32,
    ) -> Result<FrostIdentifier<C::Curve>, Errors> {
        C::identifier_from_u16(u16::try_from(identifier).map_err(
            |error: TryFromIntError| {
                Errors::InvalidParticipant(format!(
                    "Failed to convert participant identifier {} to u16: {:?}",
                    identifier, error
                ))
            },
        )?)
    }

    /// Decode a `FrostWire::Commitments` message and return the typed
    /// identifier-commitment pair.
    ///
    /// Extracted to keep `collect_commitments` free of inline match arms.
    ///
    /// # Arguments
    /// * `payload` (`&[u8]`) - Raw wire payload from the round 0 response.
    ///
    /// # Errors
    /// * `Errors::InvalidMessage` - If the wire message cannot be decoded or
    ///   is not of the expected `Commitments` variant.
    /// * `Errors::InvalidParticipant` - If the identifier cannot be converted.
    ///
    /// # Returns
    /// * `(FrostIdentifier<C::Curve>, FrostSigningCommitments<C::Curve>)` -
    ///   The typed identifier-commitment pair extracted from the wire message.
    fn decode_commitment_message(
        payload: &[u8],
    ) -> Result<
        (FrostIdentifier<C::Curve>, FrostSigningCommitments<C::Curve>),
        Errors,
    > {
        match decode_wire(payload).map_err(|error: Errors| {
            Errors::InvalidMessage(format!(
                "Failed to decode FROST wire message: {}.",
                error
            ))
        })? {
            FrostWire::Commitments { identifier, commitments } => {
                let frost_identifier: FrostIdentifier<C::Curve> =
                    Self::identifier_from_u32(identifier)?;
                let signing_commitments: FrostSigningCommitments<C::Curve> =
                    C::deserialize_commitments(&commitments)?;
                Ok((frost_identifier, signing_commitments))
            },
            _ => Err(Errors::InvalidMessage(
                "Unexpected wire message type in round 0.".into(),
            )),
        }
    }

    /// Decode a `FrostWire::SignatureShare` message and return the typed
    /// identifier-share pair.
    ///
    /// Extracted to keep `broadcast_signing_package` free of inline match
    /// arms.
    ///
    /// # Arguments
    /// * `payload` (`&[u8]`) - Raw wire payload from the round 1 response.
    ///
    /// # Errors
    /// * `Errors::InvalidMessage` - If the wire message cannot be decoded or
    ///   is not of the expected `SignatureShare` variant.
    /// * `Errors::InvalidParticipant` - If the identifier cannot be converted.
    ///
    /// # Returns
    /// * `(FrostIdentifier<C::Curve>, FrostSignatureShare<C::Curve>)` - The
    ///   typed identifier-share pair extracted from the wire message.
    fn decode_signature_share_message(
        payload: &[u8],
    ) -> Result<
        (FrostIdentifier<C::Curve>, FrostSignatureShare<C::Curve>),
        Errors,
    > {
        match decode_wire(payload).map_err(|error: Errors| {
            Errors::InvalidMessage(format!(
                "Failed to decode FROST wire message: {}",
                error
            ))
        })? {
            FrostWire::SignatureShare { identifier, signature_share } => {
                let frost_identifier: FrostIdentifier<C::Curve> =
                    Self::identifier_from_u32(identifier)?;
                let share: FrostSignatureShare<C::Curve> =
                    C::deserialize_signature_share(&signature_share)?;
                Ok((frost_identifier, share))
            },
            _ => Err(Errors::InvalidMessage(
                "Unexpected wire message type in round 1.".into(),
            )),
        }
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
        let futures: FuturesUnordered<_> = self
            .node_identifiers()?
            .into_iter()
            .map(|identifier: u32| {
                let node: NodeIpcClient = self.node_clone(identifier)?;
                let request: StartSigningSessionRequest =
                    StartSigningSessionRequest {
                        // Scoped key identifier for Vault lookup on the node.
                        key_identifier: scoped(
                            &self.key_identifier,
                            identifier,
                        ),
                        algorithm: self.algorithm.into(),
                        threshold: self.threshold,
                        participants: self.participants,
                        message: self.message.clone(),
                    };

                Ok(async move {
                    let response: StartSessionResponse = node
                        .start_signing(request)
                        .await
                        .map_err(map_status)?;
                    Ok::<(u32, StartSessionResponse), Errors>((
                        identifier, response,
                    ))
                })
            })
            .collect::<Result<FuturesUnordered<_>, Errors>>()?;

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

        self.commitments = results
            .iter()
            .map(|(_, response): &(u32, StartSessionResponse)| {
                let payload: &[u8] = &response
                    .messages
                    .first()
                    .ok_or_else(|| {
                        Errors::InvalidMessage(
                            "Missing round 0 message in start session \
                            response."
                                .into(),
                        )
                    })?
                    .payload;
                Self::decode_commitment_message(payload)
            })
            .collect::<Result<BTreeMap<_, _>, _>>()?;

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
    ///
    /// # Returns
    /// * `FrostSigningPackage<C::Curve>` - The signing package that was
    ///   broadcast to the nodes, needed for aggregation in the next step.
    async fn broadcast_signing_package(
        &mut self,
    ) -> Result<FrostSigningPackage<C::Curve>, Errors> {
        let signing_package: FrostSigningPackage<C::Curve> =
            C::build_signing_package(self.commitments.clone(), &self.message)?;

        let payload: Vec<u8> = encode_wire(&FrostWire::SigningPackage {
            signing_package: C::serialize_signing_package(&signing_package)?,
        })?;

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
                        .ok_or_else(|| {
                            Errors::InvalidMessage(
                                "Missing signature share in submit round \
                                response."
                                    .into(),
                            )
                        })?
                        .payload;

                    Self::decode_signature_share_message(payload)
                })
            })
            .collect::<Result<FuturesUnordered<_>, Errors>>()?;

        self.shares = futures
            .collect::<Vec<Result<_, _>>>()
            .await
            .into_iter()
            .collect::<Result<BTreeMap<_, _>, _>>()?;

        Ok(signing_package)
    }

    /// Aggregate all collected signature shares into a final signature and
    /// store the protocol output.
    ///
    /// Verifies the aggregated signature against the public key package before
    /// storing — `frost_*::aggregate` performs this check internally.
    ///
    /// # Arguments
    /// * `signing_package` (`FrostSigningPackage<C::Curve>`) - The signing
    ///   package that was signed by the participants, used for verification
    ///   during aggregation.
    ///
    /// # Errors
    /// * `Errors::InvalidSignature` - If aggregation or serialization fails.
    fn aggregate(
        &mut self,
        signing_package: FrostSigningPackage<C::Curve>,
    ) -> Result<(), Errors> {
        let signature: FrostSignature<C::Curve> = C::aggregate(
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
impl<C: FrostControllerSigningCurve> Protocol for FrostControllerSigning<C>
where
    FrostIdentifier<C::Curve>: Send + Sync,
    FrostSigningCommitments<C::Curve>: Send + Sync,
    FrostSignatureShare<C::Curve>: Send + Sync,
    FrostPublicKeyPackage<C::Curve>: Send + Sync,
    FrostSigningPackage<C::Curve>: Send + Sync,
    FrostSignature<C::Curve>: Send + Sync,
{
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
        let signing_package: FrostSigningPackage<C::Curve> =
            self.broadcast_signing_package().await?;
        self.aggregate(signing_package)?;

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
        self.commitments.clear();
        self.shares.clear();
    }
}
