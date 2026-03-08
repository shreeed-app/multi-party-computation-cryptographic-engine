//! FROST participant-side DKG (Distributed Key Generation).
//!
//! A single generic implementation shared across all FROST curve variants.
//! Each curve implements the `FrostCurve` trait to provide its types and
//! serialization logic.

use std::{collections::BTreeMap, num::TryFromIntError};

use async_trait::async_trait;
use rkyv::{rancor::Error as RkyvError, to_bytes, util::AlignedVec};

use crate::{
    proto::signer::v1::RoundMessage,
    protocols::{
        algorithm::Algorithm,
        codec::{decode_wire, encode_wire},
        frost::{stored_key::FrostStoredKey, wire::FrostWire},
        protocol::Protocol,
        types::{
            KeyGenerationInit,
            NodeKeyGenerationInit,
            ProtocolInit,
            ProtocolOutput,
            Round,
        },
    },
    secrets::secret::Secret,
    transport::errors::Errors,
};

/// Abstracts over FROST curve variants to allow a single generic DKG
/// implementation.
/// Each curve (ed25519, secp256k1) implements this trait to provide its
/// concrete cryptographic types and serialization/deserialization logic.
pub trait FrostCurve: Send + Sync + 'static {
    /// The type representing participant identifiers for this curve. This is
    /// the type used internally within the protocol implementation to track
    /// participants and their messages. It must be constructible from a u16
    /// (the participant identifier provided in the protocol init) and
    /// convertible back to a u16 for message encoding.
    type Identifier: Ord + Copy + Send + Sync + TryFrom<u16> + 'static;
    /// The secret package produced in round 1, consumed in round 2.
    type Round1SecretPackage: Send + Sync + 'static;
    /// The round 1 package produced in round 1 and consumed by peers in round
    /// 2.
    type Round1Package: Send + Sync + Clone + 'static;
    /// The secret package produced in round 2, consumed in round 3.
    type Round2SecretPackage: Send + Sync + 'static;
    /// The round 2 package produced in round 2 and consumed by peers in round
    /// 3.
    type Round2Package: Send + Sync + Clone + 'static;
    /// The final key package produced in round 3, containing the participant's
    /// key share and any other participant-level information. This is the
    /// main output of DKG for the participant and is stored for later signing
    /// operations.
    type KeyPackage: Send + Sync + 'static;
    /// The final public key package produced in round 3, containing the
    /// group's public key and any other group-level information.
    type PublicKeyPackage: Send + Sync + 'static;

    /// The algorithm identifier for this curve.
    ///
    /// # Returns
    /// * `Algorithm` - The algorithm identifier corresponding to this curve.
    fn algorithm() -> Algorithm;

    /// Create a FROST Identifier from a u16.
    ///
    /// # Arguments
    /// * `identifier` (`u16`) - The participant identifier as a u16.
    ///
    /// # Errors
    /// * `Errors::InvalidProtocolInit` - If the identifier cannot be converted
    ///   to an Identifier (e.g. out of range).
    ///
    /// # Returns
    /// * `Identifier` - The FROST Identifier corresponding to the given
    ///   identifier.
    fn identifier_from_u16(
        identifier: u16,
    ) -> Result<Self::Identifier, Errors>;

    /// Execute DKG round 1: generate secret and public package.
    ///
    /// # Arguments
    /// * `identifier` (`Identifier`) - This participant's FROST Identifier.
    /// * `participants` (`u16`) - Total number of participants in the
    ///   protocol.
    /// * `threshold` (`u16`) - Threshold number of participants required to
    ///   sign.
    ///
    /// # Errors
    /// * `Errors::InvalidMessage` - If package generation fails.
    ///
    /// # Returns
    /// * `(Round1SecretPackage, Round1Package)` - The secret and public
    ///   packages produced in round 1.
    fn part1(
        identifier: Self::Identifier,
        participants: u16,
        threshold: u16,
    ) -> Result<(Self::Round1SecretPackage, Self::Round1Package), Errors>;

    /// Execute DKG round 2: compute round 2 packages from round 1 inputs.
    ///
    /// # Arguments
    /// * `secret` (`Round1SecretPackage`) - The secret package produced in
    ///   round 1.
    /// * `round1_packages` (`BTreeMap<Identifier, Round1Package>`) - Mapping
    ///   of peer Identifiers to their round 1 packages.
    ///
    /// # Errors
    /// * `Errors::InvalidMessage` - If round 2 package computation fails.
    ///
    /// # Returns
    /// * `(Round2SecretPackage, BTreeMap<Identifier, Round2Package>)` - The
    ///   round 2 secret package and mapping of peer Identifiers to their round
    ///   2 packages.
    fn part2(
        secret: Self::Round1SecretPackage,
        round1_packages: &BTreeMap<Self::Identifier, Self::Round1Package>,
    ) -> Result<
        (
            Self::Round2SecretPackage,
            BTreeMap<Self::Identifier, Self::Round2Package>,
        ),
        Errors,
    >;

    /// Execute DKG round 3: finalize and produce key packages.
    ///
    /// # Arguments
    /// * `round2_secret` (`Round2SecretPackage`) - The secret package produced
    ///   in round 2.
    /// * `round1_packages` (`BTreeMap<Identifier, Round1Package>`) - Mapping
    ///   of peer Identifiers to their round 1 packages.
    /// * `round2_packages` (`BTreeMap<Identifier, Round2Package>`) - Mapping
    ///   of peer Identifiers to their round 2 packages.
    ///
    /// # Errors
    /// * `Errors::InvalidMessage` - If finalization fails.
    ///
    /// # Returns
    /// * `(KeyPackage, PublicKeyPackage)` - The final key package for this
    ///   participant and the public key package for the group.
    fn part3(
        round2_secret: &Self::Round2SecretPackage,
        round1_packages: &BTreeMap<Self::Identifier, Self::Round1Package>,
        round2_packages: &BTreeMap<Self::Identifier, Self::Round2Package>,
    ) -> Result<(Self::KeyPackage, Self::PublicKeyPackage), Errors>;

    /// Serialize a round 1 package to bytes.
    ///
    /// # Arguments
    /// * `package` (`Round1Package`) - The round 1 package to serialize.
    ///
    /// # Errors
    /// * `Errors::InvalidMessage` - If serialization fails.
    ///
    /// # Returns
    /// * `Vec<u8>` - The serialized round 1 package.
    fn serialize_round1_package(
        package: &Self::Round1Package,
    ) -> Result<Vec<u8>, Errors>;

    /// Deserialize a round 1 package from bytes.
    ///
    /// # Arguments
    /// * `bytes` (`&[u8]`) - The bytes to deserialize.
    ///
    /// # Errors
    /// * `Errors::InvalidMessage` - If deserialization fails.
    ///
    /// # Returns
    /// * `Round1Package` - The deserialized round 1 package.
    fn deserialize_round1_package(
        bytes: &[u8],
    ) -> Result<Self::Round1Package, Errors>;

    /// Serialize a round 2 package to bytes.
    ///
    /// # Arguments
    /// * `package` (`Round2Package`) - The round 2 package to serialize.
    ///
    /// # Errors
    /// * `Errors::InvalidMessage` - If serialization fails.
    ///
    /// # Returns
    /// * `Vec<u8>` - The serialized round 2 package.
    fn serialize_round2_package(
        package: &Self::Round2Package,
    ) -> Result<Vec<u8>, Errors>;

    /// Deserialize a round 2 package from bytes.
    ///
    /// # Arguments
    /// * `bytes` (`&[u8]`) - The bytes to deserialize.
    ///
    /// # Errors
    /// * `Errors::InvalidMessage` - If deserialization fails.
    ///
    /// # Returns
    /// * `Round2Package` - The deserialized round 2 package.
    fn deserialize_round2_package(
        bytes: &[u8],
    ) -> Result<Self::Round2Package, Errors>;

    /// Serialize a key package to bytes.
    ///
    /// # Arguments
    /// * `package` (`KeyPackage`) - The key package to serialize.
    ///
    /// # Errors
    /// * `Errors::InvalidMessage` - If serialization fails.
    ///
    /// # Returns
    /// * `Vec<u8>` - The serialized key package.
    fn serialize_key_package(
        package: &Self::KeyPackage,
    ) -> Result<Vec<u8>, Errors>;

    /// Serialize a public key package to bytes.
    ///
    /// # Arguments
    /// * `package` (`PublicKeyPackage`) - The public key package to serialize.
    ///
    /// # Errors
    /// * `Errors::InvalidMessage` - If serialization fails.
    ///
    /// # Returns
    /// * `Vec<u8>` - The serialized public key package.
    fn serialize_public_key_package(
        package: &Self::PublicKeyPackage,
    ) -> Result<Vec<u8>, Errors>;

    /// Extract the raw verifying key bytes from a public key package.
    ///
    /// # Arguments
    /// * `package` (`PublicKeyPackage`) - The public key package to extract
    ///   from.
    ///
    /// # Errors
    /// * `Errors::InvalidMessage` - If extraction fails.
    ///
    /// # Returns
    /// * `Vec<u8>` - The raw verifying key bytes.
    fn verifying_key(
        package: &Self::PublicKeyPackage,
    ) -> Result<Vec<u8>, Errors>;
}

/// Participant-side FROST key generation protocol instance.
pub struct FrostNodeKeyGeneration<C: FrostCurve> {
    /// Unique key identifier.
    key_identifier: String,
    /// Minimum number of participants required to sign.
    threshold: u32,
    /// Total number of participants.
    participants: u32,
    /// Current protocol round.
    round: Round,
    /// This participant's FROST identifier.
    identifier: C::Identifier,
    /// This participant's identifier as u32.
    identifier_u32: u32,
    /// Learned mapping from FROST Identifier to u32 participant identifier.
    /// Populated during round 1 when packages from others arrive.
    identifier_map: BTreeMap<C::Identifier, u32>,
    /// Secret package produced in round 1, consumed in round 2.
    round1_secret: Option<C::Round1SecretPackage>,
    /// Secret package produced in round 2, consumed in round 3.
    round2_secret: Option<C::Round2SecretPackage>,
    /// Round 1 packages received from all other participants.
    received_round1: BTreeMap<C::Identifier, C::Round1Package>,
    /// Round 2 packages received from all other participants.
    received_round2: BTreeMap<C::Identifier, C::Round2Package>,
    /// Final key package, available after round 2 completes.
    key_package: Option<C::KeyPackage>,
    /// Final public key package, available after round 2 completes.
    public_key_package: Option<C::PublicKeyPackage>,
    /// True if the protocol has been aborted.
    aborted: bool,
}

impl<C: FrostCurve> FrostNodeKeyGeneration<C> {
    /// Try to create a new FROST node key generation protocol instance.
    ///
    /// # Arguments
    /// * `protocol_init` (`ProtocolInit`) - Protocol initialization context.
    ///
    /// # Errors
    /// * `Errors::InvalidProtocolInit` - If the init context is invalid.
    /// * `Errors::UnsupportedAlgorithm` - If the algorithm does not match the
    ///   curve.
    ///
    /// # Returns
    /// * `Self` - The initialized protocol instance ready to run.
    pub fn try_new(protocol_init: ProtocolInit) -> Result<Self, Errors> {
        let init: NodeKeyGenerationInit = match protocol_init {
            ProtocolInit::KeyGeneration(KeyGenerationInit::Node(init)) => init,
            _ => {
                return Err(Errors::InvalidProtocolInit(
                    "Expected node key generation init.".into(),
                ));
            },
        };

        if init.common.algorithm != C::algorithm() {
            return Err(Errors::UnsupportedAlgorithm(
                init.common.algorithm.as_str().into(),
            ));
        }

        let identifier: C::Identifier =
            C::identifier_from_u16(u16::try_from(init.identifier).map_err(
                |error: TryFromIntError| {
                    Errors::InvalidProtocolInit(format!(
                        "Failed to convert participant identifier to u16: {}",
                        error
                    ))
                },
            )?)?;

        // Initialize the identifier map with our own identifier.
        let mut identifier_map: BTreeMap<C::Identifier, u32> = BTreeMap::new();
        identifier_map.insert(identifier, init.identifier);

        Ok(Self {
            key_identifier: init.common.key_identifier,
            threshold: init.common.threshold,
            participants: init.common.participants,
            round: 0,
            identifier,
            identifier_u32: init.identifier,
            identifier_map,
            round1_secret: None,
            round2_secret: None,
            received_round1: BTreeMap::new(),
            received_round2: BTreeMap::new(),
            key_package: None,
            public_key_package: None,
            aborted: false,
        })
    }

    /// Convert a u32 participant identifier to a curve Identifier.
    ///
    /// # Arguments
    /// * `identifier` (`u32`) - The participant identifier as a u32.
    ///
    /// # Errors
    /// * `Errors::InvalidMessage` - If the identifier cannot be converted to a
    ///   curve Identifier (e.g. out of range).
    ///
    /// # Returns
    /// * `Identifier` - The curve Identifier corresponding to the given
    ///   participant identifier.
    fn identifier_from_u32(
        &self,
        identifier: u32,
    ) -> Result<C::Identifier, Errors> {
        C::identifier_from_u16(u16::try_from(identifier).map_err(
            |error: TryFromIntError| {
                Errors::InvalidMessage(format!(
                    "Failed to convert participant identifier {} to u16: {}",
                    identifier, error
                ))
            },
        )?)
    }
}

#[async_trait]
impl<C: FrostCurve> Protocol for FrostNodeKeyGeneration<C> {
    fn algorithm(&self) -> Algorithm {
        C::algorithm()
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

    /// Execute round 0 — generate the round 1 package and broadcast it.
    ///
    /// Only executes once (at round 0). Subsequent calls return `None`.
    async fn next_round(&mut self) -> Result<Option<RoundMessage>, Errors> {
        if self.aborted {
            return Err(Errors::Aborted("Protocol has been aborted.".into()));
        }

        if self.round != 0 {
            return Ok(None);
        }

        let participants: u16 = u16::try_from(self.participants).map_err(
            |error: TryFromIntError| {
                Errors::InvalidMessage(format!(
                    "Failed to convert participants count to u16: {}",
                    error
                ))
            },
        )?;

        let threshold: u16 = u16::try_from(self.threshold).map_err(
            |error: TryFromIntError| {
                Errors::InvalidMessage(format!(
                    "Failed to convert threshold to u16: {}",
                    error
                ))
            },
        )?;

        let (secret, package): (C::Round1SecretPackage, C::Round1Package) =
            C::part1(self.identifier, participants, threshold)?;

        self.round1_secret = Some(secret);
        self.round = 1;

        let payload: Vec<u8> = encode_wire(&FrostWire::DkgRound1Package {
            identifier: self.identifier_u32,
            package: C::serialize_round1_package(&package)?,
        })?;

        Ok(Some(RoundMessage {
            round: 0,
            from: Some(self.identifier_u32),
            to: None,
            payload,
        }))
    }

    /// Handle an incoming round message and advance the protocol state.
    ///
    /// - Round 1 (`DkgRound1Packages`): ingest all peers' round 1 packages,
    ///   run `part2`, and return the round 2 output packages.
    /// - Round 2 (`DkgRound2Packages`): ingest all peers' round 2 packages,
    ///   run `part3`, finalize DKG, and store key packages for `finalize()`.
    ///
    /// # Arguments
    /// * `message` (`RoundMessage`) - The incoming message to handle.
    ///
    /// # Errors
    /// * `Errors::Aborted` - If the protocol has been aborted.
    /// * `Errors::InvalidMessage` - If the message is invalid for the current
    ///   round (e.g. wrong payload, deserialization failure, unexpected
    ///   round).
    /// * `Errors::InvalidState` - If the protocol is in an invalid state to
    ///   handle the message (e.g. missing secrets, missing packages).
    ///
    /// # Returns
    /// * `Option<RoundMessage>` - The outgoing message to send in response, if
    ///  applicable (e.g. after round 1). `None` if no response message is
    /// needed (e.g. after round 2, waiting for finalization).
    async fn handle_message(
        &mut self,
        message: RoundMessage,
    ) -> Result<Option<RoundMessage>, Errors> {
        if self.aborted {
            return Err(Errors::Aborted("Protocol has been aborted.".into()));
        }

        let wire: FrostWire =
            decode_wire(&message.payload).map_err(|error: Errors| {
                Errors::InvalidMessage(format!(
                    "Failed to decode wire message: {}",
                    error
                ))
            })?;

        match (self.round, message.round, wire) {
            // Round 1: receive all round 1 packages, compute round 2 output.
            (1, 1, FrostWire::DkgRound1Packages { packages }) => {
                let secret: C::Round1SecretPackage =
                    self.round1_secret.take().ok_or_else(|| {
                        Errors::InvalidState("Missing round 1 secret.".into())
                    })?;

                self.received_round1.clear();

                for (from_u32, bytes) in packages {
                    // Skip our own package.
                    if from_u32 == self.identifier_u32 {
                        continue;
                    }

                    let from_identifier: C::Identifier =
                        self.identifier_from_u32(from_u32)?;

                    self.identifier_map.insert(from_identifier, from_u32);

                    let package: C::Round1Package =
                        C::deserialize_round1_package(&bytes)?;

                    self.received_round1.insert(from_identifier, package);
                }

                // Ensure all expected packages arrived.
                let expected: usize =
                    (self.participants as usize).saturating_sub(1);

                if self.received_round1.len() != expected {
                    return Err(Errors::InvalidState(format!(
                        "Expected {} round 1 packages, got {}.",
                        expected,
                        self.received_round1.len()
                    )));
                }

                let (round2_secret, round2_output): (
                    C::Round2SecretPackage,
                    BTreeMap<C::Identifier, C::Round2Package>,
                ) = C::part2(secret, &self.received_round1)?;

                self.round2_secret = Some(round2_secret);

                // Build the round 2 output payload — one package per peer.
                let mut packages: Vec<(u32, Vec<u8>)> = Vec::new();
                for (to_identifier, package) in round2_output {
                    let to_u32: u32 = *self
                        .identifier_map
                        .get(&to_identifier)
                        .ok_or_else(|| {
                            Errors::InvalidMessage(
                                "Missing identifier mapping for round 2 \
                                package."
                                    .into(),
                            )
                        })?;

                    packages.push((
                        to_u32,
                        C::serialize_round2_package(&package)?,
                    ));
                }

                self.round = 2;

                Ok(Some(RoundMessage {
                    round: 1,
                    from: Some(self.identifier_u32),
                    to: None,
                    payload: encode_wire(
                        &FrostWire::DkgRound2PackagesOutput { packages },
                    )?,
                }))
            },

            // Round 2: receive all round 2 packages, finalize DKG.
            (2, 2, FrostWire::DkgRound2Packages { packages }) => {
                let secret: &C::Round2SecretPackage =
                    self.round2_secret.as_ref().ok_or_else(|| {
                        Errors::InvalidState("Missing round 2 secret.".into())
                    })?;

                self.received_round2.clear();

                for (from_u32, bytes) in packages {
                    // Skip our own package.
                    if from_u32 == self.identifier_u32 {
                        continue;
                    }

                    let from_identifier: C::Identifier =
                        self.identifier_from_u32(from_u32)?;

                    self.identifier_map.insert(from_identifier, from_u32);

                    let package: C::Round2Package =
                        C::deserialize_round2_package(&bytes)?;

                    self.received_round2.insert(from_identifier, package);
                }

                // Ensure all expected packages arrived.
                let expected: usize =
                    (self.participants as usize).saturating_sub(1);

                if self.received_round2.len() != expected {
                    return Err(Errors::InvalidState(format!(
                        "Expected {} round 2 packages, got {}.",
                        expected,
                        self.received_round2.len()
                    )));
                }

                let (key_package, public_key_package): (
                    C::KeyPackage,
                    C::PublicKeyPackage,
                ) = C::part3(
                    secret,
                    &self.received_round1,
                    &self.received_round2,
                )?;

                self.key_package = Some(key_package);
                self.public_key_package = Some(public_key_package);

                // Empty payload — signals to the controller that this node
                // has completed DKG and is ready for finalization.
                Ok(Some(RoundMessage {
                    round: 2,
                    from: Some(self.identifier_u32),
                    to: None,
                    payload: vec![],
                }))
            },

            _ => Err(Errors::InvalidMessage(format!(
                "Unexpected message at round {} (message round {}).",
                self.round, message.round
            ))),
        }
    }

    /// Finalize the protocol — serialize and store the key share.
    ///
    /// Consumes the key packages produced in round 2 and serializes them
    /// into a `FrostStoredKey` for Vault storage.
    ///
    /// # Errors
    /// * `Errors::InvalidState` - If the protocol is not in a state that can
    ///   be finalized (e.g. missing key packages).
    /// * `Errors::InvalidMessage` - If serialization of the stored key fails.
    ///
    /// # Returns
    /// * `ProtocolOutput::KeyGeneration` - The protocol output containing the
    ///   key share and public key information.
    async fn finalize(&mut self) -> Result<ProtocolOutput, Errors> {
        let key_package: C::KeyPackage =
            self.key_package.take().ok_or_else(|| {
                Errors::InvalidState("Missing key package.".into())
            })?;

        let public_key_package: C::PublicKeyPackage =
            self.public_key_package.take().ok_or_else(|| {
                Errors::InvalidState("Missing public key package.".into())
            })?;

        let stored: FrostStoredKey = FrostStoredKey {
            identifier: self.identifier_u32,
            key_package: C::serialize_key_package(&key_package)?,
            public_key_package: C::serialize_public_key_package(
                &public_key_package,
            )?,
        };

        let archived: AlignedVec =
            to_bytes::<RkyvError>(&stored).map_err(|error: RkyvError| {
                Errors::InvalidMessage(format!(
                    "Failed to serialize stored key: {}",
                    error
                ))
            })?;

        Ok(ProtocolOutput::KeyGeneration {
            key_identifier: self.key_identifier.clone(),
            key_share: Some(Secret::new(archived.to_vec())),
            public_key: C::verifying_key(&public_key_package)?,
            public_key_package: C::serialize_public_key_package(
                &public_key_package,
            )?,
        })
    }

    fn abort(&mut self) {
        self.aborted = true;
    }
}
