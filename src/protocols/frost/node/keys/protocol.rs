//! FROST participant-side DKG (Distributed Key Generation).
//!
//! A single generic implementation shared across all FROST curve variants.
//! Each curve implements the `FrostCurve` trait to provide its concrete
//! cryptographic types and serialization logic.

use std::{collections::BTreeMap, num::TryFromIntError};

use async_trait::async_trait;
use frost_core::{
    Ciphersuite,
    Error,
    Identifier as FrostIdentifier,
    keys::{
        KeyPackage as FrostKeyPackage,
        PublicKeyPackage as FrostPublicKeyPackage,
        dkg::{
            part1,
            part2,
            part3,
            round1::{
                Package as Round1Package,
                SecretPackage as Round1SecretPackage,
            },
            round2::{
                Package as Round2Package,
                SecretPackage as Round2SecretPackage,
            },
        },
    },
};
use postcard::{Error as PostcardError, from_bytes, to_allocvec};
use rand_core::OsRng;
use rkyv::{rancor::Error as RkyvError, to_bytes, util::AlignedVec};
use zeroize::Zeroize;

use crate::{
    proto::engine::v1::RoundMessage,
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
/// implementation. Each curve (ed25519, secp256k1) implements this trait
/// to provide its concrete cryptographic types and serialization logic.
pub trait FrostCurve: Send + Sync + 'static {
    /// The frost_core Ciphersuite for this curve.
    type Curve: Ciphersuite + Send + Sync;

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
    /// * `FrostIdentifier<Self::Curve>` - The FROST Identifier corresponding
    ///   to the given identifier.
    fn identifier_from_u16(
        identifier: u16,
    ) -> Result<FrostIdentifier<Self::Curve>, Errors> {
        FrostIdentifier::<Self::Curve>::try_from(identifier).map_err(
            |error: <FrostIdentifier<Self::Curve> as TryFrom<u16>>::Error| {
                Errors::InvalidProtocolInit(format!(
                    "Failed to create FROST identifier from {}: {:?}",
                    identifier, error
                ))
            },
        )
    }

    /// Execute DKG round 1: generate secret and public package.
    ///
    /// # Arguments
    /// * `identifier` (`FrostIdentifier<Self::Curve>`) - This participant's
    ///   FROST Identifier.
    /// * `participants` (`u16`) - Total number of participants in the
    ///   protocol.
    /// * `threshold` (`u16`) - Threshold number of participants required to
    ///   sign.
    ///
    /// # Errors
    /// * `Errors::InvalidMessage` - If package generation fails.
    ///
    /// # Returns
    /// * `(Round1SecretPackage<Self::Curve>, Round1Package<Self::Curve>)` -
    ///   The secret and public packages produced in round 1.
    fn part1(
        identifier: FrostIdentifier<Self::Curve>,
        participants: u16,
        threshold: u16,
    ) -> Result<
        (Round1SecretPackage<Self::Curve>, Round1Package<Self::Curve>),
        Errors,
    > {
        part1(identifier, participants, threshold, OsRng).map_err(
            |error: Error<Self::Curve>| {
                Errors::InvalidMessage(format!(
                    "Failed to generate round 1 secret and package: {}",
                    error
                ))
            },
        )
    }

    /// Execute DKG round 2: compute round 2 packages from round 1 inputs.
    ///
    /// # Arguments
    /// * `secret` (`Round1SecretPackage<Self::Curve>`) - The secret package
    ///   produced in round 1.
    /// * `round1_packages` (`&BTreeMap<FrostIdentifier<Self::Curve>,
    ///   Round1Package<Self::Curve>>`) - Mapping of peer Identifiers to their
    ///   round 1 packages.
    ///
    /// # Errors
    /// * `Errors::InvalidMessage` - If round 2 package computation fails.
    ///
    /// # Returns
    /// * `(Round2SecretPackage<Self::Curve>, BTreeMap<FrostIdentifier
    ///   Self::Curve>, Round2Package<Self::Curve>>)` - The round 2 secret
    ///   package and mapping of peer Identifiers to their round 2 packages.
    fn part2(
        secret: Round1SecretPackage<Self::Curve>,
        round1_packages: &BTreeMap<
            FrostIdentifier<Self::Curve>,
            Round1Package<Self::Curve>,
        >,
    ) -> Result<
        (
            Round2SecretPackage<Self::Curve>,
            BTreeMap<FrostIdentifier<Self::Curve>, Round2Package<Self::Curve>>,
        ),
        Errors,
    > {
        part2(secret, round1_packages).map_err(|error: Error<Self::Curve>| {
            Errors::InvalidMessage(format!(
                "Failed to compute round 2 packages: {}",
                error
            ))
        })
    }

    /// Execute DKG round 3: finalize and produce key packages.
    ///
    /// # Arguments
    /// * `round2_secret` (`&Round2SecretPackage<Self::Curve>`) - The secret
    ///   package produced in round 2.
    /// * `round1_packages` (`&BTreeMap<FrostIdentifier<Self::Curve>,
    ///   Round1Package<Self::Curve>>`) - Mapping of peer Identifiers to their
    ///   round 1 packages.
    /// * `round2_packages` (`&BTreeMap<FrostIdentifier<Self::Curve>,
    ///   Round2Package<Self::Curve>>`) - Mapping of peer Identifiers to their
    ///   round 2 packages.
    ///
    /// # Errors
    /// * `Errors::InvalidMessage` - If finalization fails.
    ///
    /// # Returns
    /// * `(FrostKeyPackage<Self::Curve>, FrostPublicKeyPackage<Self::Curve>)`
    ///   - The final key package for this participant and the public key
    ///     package for the group.
    fn part3(
        round2_secret: &Round2SecretPackage<Self::Curve>,
        round1_packages: &BTreeMap<
            FrostIdentifier<Self::Curve>,
            Round1Package<Self::Curve>,
        >,
        round2_packages: &BTreeMap<
            FrostIdentifier<Self::Curve>,
            Round2Package<Self::Curve>,
        >,
    ) -> Result<
        (FrostKeyPackage<Self::Curve>, FrostPublicKeyPackage<Self::Curve>),
        Errors,
    > {
        part3(round2_secret, round1_packages, round2_packages).map_err(
            |error: Error<Self::Curve>| {
                Errors::InvalidMessage(format!(
                    "Failed to finalize DKG: {}",
                    error
                ))
            },
        )
    }

    /// Serialize a round 1 package to postcard bytes.
    ///
    /// # Arguments
    /// * `package` (`&Round1Package<Self::Curve>`) - The round 1 package to
    ///   serialize.
    ///
    /// # Errors
    /// * `Errors::InvalidMessage` - If serialization fails.
    ///
    /// # Returns
    /// * `Vec<u8>` - The serialized round 1 package.
    fn serialize_round1_package(
        package: &Round1Package<Self::Curve>,
    ) -> Result<Vec<u8>, Errors> {
        to_allocvec(package).map_err(|error: PostcardError| {
            Errors::InvalidMessage(format!(
                "Failed to serialize round 1 package: {}",
                error
            ))
        })
    }

    /// Deserialize a round 1 package from postcard bytes.
    ///
    /// # Arguments
    /// * `bytes` (`&[u8]`) - The bytes to deserialize.
    ///
    /// # Errors
    /// * `Errors::InvalidMessage` - If deserialization fails.
    ///
    /// # Returns
    /// * `Round1Package<Self::Curve>` - The deserialized round 1 package.
    fn deserialize_round1_package(
        bytes: &[u8],
    ) -> Result<Round1Package<Self::Curve>, Errors> {
        from_bytes(bytes).map_err(|error: PostcardError| {
            Errors::InvalidMessage(format!(
                "Failed to deserialize round 1 package: {}",
                error
            ))
        })
    }

    /// Serialize a round 2 package to postcard bytes.
    ///
    /// # Arguments
    /// * `package` (`&Round2Package<Self::Curve>`) - The round 2 package to
    ///   serialize.
    ///
    /// # Errors
    /// * `Errors::InvalidMessage` - If serialization fails.
    ///
    /// # Returns
    /// * `Vec<u8>` - The serialized round 2 package.
    fn serialize_round2_package(
        package: &Round2Package<Self::Curve>,
    ) -> Result<Vec<u8>, Errors> {
        to_allocvec(package).map_err(|error: PostcardError| {
            Errors::InvalidMessage(format!(
                "Failed to serialize round 2 package: {}",
                error
            ))
        })
    }

    /// Deserialize a round 2 package from postcard bytes.
    ///
    /// # Arguments
    /// * `bytes` (`&[u8]`) - The bytes to deserialize.
    ///
    /// # Errors
    /// * `Errors::InvalidMessage` - If deserialization fails.
    ///
    /// # Returns
    /// * `Round2Package<Self::Curve>` - The deserialized round 2 package.
    fn deserialize_round2_package(
        bytes: &[u8],
    ) -> Result<Round2Package<Self::Curve>, Errors> {
        from_bytes(bytes).map_err(|error: PostcardError| {
            Errors::InvalidMessage(format!(
                "Failed to deserialize round 2 package: {}",
                error
            ))
        })
    }

    /// Serialize a key package to postcard bytes.
    ///
    /// # Arguments
    /// * `package` (`&FrostKeyPackage<Self::Curve>`) - The key package to
    ///   serialize.
    ///
    /// # Errors
    /// * `Errors::InvalidMessage` - If serialization fails.
    ///
    /// # Returns
    /// * `Vec<u8>` - The serialized key package.
    fn serialize_key_package(
        package: &FrostKeyPackage<Self::Curve>,
    ) -> Result<Vec<u8>, Errors> {
        to_allocvec(package).map_err(|error: PostcardError| {
            Errors::InvalidMessage(format!(
                "Failed to serialize key package: {}",
                error
            ))
        })
    }

    /// Serialize a public key package to postcard bytes.
    ///
    /// # Arguments
    /// * `package` (`&FrostPublicKeyPackage<Self::Curve>`) - The public key
    ///   package to serialize.
    ///
    /// # Errors
    /// * `Errors::InvalidMessage` - If serialization fails.
    ///
    /// # Returns
    /// * `Vec<u8>` - The serialized public key package.
    fn serialize_public_key_package(
        package: &FrostPublicKeyPackage<Self::Curve>,
    ) -> Result<Vec<u8>, Errors> {
        to_allocvec(package).map_err(|error: PostcardError| {
            Errors::InvalidMessage(format!(
                "Failed to serialize public key package: {}",
                error
            ))
        })
    }

    /// Extract the raw verifying key bytes from a public key package.
    ///
    /// # Arguments
    /// * `package` (`&FrostPublicKeyPackage<Self::Curve>`) - The public key
    ///   package to extract from.
    ///
    /// # Errors
    /// * `Errors::InvalidMessage` - If extraction fails.
    ///
    /// # Returns
    /// * `Vec<u8>` - The raw verifying key bytes.
    fn verifying_key(
        package: &FrostPublicKeyPackage<Self::Curve>,
    ) -> Result<Vec<u8>, Errors> {
        package.verifying_key().serialize().map_err(
            |error: Error<Self::Curve>| {
                Errors::InvalidMessage(format!(
                    "Failed to serialize verifying key: {}",
                    error
                ))
            },
        )
    }
}

/// Participant-side FROST key generation protocol instance.
pub struct FrostNodeKeyGeneration<C: FrostCurve> {
    /// The algorithm identifier for this protocol instance.
    algorithm: Algorithm,
    /// Unique key identifier.
    key_identifier: String,
    /// Minimum number of participants required to sign.
    threshold: u32,
    /// Total number of participants.
    participants: u32,
    /// Current protocol round.
    round: Round,
    /// This participant's FROST identifier.
    identifier: FrostIdentifier<C::Curve>,
    /// This participant's identifier as u32.
    identifier_u32: u32,
    /// Learned mapping from FROST Identifier to u32 participant identifier.
    /// Populated during round 1 when packages from others arrive.
    identifier_map: BTreeMap<FrostIdentifier<C::Curve>, u32>,
    /// Secret package produced in round 1, consumed in round 2.
    round1_secret: Option<Round1SecretPackage<C::Curve>>,
    /// Secret package produced in round 2, consumed in round 3.
    round2_secret: Option<Secret<Round2SecretPackage<C::Curve>>>,
    /// Round 1 packages received from all other participants.
    received_round1:
        BTreeMap<FrostIdentifier<C::Curve>, Round1Package<C::Curve>>,
    /// Round 2 packages received from all other participants.
    received_round2:
        BTreeMap<FrostIdentifier<C::Curve>, Round2Package<C::Curve>>,
    /// Final key package, available after round 2 completes.
    key_package: Option<FrostKeyPackage<C::Curve>>,
    /// Final public key package, available after round 2 completes.
    public_key_package: Option<FrostPublicKeyPackage<C::Curve>>,
    /// True if the protocol has been aborted.
    aborted: bool,
}

impl<C: FrostCurve> FrostNodeKeyGeneration<C>
where
    FrostIdentifier<C::Curve>: Send + Sync,
    Round1Package<C::Curve>: Send + Sync,
    Round2Package<C::Curve>: Send + Sync,
    Round1SecretPackage<C::Curve>: Send + Sync,
    Round2SecretPackage<C::Curve>: Send + Sync + Zeroize,
    FrostKeyPackage<C::Curve>: Send + Sync,
    FrostPublicKeyPackage<C::Curve>: Send + Sync,
{
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

        let identifier: FrostIdentifier<C::Curve> =
            C::identifier_from_u16(u16::try_from(init.identifier).map_err(
                |error: TryFromIntError| {
                    Errors::InvalidProtocolInit(format!(
                        "Failed to convert participant identifier to u16: {}",
                        error
                    ))
                },
            )?)?;

        Ok(Self {
            algorithm: init.common.algorithm,
            key_identifier: init.common.key_identifier,
            threshold: init.common.threshold,
            participants: init.common.participants,
            round: 0,
            identifier,
            identifier_u32: init.identifier,
            identifier_map: BTreeMap::new(),
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
    /// * `Errors::InvalidMessage` - If the identifier cannot be converted.
    ///
    /// # Returns
    /// * `FrostIdentifier<C::Curve>` - The curve Identifier corresponding to
    ///   the given participant identifier.
    fn identifier_from_u32(
        identifier: u32,
    ) -> Result<FrostIdentifier<C::Curve>, Errors> {
        C::identifier_from_u16(u16::try_from(identifier).map_err(
            |error: TryFromIntError| {
                Errors::InvalidMessage(format!(
                    "Failed to convert participant identifier {} to u16: {}",
                    identifier, error
                ))
            },
        )?)
    }

    /// Ingest a set of round 1 packages from peers, skipping our own entry,
    /// and populate `received_round1` and `identifier_map`.
    ///
    /// # Arguments
    /// * `packages` (`Vec<(u32, Vec<u8>)>`) - Pairs of (sender_u32, bytes).
    ///
    /// # Errors
    /// * `Errors::InvalidMessage` - If any package cannot be deserialized or
    ///   its identifier cannot be converted.
    fn ingest_round1_packages(
        &mut self,
        packages: Vec<(u32, Vec<u8>)>,
    ) -> Result<(), Errors> {
        packages
            .into_iter()
            // Skip our own package — we don't process messages from ourselves.
            .filter(|(from_u32, _): &(u32, Vec<u8>)| {
                *from_u32 != self.identifier_u32
            })
            .try_for_each(|(from_u32, bytes): (u32, Vec<u8>)| {
                let from_identifier: FrostIdentifier<C::Curve> =
                    Self::identifier_from_u32(from_u32)?;

                // Record the mapping from FROST Identifier to u32 —
                // needed in round 2 to route packages to their targets.
                self.identifier_map.insert(from_identifier, from_u32);

                let package: Round1Package<C::Curve> =
                    C::deserialize_round1_package(&bytes)?;

                self.received_round1.insert(from_identifier, package);

                Ok(())
            })
    }

    /// Ingest a set of round 2 packages from peers, skipping our own entry,
    /// and populate `received_round2` and `identifier_map`.
    ///
    /// # Arguments
    /// * `packages` (`Vec<(u32, Vec<u8>)>`) - Pairs of (sender_u32, bytes).
    ///
    /// # Errors
    /// * `Errors::InvalidMessage` - If any package cannot be deserialized or
    ///   its identifier cannot be converted.
    fn ingest_round2_packages(
        &mut self,
        packages: Vec<(u32, Vec<u8>)>,
    ) -> Result<(), Errors> {
        packages
            .into_iter()
            // Skip our own package — we don't process messages from ourselves.
            .filter(|(from_u32, _): &(u32, Vec<u8>)| {
                *from_u32 != self.identifier_u32
            })
            .try_for_each(|(from_u32, bytes): (u32, Vec<u8>)| {
                let from_identifier: FrostIdentifier<C::Curve> =
                    Self::identifier_from_u32(from_u32)?;

                self.identifier_map.insert(from_identifier, from_u32);

                let package: Round2Package<C::Curve> =
                    C::deserialize_round2_package(&bytes)?;

                self.received_round2.insert(from_identifier, package);

                Ok(())
            })
    }

    /// Serialize the round 2 output packages into wire-format pairs.
    ///
    /// Maps each `(FrostIdentifier, Round2Package)` produced by `part2` into
    /// a `(to_u32, bytes)` pair using `identifier_map` for routing.
    ///
    /// # Arguments
    /// * `round2_output` (`BTreeMap<FrostIdentifier<C::Curve>,
    ///   Round2Package<C::Curve>>`) - Output packages from `part2`.
    ///
    /// # Errors
    /// * `Errors::InvalidMessage` - If any package cannot be serialized or its
    ///   target identifier is missing from `identifier_map`.
    ///
    /// # Returns
    /// * `Vec<(u32, Vec<u8>)>` - Wire-format pairs ready for broadcast.
    fn build_round2_output(
        &self,
        round2_output: BTreeMap<
            FrostIdentifier<C::Curve>,
            Round2Package<C::Curve>,
        >,
    ) -> Result<Vec<(u32, Vec<u8>)>, Errors> {
        round2_output
            .into_iter()
            .map(
                |(to_identifier, package): (
                    FrostIdentifier<C::Curve>,
                    Round2Package<C::Curve>,
                )| {
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

                    Ok((to_u32, C::serialize_round2_package(&package)?))
                },
            )
            .collect()
    }
}

#[async_trait]
impl<C: FrostCurve> Protocol for FrostNodeKeyGeneration<C>
where
    FrostIdentifier<C::Curve>: Send + Sync,
    Round1Package<C::Curve>: Send + Sync,
    Round2Package<C::Curve>: Send + Sync,
    Round1SecretPackage<C::Curve>: Send + Sync,
    Round2SecretPackage<C::Curve>: Send + Sync + Zeroize,
    FrostKeyPackage<C::Curve>: Send + Sync,
    FrostPublicKeyPackage<C::Curve>: Send + Sync,
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

        let (secret, package): (
            Round1SecretPackage<C::Curve>,
            Round1Package<C::Curve>,
        ) = C::part1(self.identifier, participants, threshold)?;

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
    ///   round.
    /// * `Errors::InvalidState` - If the protocol is in an invalid state to
    ///   handle the message.
    ///
    /// # Returns
    /// * `Option<RoundMessage>` - The outgoing message to send in response, if
    ///   applicable. `None` if no response is needed.
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
            (1, 1, FrostWire::DkgRound1Packages { packages }) => {
                let secret: Round1SecretPackage<C::Curve> =
                    self.round1_secret.take().ok_or_else(|| {
                        Errors::InvalidState("Missing round 1 secret.".into())
                    })?;

                // Ingest all peers' round 1 packages into `received_round1`
                // and populate `identifier_map` for routing in round 2.
                self.ingest_round1_packages(packages)?;

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
                    Round2SecretPackage<C::Curve>,
                    BTreeMap<
                        FrostIdentifier<C::Curve>,
                        Round2Package<C::Curve>,
                    >,
                ) = C::part2(secret, &self.received_round1)?;

                self.round2_secret = Some(Secret::new(round2_secret));

                // Serialize round 2 output packages and resolve their target
                // u32 identifiers using `identifier_map`.
                let packages: Vec<(u32, Vec<u8>)> =
                    self.build_round2_output(round2_output)?;

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

            (2, 2, FrostWire::DkgRound2Packages { packages }) => {
                // Take the secret temporarily — released before the mutable
                // borrow in ingest_round2_packages to avoid a
                // simultaneous borrow conflict.
                let secret: Secret<Round2SecretPackage<C::Curve>> =
                    self.round2_secret.take().ok_or_else(|| {
                        Errors::InvalidState("Missing round 2 secret.".into())
                    })?;

                // Ingest all peers' round 2 packages into `received_round2`.
                self.ingest_round2_packages(packages)?;

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
                    FrostKeyPackage<C::Curve>,
                    FrostPublicKeyPackage<C::Curve>,
                ) = secret.with_ref(
                    |secret: &Round2SecretPackage<C::Curve>| {
                        C::part3(
                            secret,
                            &self.received_round1,
                            &self.received_round2,
                        )
                    },
                )?;

                self.key_package = Some(key_package);
                self.public_key_package = Some(public_key_package);

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
    ///   be finalized.
    /// * `Errors::InvalidMessage` - If serialization of the stored key fails.
    ///
    /// # Returns
    /// * `ProtocolOutput::KeyGeneration` - The protocol output containing the
    ///   key share and public key information.
    async fn finalize(&mut self) -> Result<ProtocolOutput, Errors> {
        let key_package: FrostKeyPackage<C::Curve> =
            self.key_package.take().ok_or_else(|| {
                Errors::InvalidState("Missing key package.".into())
            })?;

        let public_key_package: FrostPublicKeyPackage<C::Curve> =
            self.public_key_package.take().ok_or_else(|| {
                Errors::InvalidState("Missing public key package.".into())
            })?;

        // Serialize once and reuse for both FrostStoredKey and
        // ProtocolOutput to avoid redundant serialization.
        let public_key_package_bytes: Vec<u8> =
            C::serialize_public_key_package(&public_key_package)?;

        let stored: FrostStoredKey = FrostStoredKey {
            identifier: self.identifier_u32,
            key_package: C::serialize_key_package(&key_package)?,
            public_key_package: public_key_package_bytes.clone(),
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
            public_key_package: public_key_package_bytes,
        })
    }

    fn abort(&mut self) {
        self.aborted = true;
        // Explicitly drop secrets — triggers ZeroizeOnDrop for round1_secret
        // and Secret's Drop impl (which calls zeroize) for round2_secret.
        self.round1_secret = None;
        self.round2_secret = None;
    }
}
