//! Frost-secp256k1 participant-side DKG (Distributed Key Generation).

use std::{collections::BTreeMap, num::TryFromIntError};

use async_trait::async_trait;
use frost_secp256k1::{
    Error,
    Identifier,
    keys::{
        KeyPackage,
        PublicKeyPackage,
        dkg::{part1, part2, part3, round1, round2},
    },
    rand_core::OsRng,
};
use postcard::{Error as PostcardError, from_bytes, to_allocvec};
use rkyv::{rancor::Error as RkyvError, to_bytes, util::AlignedVec};

use crate::{
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
            RoundMessage,
        },
    },
    secrets::secret::Secret,
    transport::errors::Errors,
};

/// Participant-side FROST(secp256k1) key generation protocol instance.
pub struct FrostSchnorrSecp256k1NodeKeyGeneration {
    /// Unique key identifier.
    pub key_id: String,
    /// Number of participants required to sign.
    pub threshold: u32,
    /// Total number of participants.
    pub participants: u32,
    /// Current protocol round.
    pub round: Round,
    /// Participant's FROST Identifier.
    pub identifier: Identifier,
    /// Participant's identifier as u32.
    pub identifier_u32: u32,
    /// Learned mapping Identifier -> u32
    pub identifier_map: BTreeMap<Identifier, u32>,
    /// Secret package from round 1.
    pub round1_secret: Option<round1::SecretPackage>,
    /// Secret package from round 2.
    pub round2_secret: Option<round2::SecretPackage>,
    /// Record of received round1 packages from other participants (n - 1).
    pub received_round1: BTreeMap<Identifier, round1::Package>,
    /// Record of received round2 packages from other participants (n - 1).
    pub received_round2: BTreeMap<Identifier, round2::Package>,
    /// Final key package.
    pub key_package: Option<KeyPackage>,
    /// Final public key package.
    pub public_key_package: Option<PublicKeyPackage>,
    /// Indicates if the protocol has been aborted.
    pub aborted: bool,
}

impl FrostSchnorrSecp256k1NodeKeyGeneration {
    /// Try to create a new FROST(secp256k1) protocol instance.
    ///
    /// # Arguments
    /// * `protocol_init` (`ProtocolInit`) - Protocol initialization context.
    ///
    /// # Errors
    /// * `Error` - If initialization fails.
    ///
    /// # Returns
    /// * `Result<Self, Error>` - New protocol instance or error.
    pub fn try_new(protocol_init: ProtocolInit) -> Result<Self, Errors> {
        let init: NodeKeyGenerationInit = match protocol_init {
            ProtocolInit::KeyGeneration(KeyGenerationInit::Node(init)) => init,
            _ => {
                return Err(Errors::InvalidProtocolInit(
                    "Expected node key generation init.".into(),
                ));
            },
        };

        if init.common.algorithm != Algorithm::FrostSchnorrSecp256k1 {
            return Err(Errors::UnsupportedAlgorithm(
                init.common.algorithm.as_str().into(),
            ));
        }

        let identifier: Identifier =
            Identifier::try_from(u16::try_from(init.identifier).map_err(
                |error: TryFromIntError| {
                    Errors::InvalidProtocolInit(format!(
                        "Failed to convert identifier to u16: {}",
                        error
                    ))
                },
            )?)
            .map_err(|error: Error| {
                Errors::InvalidProtocolInit(format!(
                    "Failed to create FROST Identifier: {}",
                    error
                ))
            })?;

        // Initialize identifier/identifier_u32 map.
        let mut identifier_map: BTreeMap<Identifier, u32> = BTreeMap::new();
        identifier_map.insert(identifier, init.identifier);

        Ok(Self {
            key_id: init.common.key_id,
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
}

#[async_trait]
impl Protocol for FrostSchnorrSecp256k1NodeKeyGeneration {
    /// Return the algorithm identifier.
    ///
    /// # Returns
    /// * `Algorithm` - Algorithm identifier.
    fn algorithm(&self) -> Algorithm {
        Algorithm::FrostSchnorrSecp256k1
    }

    /// Return the threshold required for operation.
    ///
    /// # Returns
    /// * `u32` - Threshold number of participants.
    fn threshold(&self) -> u32 {
        self.threshold
    }

    /// Return the total number of participants.
    ///
    /// # Returns
    /// * `u32` - Total number of participants.
    fn participants(&self) -> u32 {
        self.participants
    }

    /// Return the current round number.
    ///
    /// # Returns
    /// * `Round` - Current round number.
    fn current_round(&self) -> Round {
        self.round
    }

    /// Advance the protocol without receiving a message.
    ///
    /// # Returns
    /// * `Option<RoundMessage>` - Message to broadcast for the next round.
    ///
    /// # Errors
    /// * `Error` - If advancing the round fails.
    async fn next_round(&mut self) -> Result<Option<RoundMessage>, Errors> {
        if self.aborted {
            return Err(Errors::Aborted("Protocol has been aborted.".into()));
        }
        if self.round != 0 {
            return Ok(None);
        }

        let (secret, package): (round1::SecretPackage, round1::Package) =
            part1(
                self.identifier,
                u16::try_from(self.participants).map_err(
                    |error: TryFromIntError| {
                        Errors::InvalidMessage(format!(
                            "Failed to convert participants count to u16: {}",
                            error
                        ))
                    },
                )?,
                u16::try_from(self.threshold).map_err(
                    |error: TryFromIntError| {
                        Errors::InvalidMessage(format!(
                            "Failed to convert threshold to u16: {}",
                            error
                        ))
                    },
                )?,
                OsRng,
            )
            .map_err(|error: Error| {
                Errors::InvalidMessage(format!(
                    "Failed to generate round 1 secret and package: {}",
                    error
                ))
            })?;

        self.round1_secret = Some(secret);
        self.round = 1;

        let payload: Vec<u8> = encode_wire(&FrostWire::DkgRound1Package {
            identifier: self.identifier_u32,
            package: to_allocvec(&package).map_err(
                |error: PostcardError| {
                    Errors::InvalidMessage(format!(
                        "Failed to encode round 1 package: {}",
                        error
                    ))
                },
            )?,
        })?;

        Ok(Some(RoundMessage {
            round: 0,
            from: Some(self.identifier_u32),
            to: None,
            payload,
        }))
    }

    /// Handle an incoming round message.
    ///
    /// # Arguments
    /// * `message` (`RoundMessage`) - Incoming round message.
    ///
    /// # Errors
    /// * `Error` - If handling the message fails.
    ///
    /// # Returns
    /// * `Option<RoundMessage>` - Message to send for the next round, if any.
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
            // Round 1: receive round1 packages from others.
            (1, 1, FrostWire::DkgRound1Packages { packages }) => {
                let secret: round1::SecretPackage =
                    self.round1_secret.take().ok_or_else(|| {
                        Errors::InvalidState("Missing round 1 secret.".into())
                    })?;

                // Ingest packages from others.
                self.received_round1.clear();
                for (from_u32, bytes) in packages {
                    if from_u32 == self.identifier_u32 {
                        continue;
                    }

                    let from_identifier: Identifier = Identifier::try_from(
                        u16::try_from(from_u32).map_err(
                            |error: TryFromIntError| {
                                Errors::InvalidMessage(format!(
                                    "Failed to convert from_u32 to u16: {}",
                                    error
                                ))
                            },
                        )?,
                    )
                    .map_err(|error: Error| {
                        Errors::InvalidMessage(format!(
                            "Failed to create Identifier from u16: {}",
                            error
                        ))
                    })?;

                    self.identifier_map.insert(from_identifier, from_u32);

                    let package: round1::Package = from_bytes(&bytes)
                        .map_err(|error: PostcardError| {
                            Errors::InvalidMessage(format!(
                                "Failed to decode round 1 package: {}",
                                error
                            ))
                        })?;
                    self.received_round1.insert(from_identifier, package);
                }

                // Verify we have all expected packages.
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
                    round2::SecretPackage,
                    BTreeMap<Identifier, round2::Package>,
                ) = part2(secret, &self.received_round1).map_err(
                    |error: Error| {
                        Errors::InvalidMessage(format!(
                            "Failed to generate round 2 output: {}",
                            error
                        ))
                    },
                )?;

                self.round2_secret = Some(round2_secret);

                // Round 2: send packages to others.
                let mut packages: Vec<(u32, Vec<u8>)> = Vec::new();
                for (to_id, package) in round2_output {
                    packages.push((
                        *self
                            .identifier_map
                            .get(&to_id)
                            .ok_or(Errors::InvalidMessage(
                            "Missing identifier mapping for round 2 output."
                                .into(),
                        ))?,
                        to_allocvec(&package).map_err(
                            |error: PostcardError| {
                                Errors::InvalidMessage(format!(
                                    "Failed to encode round 2 package: {}",
                                    error
                                ))
                            },
                        )?,
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

            // Round 2: receive packages from others.
            (2, 2, FrostWire::DkgRound2Packages { packages }) => {
                let secret: &round2::SecretPackage =
                    self.round2_secret.as_ref().ok_or_else(|| {
                        Errors::InvalidState("Missing round 2 secret.".into())
                    })?;

                // Ingest packages from others.
                self.received_round2.clear();
                for (from_u32, bytes) in packages {
                    if from_u32 == self.identifier_u32 {
                        continue;
                    }

                    let from_identifier: Identifier = Identifier::try_from(
                        u16::try_from(from_u32).map_err(
                            |error: TryFromIntError| {
                                Errors::InvalidMessage(format!(
                                    "Failed to convert from_u32 to u16: {}",
                                    error
                                ))
                            },
                        )?,
                    )
                    .map_err(|error: Error| {
                        Errors::InvalidMessage(format!(
                            "Failed to convert u16 to Identifier: {}",
                            error
                        ))
                    })?;

                    self.identifier_map.insert(from_identifier, from_u32);

                    let package: round2::Package = from_bytes(&bytes)
                        .map_err(|error: PostcardError| {
                            Errors::InvalidMessage(format!(
                                "Failed to decode round 2 package: {}",
                                error
                            ))
                        })?;
                    self.received_round2.insert(from_identifier, package);
                }

                // Verify we have all expected packages.
                let expected: usize =
                    (self.participants as usize).saturating_sub(1);

                if self.received_round2.len() != expected {
                    return Err(Errors::InvalidState(format!(
                        "Expected {} round 2 packages, got {}.",
                        expected,
                        self.received_round2.len()
                    )));
                }

                // Finalize DKG.
                let (key_package, public_key_package): (
                    KeyPackage,
                    PublicKeyPackage,
                ) = part3(
                    secret,
                    &self.received_round1,
                    &self.received_round2,
                )
                .map_err(|error: Error| {
                    Errors::InvalidMessage(format!(
                        "Failed to finalize DKG: {}",
                        error
                    ))
                })?;

                self.key_package = Some(key_package);
                self.public_key_package = Some(public_key_package);

                Ok(Some(RoundMessage {
                    round: 2,
                    from: Some(self.identifier_u32),
                    to: None,
                    payload: vec![],
                }))
            },

            _ => Err(Errors::InvalidMessage("Unexpected message.".into())),
        }
    }

    /// Finalize the protocol and produce the output.
    ///
    /// # Errors
    /// * `Error` - If finalization fails.
    ///
    /// # Returns
    /// * `ProtocolOutput` - Final protocol output.
    async fn finalize(&mut self) -> Result<ProtocolOutput, Errors> {
        let key_package: KeyPackage =
            self.key_package.take().ok_or_else(|| {
                Errors::InvalidState("Missing key package.".into())
            })?;

        let public_key_package: PublicKeyPackage =
            self.public_key_package.take().ok_or_else(|| {
                Errors::InvalidState("Missing public key package.".into())
            })?;

        let stored: FrostStoredKey = FrostStoredKey {
            identifier: self.identifier_u32,
            key_package: to_allocvec(&key_package).map_err(
                |error: PostcardError| {
                    Errors::InvalidMessage(format!(
                        "Failed to convert key package to allocvec: {}",
                        error
                    ))
                },
            )?,
            public_key_package: to_allocvec(&public_key_package).map_err(
                |error: PostcardError| {
                    Errors::InvalidMessage(format!(
                        "Failed to convert public key package to allocvec: {}",
                        error
                    ))
                },
            )?,
        };

        let archived: AlignedVec =
            to_bytes::<RkyvError>(&stored).map_err(|error: RkyvError| {
                Errors::InvalidMessage(format!(
                    "Failed to convert stored key to bytes: {}",
                    error
                ))
            })?;

        Ok(ProtocolOutput::KeyGeneration {
            key_id: self.key_id.clone(),
            key_share: Some(Secret::new(archived.to_vec())),
            public_key: public_key_package
                .verifying_key()
                .serialize()
                .map_err(|error: Error| {
                    Errors::InvalidMessage(format!(
                        "Failed to serialize public key: {}",
                        error
                    ))
                })?,
            public_key_package: to_allocvec(&public_key_package).map_err(
                |error: PostcardError| {
                    Errors::InvalidMessage(format!(
                        "Failed to convert public key package to allocvec: {}",
                        error
                    ))
                },
            )?,
        })
    }

    /// Abort the protocol.
    fn abort(&mut self) {
        self.aborted = true;
    }
}
