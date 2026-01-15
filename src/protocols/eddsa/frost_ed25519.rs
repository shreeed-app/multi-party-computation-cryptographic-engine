//! Frost-ed25519 participant-side protocol implementation.

use frost_ed25519::keys::KeyPackage;
use frost_ed25519::rand_core::OsRng;
use frost_ed25519::round1::{SigningCommitments, SigningNonces};
use frost_ed25519::round2::SignatureShare;
use frost_ed25519::{Identifier, SigningPackage, round1, round2};

use rkyv::rancor::Error as RkyvError;
use rkyv::{
    Archive, Archived, Deserialize, Serialize, access, deserialize, to_bytes,
};

use crate::messages::error::Error;
use crate::protocols::algorithm::Algorithm;
use crate::protocols::signing::SigningProtocol;
use crate::protocols::types::{ProtocolInit, Round, RoundMessage, Signature};

/// Wire messages exchanged between orchestrator and peer for FROST(Ed25519).
/// Round 0 (peer -> orchestrator): publish commitments.
/// Round 1 (orchestrator -> peer): send signing package.
/// Round 1 response (peer -> orchestrator): signature share.
#[derive(Debug, PartialEq, Archive, Serialize, Deserialize)]
enum FrostWire {
    /// Peer publishes commitments for Round 1.
    Commitments {
        /// Participant identifier (non-zero) in u16.
        identifier: u16,
        /// postcard(SigningCommitments).
        commitments: Vec<u8>,
    },

    /// Orchestrator sends SigningPackage.
    SigningPackage {
        /// postcard(SigningPackage).
        signing_package: Vec<u8>,
    },

    /// Peer responds with signature share.
    SignatureShare {
        identifier: u16,
        /// postcard(SignatureShare).
        signature_share: Vec<u8>,
    },
}

/// What is stored in Vault for a participant key.
#[derive(Debug, PartialEq, Archive, Serialize, Deserialize)]
pub struct FrostStoredKey {
    /// Non-zero participant identifier in u16.
    pub identifier: u16,
    /// postcard(KeyPackage).
    pub key_package: Vec<u8>,
}

/// Participant-side FROST(Ed25519) protocol instance.
pub struct FrostEd25519Protocol {
    /// Threshold and participant count.
    pub threshold: u32,
    /// Total number of participants.
    pub participants: u32,
    /// Current protocol round.
    pub round: Round,
    /// Bytes to sign.
    pub message: Vec<u8>,
    /// Participant key package.
    pub key_package: KeyPackage,
    /// Participant identifier.
    pub identifier: Identifier,
    /// Canonical u16 identifier (from Vault).
    pub identifier_u16: u16,
    /// Nonces generated at round 0 (commitments).
    pub nonces: Option<SigningNonces>,
    /// Signature share after signing.
    pub signature_share: Option<SignatureShare>,
    /// Whether the protocol has been aborted.
    pub aborted: bool,
}

impl FrostEd25519Protocol {
    /// Instantiate from engine-provided init context.
    ///
    /// # Arguments
    /// * `init` (`ProtocolInit`) - Protocol initialization context.
    ///
    /// # Errors
    /// - `Error::UnsupportedAlgorithm` if algorithm is not FrostEd25519.
    /// - `Error::InvalidKeyShare` if stored key cannot be decoded.
    ///
    /// # Returns
    /// * `FrostEd25519Protocol` - New protocol instance.
    pub fn try_new(init: ProtocolInit) -> Result<Self, Error> {
        let algorithm: Algorithm = match init.algorithm.parse::<Algorithm>() {
            Ok(algorithm) => algorithm,
            Err(_) => {
                return Err(Error::UnsupportedAlgorithm(
                    init.algorithm.clone(),
                ));
            }
        };

        if algorithm != Algorithm::FrostEd25519 {
            return Err(Error::UnsupportedAlgorithm(init.algorithm.clone()));
        }

        // Decode FrostStoredKey from Secret<Vec<u8>> using
        // rkyv high-level API.
        let stored: FrostStoredKey =
            init.key_share.with_ref(|bytes: &Vec<u8>| {
                match deserialize::<FrostStoredKey, RkyvError>(
                    match access::<Archived<FrostStoredKey>, RkyvError>(
                        bytes.as_slice(),
                    ) {
                        Ok(archived) => archived,
                        Err(_) => return Err(Error::InvalidKeyShare),
                    },
                ) {
                    Ok(deserialized) => Ok(deserialized),
                    Err(_) => Err(Error::InvalidKeyShare),
                }
            })?;

        // Decode the frost KeyPackage from opaque bytes (postcard).
        let key_package: KeyPackage =
            match postcard::from_bytes(&stored.key_package) {
                Ok(key_package) => key_package,
                Err(_) => return Err(Error::InvalidKeyShare),
            };

        let identifier: Identifier = match stored.identifier.try_into() {
            Ok(id) => id,
            Err(_) => return Err(Error::InvalidKeyShare),
        };

        Ok(Self {
            threshold: init.threshold,
            participants: init.participants,
            round: 0,
            message: init.message,
            key_package,
            identifier,
            identifier_u16: stored.identifier,
            nonces: None,
            signature_share: None,
            aborted: false,
        })
    }

    /// Encode a FrostWire message into bytes.
    ///
    /// # Arguments
    /// * `wire` (`&FrostWire`) - Input wire message.
    ///
    /// # Errors
    /// Returns `Error::InvalidMessage` on serialization failure.
    ///
    /// # Returns
    /// * `Vec<u8>` - Encoded bytes.
    fn encode_wire(wire: &FrostWire) -> Result<Vec<u8>, Error> {
        // rkyv high-level API: to_bytes::<E>(&T) -> AlignedVec
        let buffer: rkyv::util::AlignedVec = match to_bytes::<RkyvError>(wire)
        {
            Ok(buffer) => buffer,
            Err(_) => return Err(Error::InvalidMessage),
        };
        Ok(buffer.into_vec())
    }

    /// Decode FrostWire from bytes.
    ///
    /// # Arguments
    /// * `bytes` (`&[u8]`) - Input byte slice.
    ///
    /// # Errors
    /// Returns `Error::InvalidMessage` if validation/deserialization fails.
    ///
    /// # Returns
    /// * `FrostWire` - Decoded wire message.
    fn decode_wire(bytes: &[u8]) -> Result<FrostWire, Error> {
        match deserialize::<FrostWire, RkyvError>(
            match access::<Archived<FrostWire>, RkyvError>(bytes) {
                Ok(archived) => archived,
                Err(_) => return Err(Error::InvalidMessage),
            },
        ) {
            Ok(deserialized) => Ok(deserialized),
            Err(_) => Err(Error::InvalidMessage),
        }
    }
}

impl SigningProtocol for FrostEd25519Protocol {
    fn algorithm(&self) -> Algorithm {
        Algorithm::FrostEd25519
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

    /// Advance the protocol without receiving a message.
    ///
    /// At round 0, it generate nonces and commitments, keep nonces locally
    /// and finally send commitments to orchestrator.
    ///
    /// # Errors
    /// Returns `Error::Aborted` if the protocol has been aborted.
    ///
    /// # Returns
    /// * `Option<RoundMessage>` - Outgoing message for the round, if any.
    fn next_round(&mut self) -> Result<Option<RoundMessage>, Error> {
        if self.aborted {
            return Err(Error::Aborted);
        }

        match self.round {
            // Round 0: generate nonces and commitments.
            0 => {
                let mut random: OsRng = OsRng;
                let (nonces, commitments): (
                    SigningNonces,
                    SigningCommitments,
                ) = round1::commit(
                    self.key_package.signing_share(),
                    &mut random,
                );

                self.nonces = Some(nonces);
                self.round = 1;

                let commitments_bytes: Vec<u8> =
                    match postcard::to_allocvec(&commitments) {
                        Ok(bytes) => bytes,
                        Err(_) => return Err(Error::InvalidMessage),
                    };

                let wire: FrostWire = FrostWire::Commitments {
                    identifier: self.identifier_u16,
                    commitments: commitments_bytes,
                };

                let payload: Vec<u8> = Self::encode_wire(&wire)?;
                Ok(Some(RoundMessage { round: 0, payload }))
            }
            // Other rounds: no-operation.
            _ => Ok(None),
        }
    }

    /// Handle an incoming message from the orchestrator.
    /// Round 1 input: SigningPackage (bytes).
    /// Round 1 output: SignatureShare (bytes).
    ///
    /// # Arguments
    /// * `message` (`RoundMessage`) - Incoming message.
    ///
    /// # Errors
    /// - `Error::Aborted` if the protocol has been aborted.
    /// - `Error::InvalidRound` if the message round does not match expected
    ///   round.
    /// - `Error::InvalidMessage` if message decoding or content is invalid.
    /// - `Error::InvalidState` if protocol state is inconsistent.
    ///
    /// # Returns
    /// * `Option<RoundMessage>` - Outgoing message for the round, if any.
    fn handle_message(
        &mut self,
        message: RoundMessage,
    ) -> Result<Option<RoundMessage>, Error> {
        if self.aborted {
            return Err(Error::Aborted);
        }

        if message.round != 1 {
            return Err(Error::InvalidRound(message.round));
        }

        let wire: FrostWire = Self::decode_wire(&message.payload)?;

        match wire {
            FrostWire::SigningPackage { signing_package } => {
                let nonces: SigningNonces =
                    self.nonces.take().ok_or(Error::InvalidSignature)?;

                let signing_package: SigningPackage =
                    postcard::from_bytes(&signing_package)
                        .map_err(|_| Error::InvalidMessage)?;

                if signing_package.message() != self.message.as_slice() {
                    return Err(Error::InvalidMessage);
                }

                if !signing_package
                    .signing_commitments()
                    .contains_key(&self.identifier)
                {
                    return Err(Error::InvalidMessage);
                }

                let signature_share: SignatureShare = match round2::sign(
                    &signing_package,
                    &nonces,
                    &self.key_package,
                ) {
                    Ok(share) => share,
                    Err(_) => return Err(Error::FailedToSign),
                };

                self.signature_share = Some(signature_share);

                let signature_bytes: Vec<u8> =
                    match postcard::to_allocvec(&signature_share) {
                        Ok(bytes) => bytes,
                        Err(_) => return Err(Error::InvalidMessage),
                    };

                let output: FrostWire = FrostWire::SignatureShare {
                    identifier: self.identifier_u16,
                    signature_share: signature_bytes,
                };

                let payload: Vec<u8> = Self::encode_wire(&output)?;
                Ok(Some(RoundMessage { round: 1, payload }))
            }
            _ => Err(Error::InvalidMessage),
        }
    }

    /// Finalize and return protocol-dependent output.
    /// For Frost participant, this returns serialized SignatureShare bytes.
    ///
    /// # Errors
    /// - `Error::Aborted` if the protocol has been aborted.
    /// - `Error::InvalidState` if the protocol is in an invalid state.
    /// - `Error::InvalidMessage` if serialization fails.
    ///
    /// # Returns
    /// * `Signature` - Final protocol output.
    fn finalize(self: Box<Self>) -> Result<Signature, Error> {
        if self.aborted {
            return Err(Error::Aborted);
        }

        let share: SignatureShare =
            self.signature_share.ok_or(Error::InvalidSignature)?;

        let bytes: Vec<u8> = match postcard::to_allocvec(&share) {
            Ok(bytes) => bytes,
            Err(_) => return Err(Error::InvalidMessage),
        };
        Ok(Signature { bytes })
    }

    /// Abort the protocol, cleaning up sensitive state.
    ///
    /// # Returns
    /// `()` - Nothing.
    fn abort(&mut self) {
        self.aborted = true;
        self.nonces = None;
        self.signature_share = None;
    }
}
