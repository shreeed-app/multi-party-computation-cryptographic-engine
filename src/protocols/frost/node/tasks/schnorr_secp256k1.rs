//! Frost-secp256k1 (Schnorr) participant-side protocol implementation.

use async_trait::async_trait;
use frost_secp256k1::{
    Identifier,
    SigningPackage,
    keys::KeyPackage,
    rand_core::OsRng,
    round1::{SigningCommitments, SigningNonces, commit},
    round2::{SignatureShare, sign},
};
use rkyv::{Archived, access, deserialize, rancor::Error as RkyvError};

use crate::{
    proto::signer::v1::signature_result::FinalSignature,
    protocols::{
        algorithm::Algorithm,
        codec::{decode_wire, encode_wire},
        frost::{
            stored_key::{ArchivedFrostStoredKey, FrostStoredKey},
            wire::FrostWire,
        },
        protocol::Protocol,
        types::{
            NodeSigningInit,
            ProtocolInit,
            ProtocolOutput,
            Round,
            RoundMessage,
            SigningInit,
        },
    },
    transport::errors::Errors,
};

/// Participant-side FROST(secp256k1) protocol instance.
pub struct FrostSchnorrSecp256k1NodeSigning {
    /// Number of participants required to sign.
    pub threshold: u32,
    /// Total number of participants.
    pub participants: u32,
    /// Current protocol round.
    pub round: Round,
    /// Message to be signed.
    pub message: Vec<u8>,
    /// Participant's KeyPackage.
    pub key_package: KeyPackage,
    /// Participant's FROST Identifier.
    pub identifier: Identifier,
    /// Participant's identifier as u32.
    pub identifier_u32: u32,
    /// Nonces generated in round 1.
    pub nonces: Option<SigningNonces>,
    /// Participant's signature share.
    pub signature_share: Option<SignatureShare>,
    /// Indicates if the protocol has been aborted.
    pub aborted: bool,
}

impl FrostSchnorrSecp256k1NodeSigning {
    /// Try to create a new FROST(secp256k1) protocol instance.
    ///
    /// # Arguments
    /// * `protocol_init` (`ProtocolInit`) - Protocol initialization context.
    ///
    /// # Errors
    /// * `Error::UnsupportedAlgorithm` if the algorithm is not
    ///   FROST(secp256k1).
    /// * `Error::InvalidKeyShare` if the key share cannot be decoded.
    ///
    /// # Returns
    /// * `FrostSchnorrSecp256k1Protocol` - Initialized protocol instance.
    pub fn try_new(protocol_init: ProtocolInit) -> Result<Self, Errors> {
        let init: NodeSigningInit = match protocol_init {
            ProtocolInit::Signing(SigningInit::Node(init)) => init,
            _ => return Err(Errors::InvalidProtocolInit),
        };

        if init.common.algorithm != Algorithm::FrostSchnorrSecp256k1 {
            return Err(Errors::UnsupportedAlgorithm(
                init.common.algorithm.as_str().into(),
            ));
        }

        // Decode stored key from Vault blob (rkyv).
        let stored: FrostStoredKey =
            init.key_share.with_ref(|bytes: &Vec<u8>| {
                let archived: &ArchivedFrostStoredKey =
                    access::<Archived<FrostStoredKey>, RkyvError>(
                        bytes.as_slice(),
                    )
                    .map_err(|_| Errors::InvalidKeyShare)?;
                deserialize::<FrostStoredKey, RkyvError>(archived)
                    .map_err(|_| Errors::InvalidKeyShare)
            })?;

        // Decode KeyPackage from postcard bytes.
        let key_package: KeyPackage =
            postcard::from_bytes(&stored.key_package)
                .map_err(|_| Errors::InvalidKeyShare)?;

        let identifier: Identifier = Identifier::try_from(
            u16::try_from(stored.identifier)
                .map_err(|_| Errors::InvalidKeyShare)?,
        )
        .map_err(|_| Errors::InvalidKeyShare)?;

        Ok(Self {
            threshold: init.common.threshold,
            participants: init.common.participants,
            round: 0,
            message: init.common.message,
            key_package,
            identifier,
            identifier_u32: stored.identifier,
            nonces: None,
            signature_share: None,
            aborted: false,
        })
    }
}

#[async_trait]
impl Protocol for FrostSchnorrSecp256k1NodeSigning {
    /// Return the algorithm identifier.
    ///
    /// # Returns
    /// * `Algorithm` - Algorithm enum variant.
    fn algorithm(&self) -> Algorithm {
        Algorithm::FrostSchnorrSecp256k1
    }

    /// Return the protocol threshold.
    ///
    /// # Returns
    /// * `u32` - Threshold number.
    fn threshold(&self) -> u32 {
        self.threshold
    }

    /// Return the total number of participants.
    ///
    /// # Returns
    /// * `u32` - Number of participants.
    fn participants(&self) -> u32 {
        self.participants
    }

    /// Return the current protocol round.
    ///
    /// # Returns
    /// * `Round` - Current round number.
    fn current_round(&self) -> Round {
        self.round
    }

    /// Proceed to the next protocol round.
    ///
    /// # Errors
    /// * `Error::Aborted` if the protocol has been aborted.
    /// * `Error::InvalidMessage` if message encoding fails.
    ///
    /// # Returns
    /// * `Option<RoundMessage>` - Message to send to controller, if any.
    async fn next_round(&mut self) -> Result<Option<RoundMessage>, Errors> {
        if self.aborted {
            return Err(Errors::Aborted);
        }

        match self.round {
            0 => {
                let mut random: OsRng = OsRng;
                let (nonces, commitments): (
                    SigningNonces,
                    SigningCommitments,
                ) = commit(self.key_package.signing_share(), &mut random);
                self.nonces = Some(nonces);
                self.round = 1;

                let commitments_bytes: Vec<u8> =
                    postcard::to_allocvec(&commitments)
                        .map_err(|_| Errors::InvalidMessage)?;

                let wire: FrostWire = FrostWire::Commitments {
                    identifier: self.identifier_u32,
                    commitments: commitments_bytes,
                };

                let payload: Vec<u8> = encode_wire(&wire)?;
                Ok(Some(RoundMessage {
                    round: 0,
                    from: Some(self.identifier_u32),
                    to: None,
                    payload,
                }))
            },
            _ => Ok(None),
        }
    }

    /// Handle an incoming message from the controller.
    ///
    /// # Arguments
    /// * `message` (`RoundMessage`) - Incoming message to process.
    ///
    /// # Errors
    /// * `Error::Aborted` if the protocol has been aborted.
    /// * `Error::InvalidRound` if the message round is unexpected.
    /// * `Error::InvalidMessage` if message decoding fails.
    /// * `Error::FailedToSign` if signing fails.
    ///
    /// # Returns
    /// * `Option<RoundMessage>` - Message to send to controller, if any.
    async fn handle_message(
        &mut self,
        message: RoundMessage,
    ) -> Result<Option<RoundMessage>, Errors> {
        if self.aborted {
            return Err(Errors::Aborted);
        }
        if message.round != 1 {
            return Err(Errors::InvalidRound(message.round));
        }

        let wire: FrostWire = decode_wire(&message.payload)?;

        match wire {
            FrostWire::SigningPackage { signing_package } => {
                let nonces: SigningNonces =
                    self.nonces.take().ok_or(Errors::InvalidSignature)?;

                let signing_package: SigningPackage =
                    postcard::from_bytes(&signing_package)
                        .map_err(|_| Errors::InvalidMessage)?;

                if signing_package.message() != self.message.as_slice() {
                    return Err(Errors::InvalidMessage);
                }

                if !signing_package
                    .signing_commitments()
                    .contains_key(&self.identifier)
                {
                    return Err(Errors::InvalidMessage);
                }

                let signature_share: SignatureShare =
                    sign(&signing_package, &nonces, &self.key_package)
                        .map_err(|_| Errors::FailedToSign)?;

                self.signature_share = Some(signature_share);

                let signature_share: &SignatureShare = self
                    .signature_share
                    .as_ref()
                    .ok_or(Errors::InvalidSignature)?;

                let signature_bytes: Vec<u8> =
                    postcard::to_allocvec(signature_share)
                        .map_err(|_| Errors::InvalidMessage)?;

                let output: FrostWire = FrostWire::SignatureShare {
                    identifier: self.identifier_u32,
                    signature_share: signature_bytes,
                };

                let payload: Vec<u8> = encode_wire(&output)?;
                Ok(Some(RoundMessage {
                    round: 1,
                    from: Some(self.identifier_u32),
                    to: None,
                    payload,
                }))
            },
            _ => Err(Errors::InvalidMessage),
        }
    }

    /// Finalize the protocol and produce the signature share.
    ///
    /// # Errors
    /// * `Error::Aborted` if the protocol has been aborted.
    /// * `Error::InvalidSignature` if the signature share is missing.
    /// * `Error::InvalidMessage` if serialization fails.
    ///
    /// # Returns
    /// * `ProtocolOutput` - Final signature share.
    async fn finalize(&mut self) -> Result<ProtocolOutput, Errors> {
        if self.aborted {
            return Err(Errors::Aborted);
        }

        let share: SignatureShare =
            self.signature_share.ok_or(Errors::InvalidSignature)?;

        let bytes: Vec<u8> = postcard::to_allocvec(&share)
            .map_err(|_| Errors::InvalidMessage)?;

        Ok(ProtocolOutput::Signature(FinalSignature::Raw(bytes)))
    }

    /// Abort the protocol execution.
    ///
    /// # Returns
    /// * `()` - Nothing.
    fn abort(&mut self) {
        self.aborted = true;
        self.nonces = None;
        self.signature_share = None;
    }
}
