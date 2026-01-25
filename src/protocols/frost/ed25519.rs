//! Frost-ed25519 participant-side protocol implementation.

use frost_ed25519::{
    Identifier,
    SigningPackage,
    keys::KeyPackage,
    rand_core::OsRng,
    round1::{
        SigningCommitments,
        SigningNonces,
        commit,
    },
    round2::{
        SignatureShare,
        sign,
    },
};
use rkyv::{
    Archived,
    access,
    deserialize,
    rancor::Error as RkyvError,
};

use crate::{
    messages::error::Error,
    protocols::{
        algorithm::Algorithm,
        codec::{
            decode_wire,
            encode_wire,
        },
        frost::{
            stored_key::FrostStoredKey,
            wire::FrostWire,
        },
        signing::SigningProtocol,
        types::{
            ProtocolInit,
            Round,
            RoundMessage,
            Signature,
        },
    },
};

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
    /// Canonical u32 identifier (from Vault).
    pub identifier_u32: u32,
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
        if init.algorithm != Algorithm::FrostEd25519 {
            return Err(Error::UnsupportedAlgorithm(
                init.algorithm.as_str().into(),
            ));
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

        let identifier: Identifier = Identifier::try_from(
            u16::try_from(stored.identifier)
                .map_err(|_| Error::InvalidKeyShare)?,
        )
        .map_err(|_| Error::InvalidKeyShare)?;

        Ok(Self {
            threshold: init.threshold,
            participants: init.participants,
            round: 0,
            message: init.message,
            key_package,
            identifier,
            identifier_u32: stored.identifier,
            nonces: None,
            signature_share: None,
            aborted: false,
        })
    }
}

impl SigningProtocol for FrostEd25519Protocol {
    /// Return the algorithm identifier.
    ///
    /// # Returns
    /// * `Algorithm` - Algorithm enum variant.
    fn algorithm(&self) -> Algorithm {
        Algorithm::FrostEd25519
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
                ) = commit(self.key_package.signing_share(), &mut random);

                self.nonces = Some(nonces);
                self.round = 1;

                let commitments_bytes: Vec<u8> =
                    match postcard::to_allocvec(&commitments) {
                        Ok(bytes) => bytes,
                        Err(_) => return Err(Error::InvalidMessage),
                    };

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

        let wire: FrostWire = decode_wire(&message.payload)?;

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

                let signature_share: SignatureShare =
                    match sign(&signing_package, &nonces, &self.key_package) {
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
        Ok(Signature::Raw(bytes))
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
