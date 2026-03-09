//! FROST participant-side signing protocol.
//!
//! A single generic implementation shared across all FROST curve variants.
//! Each curve implements the `FrostSigningCurve` trait to provide its concrete
//! cryptographic types and serialization logic.

use std::num::TryFromIntError;

use async_trait::async_trait;
use rkyv::{Archived, access, deserialize, rancor::Error as RkyvError};

use crate::{
    proto::signer::v1::{RoundMessage, signature_result::FinalSignature},
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
            SigningInit,
        },
    },
    transport::errors::Errors,
};

/// Abstracts over FROST curve variants for signing.
/// Implement this trait for each curve (ed25519, secp256k1) to plug into
/// the generic `FrostNodeSigning` implementation.
pub trait FrostSigningCurve: Send + Sync + 'static {
    /// The type representing participant identifiers for this curve. This is
    /// the type used internally within the protocol implementation to track
    /// participants and their messages. It must be constructible from a u16
    /// (the participant identifier provided in the protocol init) and
    /// convertible back to a u16 for message encoding.
    type Identifier: Ord + Copy + Send + Sync + 'static;
    /// The type representing the key package for this curve, containing the
    /// signing share and public key information loaded from Vault.
    type KeyPackage: Send + Sync + 'static;
    /// The type representing the signing nonces generated in round 0.
    type SigningNonces: Send + Sync + 'static;
    /// The type representing the signing commitments computed in round 0 and
    type SigningCommitments: Send + Sync + Copy + 'static;
    /// The type representing the signing package sent by the controller in
    /// round 1, containing the message to be signed and the commitments
    /// from all participants.
    type SigningPackage: Send + Sync + 'static;
    /// The type representing the signature share produced in round 1 to be
    /// sent to the controller.
    type SignatureShare: Send + Sync + Copy + 'static;

    /// The algorithm identifier for this curve.
    ///
    /// # Returns
    /// * `Algorithm` - The algorithm enum variant corresponding to this curve.
    fn algorithm() -> Algorithm;

    /// Create a FROST Identifier from a u16.
    ///
    /// # Arguments
    /// * `identifier` (`u16`) - The identifier as a u16, typically stored in
    ///   the key share.
    ///
    /// # Errors
    /// * `Errors::InvalidKeyShare` - If the identifier cannot be converted to
    ///   the curve-specific Identifier type.
    ///
    /// # Returns
    /// * `Self::Identifier` - The curve-specific Identifier type.
    fn identifier_from_u16(
        identifier: u16,
    ) -> Result<Self::Identifier, Errors>;

    /// Deserialize a `KeyPackage` from postcard bytes.
    ///
    /// # Arguments
    /// * `bytes` (`&[u8]`) - The serialized key package bytes
    ///
    /// # Errors
    /// * `Errors::InvalidKeyShare` - If deserialization fails.
    ///
    /// # Returns
    /// * `Self::KeyPackage` - The deserialized key package.
    fn deserialize_key_package(
        bytes: &[u8],
    ) -> Result<Self::KeyPackage, Errors>;

    /// Generate signing nonces and commitments from a key package.
    ///
    /// # Arguments
    /// * `key_package` (`&Self::KeyPackage`) - The participant's key package,
    ///   containing the signing share and public key information.
    ///
    /// # Errors
    /// * `Errors::InvalidMessage` - If nonce generation or commitment
    ///   computation fails.
    ///
    /// # Returns
    /// * `(Self::SigningNonces, Self::SigningCommitments)` - The generated
    ///   signing nonces and commitments to be broadcast to the other
    ///   participants.
    fn commit(
        key_package: &Self::KeyPackage,
    ) -> Result<(Self::SigningNonces, Self::SigningCommitments), Errors>;

    /// Serialize signing commitments to bytes.
    ///
    /// # Arguments
    /// * `commitments` (`&Self::SigningCommitments`) - The signing commitments
    ///   to serialize.
    ///
    /// # Errors
    /// * `Errors::InvalidMessage` - If serialization fails.
    ///
    /// # Returns
    /// * `Vec<u8>` - The serialized commitments as bytes.
    fn serialize_commitments(
        commitments: &Self::SigningCommitments,
    ) -> Result<Vec<u8>, Errors>;

    /// Deserialize a `SigningPackage` from bytes.
    ///
    /// # Arguments
    /// * `bytes` (`&[u8]`) - The serialized signing package bytes
    ///
    /// # Errors
    /// * `Errors::InvalidMessage` - If deserialization fails.
    ///
    /// # Returns
    /// * `Self::SigningPackage` - The deserialized signing package.
    fn deserialize_signing_package(
        bytes: &[u8],
    ) -> Result<Self::SigningPackage, Errors>;

    /// Extract the message embedded in a `SigningPackage`.
    ///
    /// # Arguments
    /// * `package` (`&Self::SigningPackage`) - The signing package to extract
    ///   the message from.
    ///
    /// # Returns
    /// * `&[u8]` - The message bytes embedded in the signing package
    fn signing_package_message(package: &Self::SigningPackage) -> &[u8];

    /// Return true if the signing package contains commitments for the given
    /// identifier.
    ///
    /// # Arguments
    /// * `package` (`&Self::SigningPackage`) - The signing package to check
    /// * `identifier` (`&Self::Identifier`) - The identifier to look for in
    ///   the signing package commitments
    ///
    /// # Returns
    /// * `bool` - True if the signing package contains commitments for the
    ///   identifier, false otherwise.
    fn signing_package_contains(
        package: &Self::SigningPackage,
        identifier: &Self::Identifier,
    ) -> bool;

    /// Produce a signature share from the signing package, nonces, and key
    /// package.
    ///
    /// # Arguments
    /// * `package` (`&Self::SigningPackage`) - The signing package containing
    ///   the message and commitments from all participants.
    /// * `nonces` (`&Self::SigningNonces`) - The nonces generated in round 0.
    /// * `key_package` (`&Self::KeyPackage`) - The participant's key package
    ///   containing the signing share.
    ///
    /// # Errors
    /// * `Errors::InvalidMessage` - If the signing package is malformed or
    ///   missing commitments for this participant.
    /// * `Errors::InvalidSignature` - If the nonces are missing or invalid.
    /// * `Errors::FailedToSign` - If the signing operation fails for any
    ///   reason.
    ///
    /// # Returns
    /// * `Self::SignatureShare` - The produced signature share to be sent to
    ///   the controller.
    fn sign(
        package: &Self::SigningPackage,
        nonces: &Self::SigningNonces,
        key_package: &Self::KeyPackage,
    ) -> Result<Self::SignatureShare, Errors>;

    /// Serialize a signature share to bytes.
    ///
    /// # Arguments
    /// * `share` (`&Self::SignatureShare`) - The signature share to serialize
    ///
    /// # Errors
    /// * `Errors::InvalidMessage` - If serialization fails.
    ///
    /// # Returns
    /// * `Vec<u8>` - The serialized signature share as bytes.
    fn serialize_signature_share(
        share: &Self::SignatureShare,
    ) -> Result<Vec<u8>, Errors>;
}

/// Participant-side FROST signing protocol instance.
pub struct FrostNodeSigning<C: FrostSigningCurve> {
    /// Minimum number of participants required to produce a valid signature.
    threshold: u32,
    /// Total number of participants.
    participants: u32,
    /// Current protocol round.
    round: Round,
    /// The message to be signed — verified against the signing package in
    /// round 1 to prevent substitution attacks.
    message: Vec<u8>,
    /// This participant's key package, loaded from Vault.
    key_package: C::KeyPackage,
    /// This participant's FROST identifier.
    identifier: C::Identifier,
    /// This participant's identifier as u32.
    identifier_u32: u32,
    /// Nonces generated in round 0. Consumed exactly once during signing.
    nonces: Option<C::SigningNonces>,
    /// Signature share produced in round 1. Consumed during finalization.
    signature_share: Option<C::SignatureShare>,
    /// True if the protocol has been aborted.
    aborted: bool,
}

impl<C: FrostSigningCurve> FrostNodeSigning<C> {
    /// Try to create a new FROST node signing protocol instance.
    ///
    /// Decodes the key share from Vault (rkyv) and the key package from
    /// the stored bytes (postcard).
    ///
    /// # Arguments
    /// * `protocol_init` (`ProtocolInit`) - Protocol initialization context.
    ///
    /// # Errors
    /// * `Errors::InvalidProtocolInit` - If the init context is invalid.
    /// * `Errors::UnsupportedAlgorithm` - If the algorithm does not match.
    /// * `Errors::InvalidKeyShare` - If the key share cannot be decoded.
    ///
    /// # Returns
    /// * `Self` - The initialized protocol instance ready to run.
    pub fn try_new(protocol_init: ProtocolInit) -> Result<Self, Errors> {
        let init: NodeSigningInit = match protocol_init {
            ProtocolInit::Signing(SigningInit::Node(init)) => init,
            _ => {
                return Err(Errors::InvalidProtocolInit(
                    "Expected node signing init.".into(),
                ));
            },
        };

        if init.common.algorithm != C::algorithm() {
            return Err(Errors::UnsupportedAlgorithm(
                init.common.algorithm.as_str().into(),
            ));
        }

        // Decode the FrostStoredKey from the Vault secret blob (rkyv).
        let stored: FrostStoredKey =
            init.key_share.with_ref(|bytes: &Vec<u8>| {
                let archived: &ArchivedFrostStoredKey =
                    access::<Archived<FrostStoredKey>, RkyvError>(
                        bytes.as_slice(),
                    )
                    .map_err(|error: RkyvError| {
                        Errors::InvalidKeyShare(format!(
                            "Failed to access archived key: {}",
                            error
                        ))
                    })?;

                deserialize::<FrostStoredKey, RkyvError>(archived).map_err(
                    |error: RkyvError| {
                        Errors::InvalidKeyShare(format!(
                            "Failed to deserialize key: {}",
                            error
                        ))
                    },
                )
            })?;

        // Decode the curve-specific KeyPackage from postcard bytes.
        let key_package: C::KeyPackage =
            C::deserialize_key_package(&stored.key_package)?;

        // Reconstruct the FROST Identifier from the stored u32.
        let identifier: C::Identifier = C::identifier_from_u16(
            u16::try_from(stored.identifier).map_err(
                |error: TryFromIntError| {
                    Errors::InvalidKeyShare(format!(
                        "Failed to convert identifier to u16: {}",
                        error
                    ))
                },
            )?,
        )?;

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
impl<C: FrostSigningCurve> Protocol for FrostNodeSigning<C> {
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

    /// Execute round 0 — generate nonces and broadcast commitments.
    ///
    /// Nonces are stored locally and consumed exactly once in `handle_message`
    /// during round 1. Only executes at round 0; subsequent calls return
    /// `None`.
    ///
    /// # Errors
    /// * `Errors::Aborted` - If the protocol has been aborted.
    /// * `Errors::InvalidMessage` - If nonce generation or commitment
    ///   computation fails.
    ///
    /// # Returns
    /// * `Option<RoundMessage>` - The round message containing the commitments
    ///   to be broadcast to the other participants, or `None` if no message
    ///   should be sent (e.g. if called after round 0).
    async fn next_round(&mut self) -> Result<Option<RoundMessage>, Errors> {
        if self.aborted {
            return Err(Errors::Aborted("Protocol has been aborted.".into()));
        }

        if self.round != 0 {
            return Ok(None);
        }

        let (nonces, commitments): (C::SigningNonces, C::SigningCommitments) =
            C::commit(&self.key_package)?;

        self.nonces = Some(nonces);
        self.round = 1;

        let payload: Vec<u8> = encode_wire(&FrostWire::Commitments {
            identifier: self.identifier_u32,
            commitments: C::serialize_commitments(&commitments)?,
        })?;

        Ok(Some(RoundMessage {
            round: 0,
            from: Some(self.identifier_u32),
            to: None,
            payload,
        }))
    }

    /// Handle the signing package from the controller and produce a signature
    /// share.
    ///
    /// Verifies that the signing package contains the expected message and
    /// commitments for this participant before signing. The nonces are
    /// consumed exactly once here.
    ///
    /// # Errors
    /// * `Errors::InvalidRound` - If the message round is not 1.
    /// * `Errors::InvalidMessage` - If the signing package is malformed, the
    ///   message does not match, or commitments are missing.
    /// * `Errors::InvalidSignature` - If nonces are missing.
    /// * `Errors::FailedToSign` - If the signing operation fails.
    ///
    /// # Returns
    /// * `Option<RoundMessage>` - The round message containing the signature
    ///   share to be sent to the controller, or `None` if no message should be
    ///   sent (e.g. if the signing package is invalid).
    async fn handle_message(
        &mut self,
        message: RoundMessage,
    ) -> Result<Option<RoundMessage>, Errors> {
        if self.aborted {
            return Err(Errors::Aborted("Protocol has been aborted.".into()));
        }

        if message.round != 1 {
            return Err(Errors::InvalidRound(message.round));
        }

        let wire: FrostWire = decode_wire(&message.payload)?;

        match wire {
            FrostWire::SigningPackage { signing_package } => {
                let signing_package: C::SigningPackage =
                    C::deserialize_signing_package(&signing_package)?;

                // Verify the message matches what we were initialized with —
                // prevents the controller from substituting a different
                // message after commitments were sent.
                if C::signing_package_message(&signing_package)
                    != self.message.as_slice()
                {
                    return Err(Errors::InvalidMessage(
                        "Signing package message does not match expected \
                        message."
                            .into(),
                    ));
                }

                // Verify our commitments are included in the signing package —
                // we cannot sign without them.
                if !C::signing_package_contains(
                    &signing_package,
                    &self.identifier,
                ) {
                    return Err(Errors::InvalidMessage(
                        "Signing package does not contain commitments for \
                        this participant."
                            .into(),
                    ));
                }

                // Consume nonces exactly once — they must not be reused.
                let nonces: C::SigningNonces =
                    self.nonces.take().ok_or_else(|| {
                        Errors::InvalidSignature("Missing nonces.".into())
                    })?;

                let signature_share: C::SignatureShare =
                    C::sign(&signing_package, &nonces, &self.key_package)?;

                self.signature_share = Some(signature_share);

                let payload: Vec<u8> =
                    encode_wire(&FrostWire::SignatureShare {
                        identifier: self.identifier_u32,
                        signature_share: C::serialize_signature_share(
                            &signature_share,
                        )?,
                    })?;

                Ok(Some(RoundMessage {
                    round: 1,
                    from: Some(self.identifier_u32),
                    to: None,
                    payload,
                }))
            },
            _ => Err(Errors::InvalidMessage(
                "Unexpected wire message type in round 1.".into(),
            )),
        }
    }

    /// Finalize the protocol and return the serialized signature share.
    ///
    /// The signature share is consumed here — calling `finalize` twice will
    /// return an error.
    ///
    /// # Errors
    /// * `Errors::InvalidSignature` - If the signature share is missing.
    /// * `Errors::InvalidMessage` - If serialization fails.
    /// * `Errors::Aborted` - If the protocol has been aborted.
    ///
    /// # Returns
    /// * `ProtocolOutput` - The protocol output containing the serialized
    ///  signature share to be sent to the controller.
    async fn finalize(&mut self) -> Result<ProtocolOutput, Errors> {
        if self.aborted {
            return Err(Errors::Aborted("Protocol has been aborted.".into()));
        }

        // take() ensures the share is consumed and cannot be reused.
        let share: C::SignatureShare =
            self.signature_share.take().ok_or_else(|| {
                Errors::InvalidSignature("Missing signature share.".into())
            })?;

        Ok(ProtocolOutput::Signature(FinalSignature::Raw(
            C::serialize_signature_share(&share)?,
        )))
    }

    /// Abort the protocol and clear all sensitive cryptographic material.
    fn abort(&mut self) {
        self.aborted = true;
        // Explicitly drop nonces and signature share to clear sensitive
        // material from memory.
        self.nonces = None;
        self.signature_share = None;
    }
}
