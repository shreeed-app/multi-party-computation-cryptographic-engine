//! FROST participant-side signing protocol.
//!
//! A single generic implementation shared across all FROST curve variants.
//! Each curve implements the `FrostSigningCurve` trait to provide its concrete
//! cryptographic types and serialization logic.

use std::num::TryFromIntError;

use async_trait::async_trait;
use frost_core::{
    Ciphersuite,
    Identifier as FrostIdentifier,
    SigningPackage as FrostSigningPackage,
    keys::KeyPackage as FrostKeyPackage,
    round1::{
        SigningCommitments as FrostSigningCommitments,
        SigningNonces as FrostSigningNonces,
        commit,
    },
    round2::{SignatureShare as FrostSignatureShare, sign},
};
use postcard::{Error as PostcardError, from_bytes, to_allocvec};
use rand_core::OsRng;
use rkyv::{Archived, access, deserialize, rancor::Error as RkyvError};
use zeroize::Zeroize;

use crate::{
    proto::engine::v1::{Algorithm, RoundMessage, signature_result::FinalSignature},
    protocols::{
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
    secrets::secret::Secret,
    transport::errors::Errors,
};

/// Abstracts over FROST curve variants for signing.
/// Implement this trait for each curve (ed25519, secp256k1) to plug into
/// the generic `FrostNodeSigning` implementation.
pub trait FrostSigningCurve: Send + Sync + 'static {
    /// The frost_core Ciphersuite for this curve.
    type Curve: Ciphersuite + Send + Sync;

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
    /// * `FrostIdentifier<Self::Curve>` - The curve-specific Identifier type.
    fn identifier_from_u16(
        identifier: u16,
    ) -> Result<FrostIdentifier<Self::Curve>, Errors> {
        FrostIdentifier::<Self::Curve>::try_from(identifier).map_err(
            |error: <FrostIdentifier<Self::Curve> as TryFrom<u16>>::Error| {
                Errors::InvalidKeyShare(format!(
                    "Failed to create identifier from {}: {:?}",
                    identifier, error
                ))
            },
        )
    }

    /// Deserialize a `KeyPackage` from postcard bytes.
    ///
    /// # Arguments
    /// * `bytes` (`&[u8]`) - The serialized key package bytes.
    ///
    /// # Errors
    /// * `Errors::InvalidKeyShare` - If deserialization fails.
    ///
    /// # Returns
    /// * `FrostKeyPackage<Self::Curve>` - The deserialized key package.
    fn deserialize_key_package(
        bytes: &[u8],
    ) -> Result<FrostKeyPackage<Self::Curve>, Errors> {
        from_bytes(bytes).map_err(|error: PostcardError| {
            Errors::InvalidKeyShare(format!(
                "Failed to deserialize key package: {}",
                error
            ))
        })
    }

    /// Generate signing nonces and commitments from a key package.
    ///
    /// # Arguments
    /// * `key_package` (`&FrostKeyPackage<Self::Curve>`) - The participant's
    ///   key package, containing the signing share and public key information.
    ///
    /// # Errors
    /// * `Errors::InvalidMessage` - If nonce generation or commitment
    ///   computation fails.
    ///
    /// # Returns
    /// * `(FrostSigningNonces<Self::Curve>, FrostSigningCommitments
    ///   <Self::Curve>)` - The generated signing nonces and commitments to be
    ///   broadcast to the other participants.
    fn commit(
        key_package: &FrostKeyPackage<Self::Curve>,
    ) -> Result<
        (
            FrostSigningNonces<Self::Curve>,
            FrostSigningCommitments<Self::Curve>,
        ),
        Errors,
    > {
        Ok(commit(key_package.signing_share(), &mut OsRng))
    }

    /// Serialize signing commitments to postcard bytes.
    ///
    /// # Arguments
    /// * `commitments` (`&FrostSigningCommitments<Self::Curve>`) - The signing
    ///   commitments to serialize.
    ///
    /// # Errors
    /// * `Errors::InvalidMessage` - If serialization fails.
    ///
    /// # Returns
    /// * `Vec<u8>` - The serialized commitments as bytes.
    fn serialize_commitments(
        commitments: &FrostSigningCommitments<Self::Curve>,
    ) -> Result<Vec<u8>, Errors> {
        to_allocvec(commitments).map_err(|error: PostcardError| {
            Errors::InvalidMessage(format!(
                "Failed to serialize commitments: {}",
                error
            ))
        })
    }

    /// Deserialize a `SigningPackage` from postcard bytes.
    ///
    /// # Arguments
    /// * `bytes` (`&[u8]`) - The serialized signing package bytes.
    ///
    /// # Errors
    /// * `Errors::InvalidMessage` - If deserialization fails.
    ///
    /// # Returns
    /// * `FrostSigningPackage<Self::Curve>` - The deserialized signing
    ///   package.
    fn deserialize_signing_package(
        bytes: &[u8],
    ) -> Result<FrostSigningPackage<Self::Curve>, Errors> {
        from_bytes(bytes).map_err(|error: PostcardError| {
            Errors::InvalidMessage(format!(
                "Failed to deserialize signing package: {}",
                error
            ))
        })
    }

    /// Produce a signature share from the signing package, nonces, and key
    /// package.
    ///
    /// # Arguments
    /// * `package` (`&FrostSigningPackage<Self::Curve>`) - The signing package
    ///   containing the message and commitments from all participants.
    /// * `nonces` (`&FrostSigningNonces<Self::Curve>`) - The nonces generated
    ///   in round 0.
    /// * `key_package` (`&FrostKeyPackage<Self::Curve>`) - The participant's
    ///   key package containing the signing share.
    ///
    /// # Errors
    /// * `Errors::FailedToSign` - If the signing operation fails.
    ///
    /// # Returns
    /// * `FrostSignatureShare<Self::Curve>` - The produced signature share to
    ///   be sent to the controller.
    fn sign(
        package: &FrostSigningPackage<Self::Curve>,
        nonces: &FrostSigningNonces<Self::Curve>,
        key_package: &FrostKeyPackage<Self::Curve>,
    ) -> Result<FrostSignatureShare<Self::Curve>, Errors> {
        sign(package, nonces, key_package).map_err(
            |error: frost_core::Error<Self::Curve>| {
                Errors::FailedToSign(format!("Signing failed: {}", error))
            },
        )
    }

    /// Serialize a signature share to postcard bytes.
    ///
    /// # Arguments
    /// * `share` (`&FrostSignatureShare<Self::Curve>`) - The signature share
    ///   to serialize.
    ///
    /// # Errors
    /// * `Errors::InvalidMessage` - If serialization fails.
    ///
    /// # Returns
    /// * `Vec<u8>` - The serialized signature share as bytes.
    fn serialize_signature_share(
        share: &FrostSignatureShare<Self::Curve>,
    ) -> Result<Vec<u8>, Errors> {
        to_allocvec(share).map_err(|error: PostcardError| {
            Errors::InvalidMessage(format!(
                "Failed to serialize signature share: {}",
                error
            ))
        })
    }
}

/// Participant-side FROST signing protocol instance.
pub struct FrostNodeSigning<C: FrostSigningCurve> {
    /// The signing algorithm being executed.
    algorithm: Algorithm,
    /// Minimum number of participants required to produce a valid signature.
    threshold: u32,
    /// Total number of participants.
    participants: u32,
    /// Current protocol round.
    round: Round,
    /// The message to be signed — verified against the signing package in
    /// round 1 to prevent substitution attacks.
    message: Secret<Vec<u8>>,
    /// This participant's key package, loaded from Vault.
    key_package: FrostKeyPackage<C::Curve>,
    /// This participant's FROST identifier.
    identifier: FrostIdentifier<C::Curve>,
    /// This participant's identifier as u32.
    identifier_u32: u32,
    /// Nonces generated in round 0. Consumed exactly once during signing.
    nonces: Option<Secret<FrostSigningNonces<C::Curve>>>,
    /// Serialized signature share produced in round 1. Stored as bytes to
    /// avoid re-serializing in `finalize` — consumed during finalization.
    signature_share_bytes: Option<Secret<Vec<u8>>>,
    /// True if the protocol has been aborted.
    aborted: bool,
}

impl<C: FrostSigningCurve> FrostNodeSigning<C>
where
    FrostIdentifier<C::Curve>: Send + Sync,
    FrostKeyPackage<C::Curve>: Send + Sync,
    FrostSigningNonces<C::Curve>: Send + Sync + Zeroize,
    FrostSigningCommitments<C::Curve>: Send + Sync,
    FrostSigningPackage<C::Curve>: Send + Sync,
    FrostSignatureShare<C::Curve>: Send + Sync,
{
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
        let key_package: FrostKeyPackage<C::Curve> =
            C::deserialize_key_package(&stored.key_package)?;

        // Reconstruct the FROST Identifier from the stored u32.
        let identifier: FrostIdentifier<C::Curve> = C::identifier_from_u16(
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
            algorithm: init.common.algorithm,
            threshold: init.common.threshold,
            participants: init.common.participants,
            round: 0,
            message: Secret::new(init.common.message),
            key_package,
            identifier,
            identifier_u32: stored.identifier,
            nonces: None,
            signature_share_bytes: None,
            aborted: false,
        })
    }
}

#[async_trait]
impl<C: FrostSigningCurve> Protocol for FrostNodeSigning<C>
where
    FrostIdentifier<C::Curve>: Send + Sync,
    FrostKeyPackage<C::Curve>: Send + Sync,
    FrostSigningNonces<C::Curve>: Send + Sync + Zeroize,
    FrostSigningCommitments<C::Curve>: Send + Sync,
    FrostSigningPackage<C::Curve>: Send + Sync,
    FrostSignatureShare<C::Curve>: Send + Sync,
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

        let (nonces, commitments): (
            FrostSigningNonces<C::Curve>,
            FrostSigningCommitments<C::Curve>,
        ) = C::commit(&self.key_package)?;

        self.nonces = Some(Secret::new(nonces));
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
    /// consumed exactly once here. The serialized signature share is stored
    /// for consumption in `finalize`.
    ///
    /// # Errors
    /// * `Errors::Aborted` - If the protocol has been aborted.
    /// * `Errors::InvalidRound` - If the message round is not 1.
    /// * `Errors::InvalidMessage` - If the signing package is malformed, the
    ///   message does not match, or commitments are missing.
    /// * `Errors::InvalidSignature` - If nonces are missing.
    /// * `Errors::FailedToSign` - If the signing operation fails.
    ///
    /// # Returns
    /// * `Option<RoundMessage>` - The round message containing the signature
    ///   share to be sent to the controller, or `None` if no message should be
    ///   sent.
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
                let signing_package: FrostSigningPackage<C::Curve> =
                    C::deserialize_signing_package(&signing_package)?;

                // Verify the message matches what we were initialized with —
                // prevents the controller from substituting a different
                // message after commitments were sent.
                if self.message.with_ref(|message: &Vec<u8>| {
                    signing_package.message() != message.as_slice()
                }) {
                    return Err(Errors::InvalidMessage(
                        "Signing package message does not match expected \
                        message."
                            .into(),
                    ));
                }

                // Verify our commitments are included in the signing package —
                // we cannot sign without them.
                if !signing_package
                    .signing_commitments()
                    .contains_key(&self.identifier)
                {
                    return Err(Errors::InvalidMessage(
                        "Signing package does not contain commitments for \
                        this participant."
                            .into(),
                    ));
                }

                // Consume nonces exactly once — they must not be reused.
                let nonces: Secret<FrostSigningNonces<C::Curve>> =
                    self.nonces.take().ok_or_else(|| {
                        Errors::InvalidSignature("Missing nonces.".into())
                    })?;

                let signature_share: FrostSignatureShare<C::Curve> = nonces
                    .with_ref(|nonce: &FrostSigningNonces<C::Curve>| {
                        C::sign(&signing_package, nonce, &self.key_package)
                    })?;

                // Serialize once and store — reused directly in finalize()
                // to avoid redundant serialization.
                let signature_share_bytes: Vec<u8> =
                    C::serialize_signature_share(&signature_share)?;

                let payload: Vec<u8> =
                    encode_wire(&FrostWire::SignatureShare {
                        identifier: self.identifier_u32,
                        signature_share: signature_share_bytes.clone(),
                    })?;

                self.signature_share_bytes =
                    Some(Secret::new(signature_share_bytes));

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
    /// The signature share bytes are consumed here — calling `finalize` twice
    /// will return an error.
    ///
    /// # Errors
    /// * `Errors::Aborted` - If the protocol has been aborted.
    /// * `Errors::InvalidSignature` - If the signature share is missing.
    ///
    /// # Returns
    /// * `ProtocolOutput` - The protocol output containing the serialized
    ///   signature share to be sent to the controller.
    async fn finalize(&mut self) -> Result<ProtocolOutput, Errors> {
        if self.aborted {
            return Err(Errors::Aborted("Protocol has been aborted.".into()));
        }

        // take() ensures the share bytes are consumed and cannot be reused.
        let share_secret: Secret<Vec<u8>> =
            self.signature_share_bytes.take().ok_or_else(|| {
                Errors::InvalidSignature("Missing signature share.".into())
            })?;

        let share_bytes: Vec<u8> =
            share_secret.with_ref(|bytes: &Vec<u8>| bytes.clone());

        Ok(ProtocolOutput::Signature(FinalSignature::Raw(share_bytes)))
    }

    /// Abort the protocol and clear all sensitive cryptographic material.
    fn abort(&mut self) {
        self.aborted = true;
        // Explicitly drop nonces and signature share to clear sensitive
        // material from memory.
        self.nonces = None;
        self.signature_share_bytes = None;
    }
}
