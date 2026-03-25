//! CGGMP24 ECDSA Secp256k1 signing protocol implementation.

use std::{array::TryFromSliceError, num::TryFromIntError};

use async_trait::async_trait;
use cggmp24::{
    DataToSign,
    generic_ec::{NonZero, Point, curves::Secp256k1 as CggmpSecp256k1},
    key_share::KeyShare,
};
use k256::ecdsa::{
    Error as EcdsaError,
    RecoveryId,
    Signature as K256Signature,
    VerifyingKey,
};
use rkyv::{Archived, access, deserialize, rancor::Error as RkyvError};
use serde_json::{Error, from_slice};
use sha2::{Digest, Sha256};

use crate::{
    proto::signer::v1::{
        EcdsaSignature,
        RoundMessage,
        signature_result::FinalSignature,
    },
    protocols::{
        algorithm::Algorithm,
        cggmp24::{
            node::{
                protocol::{Cggmp24NodeProtocol, CggmpNodeProtocol},
                tasks::worker::{
                    CggmpSigningMessage,
                    CggmpSigningOutput,
                    SigningProtocol,
                },
            },
            security_level::Cggmp24SecurityLevel,
            stored_key::{ArchivedCggmp24StoredKey, Cggmp24StoredKey},
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

/// Protocol-specific data for CGGMP24 ECDSA Secp256k1 signing.
pub struct SigningData {
    /// Signing threshold.
    threshold: u32,
    /// Total number of participants.
    participants: u32,
    /// Message to be signed as bytes — used for prehash computation in
    /// finalize().
    message_bytes: Vec<u8>,
    /// Compressed SEC1-encoded public key bytes — used for verifying key
    /// reconstruction and recovery identifier computation in finalize().
    public_key_bytes: Vec<u8>,
}

/// Protocol descriptor implementing `CggmpNodeProtocol` for signing.
pub struct SigningProtocolDescriptor;

impl CggmpNodeProtocol for SigningProtocolDescriptor {
    type Message = CggmpSigningMessage;
    type Output = CggmpSigningOutput;
    type Data = SigningData;

    fn algorithm() -> Algorithm {
        Algorithm::Cggmp24EcdsaSecp256k1
    }

    fn threshold(data: &Self::Data) -> u32 {
        data.threshold
    }

    fn participants(data: &Self::Data) -> u32 {
        data.participants
    }

    /// Finalize the signing protocol — reconstruct the ECDSA signature and
    /// compute the recovery identifier.
    ///
    /// # Errors
    /// * `Errors::InvalidSignature` - If any step of signature reconstruction
    ///   or recovery identifier computation fails.
    ///
    /// # Returns
    /// * `ProtocolOutput::Signature` - The final ECDSA signature with r, s,
    ///   and v components.
    fn finalize(
        data: &mut Self::Data,
        output: Self::Output,
    ) -> Result<ProtocolOutput, Errors> {
        let signature: CggmpSigningOutput = output;

        // Extract r and s as fixed-size byte arrays from the CGGMP24
        // scalar representation.
        let r: [u8; 32] =
            signature.r.to_be_bytes().as_bytes().try_into().map_err(
                |error: TryFromSliceError| {
                    Errors::InvalidSignature(format!(
                        "Failed to convert r component to array: {}",
                        error
                    ))
                },
            )?;

        let s: [u8; 32] =
            signature.s.to_be_bytes().as_bytes().try_into().map_err(
                |error: TryFromSliceError| {
                    Errors::InvalidSignature(format!(
                        "Failed to convert s component to array: {}",
                        error
                    ))
                },
            )?;

        // Reconstruct the k256 signature from r and s for recovery
        // identifier computation.
        let k256_signature: K256Signature = K256Signature::from_scalars(r, s)
            .map_err(|error: EcdsaError| {
                Errors::InvalidSignature(format!(
                    "Failed to reconstruct K256 signature: {}",
                    error
                ))
            })?;

        // Reconstruct the verifying key from the stored public key bytes
        // for recovery identifier computation.
        let verifying_key: VerifyingKey = VerifyingKey::from_sec1_bytes(
            &data.public_key_bytes,
        )
        .map_err(|error: EcdsaError| {
            Errors::InvalidSignature(format!(
                "Failed to reconstruct verifying key: {}",
                error
            ))
        })?;

        // Compute the SHA-256 prehash of the message and recover the
        // recovery identifier (v) by trial recovery.
        let prehash: [u8; 32] = Sha256::digest(&data.message_bytes).into();
        let recovery_identifier: RecoveryId =
            RecoveryId::trial_recovery_from_prehash(
                &verifying_key,
                &prehash,
                &k256_signature,
            )
            .map_err(|error: EcdsaError| {
                Errors::InvalidSignature(format!(
                    "Failed to recover recovery identifier: {}",
                    error
                ))
            })?;

        Ok(ProtocolOutput::Signature(FinalSignature::Ecdsa(EcdsaSignature {
            r: r.to_vec(),
            s: s.to_vec(),
            // u8 to u32 conversion.
            v: recovery_identifier.to_byte() as u32,
        })))
    }
}

/// CGGMP24 ECDSA Secp256k1 signing protocol instance.
pub struct Cggmp24EcdsaSecp256k1NodeSigning(
    Cggmp24NodeProtocol<SigningProtocolDescriptor>,
);

impl Cggmp24EcdsaSecp256k1NodeSigning {
    /// Creates a new CGGMP24 ECDSA Secp256k1 signing protocol instance.
    ///
    /// # Arguments
    /// * `protocol_init` (`ProtocolInit`) - Protocol initialization
    ///   parameters, expected to be `ProtocolInit::Signing(Node(...))`.
    ///
    /// # Errors
    /// * `Errors::InvalidProtocolInit` - If the init context is invalid.
    /// * `Errors::InvalidKeyShare` - If the key share cannot be decoded.
    /// * `Errors::InvalidThreshold` - If the threshold is invalid.
    /// * `Errors::InvalidParticipant` - If this node is not in the signer set.
    ///
    /// # Returns
    /// * `Self` - The initialized protocol instance ready to run.
    pub fn try_new(protocol_init: ProtocolInit) -> Result<Self, Errors> {
        // Unpack the node signing init — reject any other protocol init.
        let init: NodeSigningInit = match protocol_init {
            ProtocolInit::Signing(SigningInit::Node(init)) => init,
            _ => {
                return Err(Errors::InvalidProtocolInit(
                    "Invalid protocol initialization context for CGGMP24 \
                    node signing."
                        .into(),
                ));
            },
        };

        // Access and deserialize the stored key share for this signing
        // operation.
        let stored: Cggmp24StoredKey =
            init.key_share.with_ref(|bytes: &Vec<u8>| {
                let archived: &ArchivedCggmp24StoredKey =
                    match access::<Archived<Cggmp24StoredKey>, RkyvError>(
                        bytes,
                    ) {
                        Ok(archived) => archived,
                        Err(error) => {
                            return Err(Errors::InvalidKeyShare(format!(
                                "Failed to access archived stored key: {}.",
                                error
                            )));
                        },
                    };

                deserialize::<Cggmp24StoredKey, RkyvError>(archived).map_err(
                    |error: RkyvError| {
                        Errors::InvalidKeyShare(format!(
                            "Failed to deserialize stored key: {}",
                            error
                        ))
                    },
                )
            })?;

        // Deserialize the key share JSON into the internal `KeyShare`
        // structure used by the signing protocol. This is necessary because
        // the stored key is persisted in a format that is independent of the
        // internal representation, and we need to convert it back before
        // running the protocol.
        let key_share: KeyShare<CggmpSecp256k1, Cggmp24SecurityLevel> =
            from_slice(&stored.key_share_json).map_err(|error: Error| {
                Errors::InvalidKeyShare(format!(
                    "Failed to deserialize key share: {}",
                    error
                ))
            })?;

        // Validate that the signing threshold is less than the number of
        // participants. This is a basic sanity check to prevent starting a
        // protocol that is guaranteed to fail.
        if init.common.threshold == 0
            || init.common.threshold > init.common.participants
        {
            return Err(Errors::InvalidThreshold(
                init.common.threshold,
                init.common.participants,
            ));
        }

        // Deterministic signer selection for CGGMP24.
        //
        // Context: CGGMP24 requires the exact set of signing participants
        // ("parties") to be known before the protocol starts. Unlike Frost,
        // there is no protocol message where the controller can announce who
        // signs.
        //
        // In this system, `ProtocolInit` is shared across all protocols and
        // does not contain a list of signing participants. To keep the API
        // uniform and avoid protocol-specific configuration, we rely on a
        // deterministic convention.
        //
        // The controller starts the signing session on all nodes.
        // All nodes know, the total number of participants (`participants`),
        // the signing threshold (`threshold`), the global key identifier
        // (`key_identifier`). From these public values, every node
        // independently derives the same signer set.
        //
        // Signer selection rule:
        //   1. Hash the global `key_identifier` using SHA-256.
        //   2. Interpret the first 8 bytes of the hash as a big-endian `u64`.
        //   3. Reduce this number modulo `participants` to obtain a starting
        //      index.
        //   4. Select `threshold` consecutive participant identifiers starting
        //      from this index, with wrap-around.
        //
        // Why this is deterministic:
        //   - `key_identifier` is identical on all nodes for a given key.
        //   - SHA-256 is deterministic.
        //   - The arithmetic is pure and does not depend on local state.
        //   - Therefore, all nodes compute the *exact same* `parties` list.
        //
        // Why this provides rotation:
        //   - Different `key_identifier`s produce different hashes.
        //   - Different hashes produce different starting indices.
        //   - Over multiple keys (or sessions), different subsets of nodes are
        //     selected, distributing load and exposure.
        let parties: Vec<u16> = compute_parties(
            &init.common.key_identifier,
            init.common.threshold,
            init.common.participants,
        )?;

        // Validate that the local participant (identified by
        // `stored.identifier`) is part of the derived signer set. If not,
        // this node should not be participating in the protocol.
        if !parties.contains(&stored.identifier) {
            return Err(Errors::InvalidParticipant(
                "Local participant is not part of the signer set derived from \
                key_identifier. Check that the controller is configured \
                correctly."
                    .into(),
            ));
        }

        // Determine the local participant's index in the signer set. This
        // will be used as the participant identifier in the CGGMP24 protocol
        // messages. Note that CGGMP24 expects participant identifiers to be
        // in the range [0, participants-1], so we use the index in the
        // `parties` vector rather than the raw `stored.identifier`.
        let identifier: u16 = parties
            .iter()
            .position(|&position: &u16| position == stored.identifier)
            .ok_or(Errors::InvalidParticipant(
                "Local participant not found in parties.".into(),
            ))? as u16;

        // Hash the raw message bytes into a CGGMP24 scalar for signing.
        let data_to_sign: DataToSign<CggmpSecp256k1> =
            DataToSign::digest::<Sha256>(&init.common.message);

        // Prefix the execution identifier to avoid collisions with key
        // generation and auxiliary generation executions sharing the same
        // key identifier.
        let execution_identifier_bytes: Vec<u8> =
            format!("sign:{}", init.common.key_identifier).into_bytes();

        // Extract the compressed SEC1-encoded public key bytes for signature
        // verification and recovery identifier computation in finalize().
        let public_key: NonZero<Point<CggmpSecp256k1>> =
            key_share.core.shared_public_key;
        let public_key_bytes: Vec<u8> =
            public_key.to_bytes(true).as_ref().to_vec();

        let data: SigningData = SigningData {
            threshold: init.common.threshold,
            participants: init.common.participants,
            message_bytes: init.common.message,
            public_key_bytes,
        };

        Ok(Self(Cggmp24NodeProtocol::new(
            data,
            stored.identifier as u32,
            // Spawn the worker thread to run the CGGMP24 signing protocol.
            // The worker executes the protocol state machine and communicates
            // with this struct via the channels.
            SigningProtocol {
                identifier,
                parties,
                key_share,
                data_to_sign,
                execution_identifier_bytes,
            },
        )))
    }
}

/// Deterministically compute the set of signing participants from the key
/// identifier, threshold, and participant count.
///
/// All nodes derive the same signer set independently from these public
/// values — see the inline comments in
/// `Cggmp24EcdsaSecp256k1NodeSigning::try_new` for the full rationale. This
/// function is exposed publicly so the node server can include the computed
/// set in its `StartSessionResponse`, allowing the controller to verify
/// cross-node consistency before the protocol runs.
///
/// # Errors
/// * `Errors::InvalidMessage` - If the hash cannot be computed or converted.
///
/// # Returns
/// * `Vec<u16>` - Sorted list of participant indices in the signer set.
pub fn compute_parties(
    key_identifier: &str,
    threshold: u32,
    participants: u32,
) -> Result<Vec<u16>, Errors> {
    // Hash the key identifier to derive a deterministic starting index —
    // all nodes compute the same hash for the same key identifier.
    let digest: [u8; 32] = Sha256::digest(key_identifier.as_bytes()).into();

    // Convert participants to u16 once — reused in modulo operations.
    let participants_u16: u16 =
        u16::try_from(participants).map_err(|error: TryFromIntError| {
            Errors::InvalidMessage(error.to_string())
        })?;

    // Reduce the hash modulo participants to get a starting index in
    // [0, participants).
    let first_eight_bytes: [u8; 8] = digest
        .iter()
        .copied()
        .take(8)
        .collect::<Vec<u8>>()
        .try_into()
        .map_err(|bytes: Vec<u8>| {
            Errors::InvalidMessage(format!(
                "Failed to extract first 8 bytes from digest: got {} bytes.",
                bytes.len()
            ))
        })?;

    let start: u16 = u16::try_from(
        u64::from_be_bytes(first_eight_bytes) % participants as u64,
    )
    .map_err(|error: TryFromIntError| {
        Errors::InvalidMessage(format!(
            "Failed to convert hash to start index: {}",
            error
        ))
    })?;

    // Select `threshold` consecutive participant indices starting from
    // `start`, wrapping around modulo `participants`.
    let mut parties: Vec<u16> = (0..threshold)
        .map(|index: u32| (start + index as u16) % participants_u16)
        .collect();

    // Sort to ensure a canonical ordering — required by CGGMP24 signing.
    parties.sort();

    Ok(parties)
}

#[async_trait]
impl Protocol for Cggmp24EcdsaSecp256k1NodeSigning {
    fn algorithm(&self) -> Algorithm {
        SigningProtocolDescriptor::algorithm()
    }

    fn threshold(&self) -> u32 {
        SigningProtocolDescriptor::threshold(&self.0.data)
    }

    fn participants(&self) -> u32 {
        SigningProtocolDescriptor::participants(&self.0.data)
    }

    fn current_round(&self) -> Round {
        self.0.message_identifier as Round
    }

    fn is_done(&self) -> bool {
        self.0.is_done()
    }

    /// Drain pending outgoing messages and return the next one if available.
    ///
    /// # Errors
    /// * `Errors::Aborted` - If the protocol has been aborted.
    /// * `Errors::InvalidMessage` - If a message cannot be wrapped.
    async fn next_round(&mut self) -> Result<Option<RoundMessage>, Errors> {
        if self.0.aborted {
            return Err(Errors::Aborted("Protocol has been aborted.".into()));
        }

        // Drain any outgoing messages or completion signals produced by the
        // worker asynchronously since the last call.
        self.0.drain_pending()?;

        Ok(self.0.pending_messages.pop_front())
    }

    /// Handle an incoming signing protocol message and deliver it to the
    /// worker.
    ///
    /// Drains pending messages after delivery — the worker may have produced
    /// new outgoing messages or a completion signal synchronously in response.
    ///
    /// # Errors
    /// * `Errors::Aborted` - If the protocol has been aborted or the worker
    ///   channel is disconnected.
    /// * `Errors::InvalidMessage` - If the message cannot be decoded or
    ///   delivered.
    async fn handle_message(
        &mut self,
        message: RoundMessage,
    ) -> Result<Option<RoundMessage>, Errors> {
        if self.0.aborted {
            return Err(Errors::Aborted("Protocol has been aborted.".into()));
        }

        // Deliver the message to the worker — P2P if a recipient is set,
        // broadcast otherwise.
        self.0.deliver_message(message)?;

        // Drain pending after delivering — the worker may have produced new
        // outgoing messages or a completion signal synchronously in response.
        // drain_pending is also called in next_round to catch messages
        // produced asynchronously between rounds.
        self.0.drain_pending()?;

        Ok(self.0.pending_messages.pop_front())
    }

    /// Consume and return the final signing output.
    ///
    /// Consumes the output — calling `finalize` twice will return an error.
    ///
    /// # Errors
    /// * `Errors::Aborted` - If the protocol has been aborted.
    /// * `Errors::InvalidSignature` - If signature reconstruction fails.
    async fn finalize(&mut self) -> Result<ProtocolOutput, Errors> {
        if self.0.aborted {
            return Err(Errors::Aborted("Protocol has been aborted.".into()));
        }

        self.0.finalize_inner()
    }

    fn abort(&mut self) {
        self.0.aborted = true;
        self.0.abort_worker();
    }
}
