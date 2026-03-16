//! CGGMP24 ECDSA Secp256k1 signing protocol implementation.

use std::{
    array::TryFromSliceError,
    collections::VecDeque,
    num::TryFromIntError,
};

use async_trait::async_trait;
use cggmp24::{
    DataToSign,
    generic_ec::{NonZero, Point, curves::Secp256k1 as CggmpSecp256k1},
    key_share::KeyShare,
};
use crossbeam_channel::{
    Receiver,
    RecvError,
    SendError,
    Sender,
    bounded,
    unbounded,
};
use k256::ecdsa::{
    Error as EcdsaError,
    RecoveryId,
    Signature as K256Signature,
    VerifyingKey,
};
use rkyv::{Archived, access, deserialize, rancor::Error as RkyvError};
use round_based::{
    Incoming,
    MessageDestination,
    MessageType,
    MsgId,
    Outgoing,
};
use serde_json::{Error, from_slice, to_vec};
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
                tasks::worker::{
                    CggmpSigningMessage,
                    CggmpSigningOutput,
                    SigningProtocol,
                    SigningWorkerDone,
                },
                worker::{Worker, WorkerDone, spawn_worker},
            },
            security_level::Cggmp24SecurityLevel,
            stored_key::{ArchivedCggmp24StoredKey, Cggmp24StoredKey},
            wire::Cggmp24Wire,
        },
        codec::{decode_wire, encode_wire},
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

/// CGGMP24 ECDSA Secp256k1 signing protocol instance.
pub struct Cggmp24EcdsaSecp256k1NodeSigning {
    /// Signing threshold.
    threshold: u32,
    /// Total number of participants.
    participants: u32,
    /// Identifier of the current participant as u32.
    identifier_u32: u32,
    /// Message to be signed as bytes.
    message_bytes: Vec<u8>,
    /// Public key bytes.
    public_key_bytes: Vec<u8>,
    /// Channel to send incoming messages to the worker.
    incoming_transmitter: Sender<Incoming<CggmpSigningMessage>>,
    /// Channel to receive outgoing message batches from the worker.
    outgoing_receiver: Receiver<Vec<Outgoing<CggmpSigningMessage>>>,
    /// Channel to receive worker completion notifications.
    done_receiver: Receiver<SigningWorkerDone>,
    /// Pending outgoing messages not yet forwarded to the engine.
    pending_messages: VecDeque<RoundMessage>,
    /// Worker completion signal captured by drain_pending.
    worker_done: Option<SigningWorkerDone>,
    /// Message identifier counter used to populate `RoundMessage.round`.
    /// Important: `round_based::MsgId` is not cryptographically meaningful
    /// in CGGMP24. It is only used to ensure a monotonic message identifier
    /// when delivering messages to the state machine.
    /// CGGMP24 encodes its real protocol rounds inside the message payloads.
    /// Therefore, a local monotonic counter is sufficient and correct.
    message_identifier: MsgId,
    /// Indicates if the protocol has been aborted.
    aborted: bool,
}

impl Cggmp24EcdsaSecp256k1NodeSigning {
    /// Creates a new CGGMP24 ECDSA Secp256k1 signing protocol instance.
    ///
    /// # Arguments
    /// * `protocol_init` (`ProtocolInit`) - Protocol initialization
    ///   parameters.
    ///
    /// # Returns
    /// * `Result<Self, Errors>` - New protocol instance or error.
    pub fn try_new(protocol_init: ProtocolInit) -> Result<Self, Errors> {
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
        // structure used by the signing protocol. This is necessary
        // because the stored key is persisted in a format that is
        // independent of the internal representation, and we need to convert
        // it back before running the protocol.
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
        let digest: [u8; 32] =
            Sha256::digest(init.common.key_identifier.as_bytes()).into();

        // Extract the first 8 bytes of the hash and convert to a `u64`.
        let bytes: [u8; 8] = digest
            .get(0..8)
            .and_then(|slice: &[u8]| slice.try_into().ok())
            .ok_or(Errors::InvalidMessage(
                "Failed to extract 8 bytes from SHA-256 digest.".into(),
            ))?;

        // Reduce the number modulo `participants` to get the starting index,
        // then select `threshold` consecutive parties with wrap-around.
        let start: u16 = u16::try_from(
            u64::from_be_bytes(bytes) % init.common.participants as u64,
        )
        .map_err(|error: TryFromIntError| {
            Errors::InvalidMessage(format!(
                "Failed to convert hash to start index: {}",
                error
            ))
        })?;

        // Convert participants to u16 once — reused in the modulo below.
        let participants_u16: u16 = u16::try_from(init.common.participants)
            .map_err(|error: TryFromIntError| {
                Errors::InvalidMessage(error.to_string())
            })?;

        // Select `threshold` consecutive participant indices starting from
        // `start`, wrapping around modulo `participants`.
        let mut parties: Vec<u16> = (0..init.common.threshold)
            .map(|index: u32| {
                u16::try_from(index)
                    .map(|index: u16| (start + index) % participants_u16)
                    .map_err(|error: TryFromIntError| {
                        Errors::InvalidMessage(error.to_string())
                    })
            })
            .collect::<Result<Vec<u16>, Errors>>()?;

        // Sort to ensure a canonical ordering — required by CGGMP24 signing.
        parties.sort();

        // Validate that the local participant (identified by
        // `stored.identifier`) is part of the derived signer set. If not, this
        // node should not be participating in the protocol, and we should
        // return an error.
        if !parties.contains(&stored.identifier) {
            return Err(Errors::InvalidParticipant(
                "Local participant is not part of the signer set derived from \
                key_identifier. Check that the controller is configured \
                correctly."
                    .into(),
            ));
        }

        // Determine the local participant's index in the signer set. This will
        // be used as the participant identifier in the CGGMP24 protocol
        // messages. Note that CGGMP24 expects participant identifiers to be in
        // the range [0, participants-1], so we use the index in the `parties`
        // vector rather than the raw `stored.identifier`.
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
        // generation and auxiliary generation executions sharing the
        // same key identifier.
        let execution_identifier_bytes: Vec<u8> =
            format!("sign:{}", init.common.key_identifier).into_bytes();

        // Extract the compressed SEC1-encoded public key bytes for signature
        // verification and recovery identifier computation in finalize().
        let public_key: NonZero<Point<CggmpSecp256k1>> =
            key_share.core.shared_public_key;
        let public_key_bytes: Vec<u8> =
            public_key.to_bytes(true).as_ref().to_vec();

        // Channel pair for delivering incoming protocol messages to the
        // worker.
        let (incoming_transmitter, incoming_receiver): (
            Sender<Incoming<CggmpSigningMessage>>,
            Receiver<Incoming<CggmpSigningMessage>>,
        ) = unbounded();

        // Channel pair for receiving outgoing protocol message batches from
        // the worker.
        let (outgoing_transmitter, outgoing_receiver): (
            Sender<Vec<Outgoing<CggmpSigningMessage>>>,
            Receiver<Vec<Outgoing<CggmpSigningMessage>>>,
        ) = unbounded();

        // Bounded channel for receiving the worker completion signal —
        // capacity of 1 since the worker sends exactly one done signal
        // at the end.
        let (done_transmitter, done_receiver): (
            Sender<SigningWorkerDone>,
            Receiver<SigningWorkerDone>,
        ) = bounded(1);

        // Spawn the worker thread to run the CGGMP24 signing protocol. The
        // worker executes the protocol state machine and communicates with
        // this struct via the channels.
        spawn_worker(Worker {
            protocol: SigningProtocol {
                identifier,
                parties,
                key_share,
                data_to_sign,
                execution_identifier_bytes,
            },
            incoming_receiver,
            outgoing_transmitter,
            done_transmitter,
        });

        Ok(Self {
            threshold: init.common.threshold,
            participants: init.common.participants,
            identifier_u32: stored.identifier as u32,
            message_bytes: init.common.message,
            public_key_bytes,
            incoming_transmitter,
            outgoing_receiver,
            done_receiver,
            pending_messages: VecDeque::new(),
            worker_done: None,
            message_identifier: 0,
            aborted: false,
        })
    }

    /// Drains all pending outgoing messages from the worker and captures any
    /// completion signal. This should be called at the beginning of each
    /// round to ensure timely processing of worker outputs. It is also
    /// called after handling an incoming message to capture any new outgoing
    /// messages or completion signals triggered by that message.
    ///
    /// # Errors
    /// * `Errors::InvalidMessage` if a message from the worker cannot be
    ///   serialized.
    fn drain_pending(&mut self) -> Result<(), Errors> {
        // Drain all outgoing message batches produced by the worker since the
        // last call — each batch corresponds to one state machine step.
        while let Ok(batch) = self.outgoing_receiver.try_recv() {
            for outgoing in batch {
                let message: RoundMessage = self.wrap_outgoing(outgoing)?;
                self.pending_messages.push_back(message);
            }
        }

        // Capture the worker completion signal if not already received —
        // try_recv avoids blocking since the worker may still be running.
        if self.worker_done.is_none()
            && let Ok(done) = self.done_receiver.try_recv()
        {
            self.worker_done = Some(done);
        }

        Ok(())
    }

    /// Wraps an outgoing CGGMP message into a round-based protocol message.
    ///
    /// # Arguments
    /// * `outgoing` (`Outgoing<CggmpSigningMessage>`) - The outgoing message
    ///   from the worker to wrap.
    ///
    /// # Errors
    /// * `Errors::InvalidMessage` if the message cannot be serialized or
    ///   wrapped.
    ///
    /// # Returns
    /// * `Result<RoundMessage, Errors>` - The wrapped round message ready to
    ///   be sent to the engine, or an error if wrapping fails.
    fn wrap_outgoing(
        &mut self,
        outgoing: Outgoing<CggmpSigningMessage>,
    ) -> Result<RoundMessage, Errors> {
        // Serialize the CGGMP24 message and wrap it in the wire envelope.
        let payload: Vec<u8> = encode_wire(&Cggmp24Wire::ProtocolMessage {
            payload: to_vec(&outgoing.msg).map_err(|error: Error| {
                Errors::InvalidMessage(format!(
                    "Failed to serialize CGGMP message: {}",
                    error
                ))
            })?,
        })?;

        // Resolve the recipient — P2P messages carry a specific target,
        // broadcast messages are sent to all parties.
        let to: Option<u32> = match outgoing.recipient {
            MessageDestination::OneParty(identifier) => {
                Some(u32::from(identifier))
            },
            MessageDestination::AllParties => None,
        };

        // Assign a monotonic transport-level identifier — this is NOT a
        // CGGMP24 protocol round. Real rounds are encoded inside the
        // message payload by the state machine.
        let round: Round = self.message_identifier as Round;
        self.message_identifier = self.message_identifier.saturating_add(1);

        Ok(RoundMessage {
            round,
            from: Some(self.identifier_u32),
            to,
            payload,
        })
    }
}

#[async_trait]
impl Protocol for Cggmp24EcdsaSecp256k1NodeSigning {
    fn algorithm(&self) -> Algorithm {
        Algorithm::Cggmp24EcdsaSecp256k1
    }

    fn threshold(&self) -> u32 {
        self.threshold
    }

    fn participants(&self) -> u32 {
        self.participants
    }

    fn current_round(&self) -> Round {
        self.message_identifier as Round
    }

    async fn next_round(&mut self) -> Result<Option<RoundMessage>, Errors> {
        if self.aborted {
            return Err(Errors::Aborted("Protocol has been aborted.".into()));
        }

        // Drain any outgoing messages or completion signals produced by the
        // worker asynchronously since the last call.
        self.drain_pending()?;

        Ok(self.pending_messages.pop_front())
    }

    async fn handle_message(
        &mut self,
        round_message: RoundMessage,
    ) -> Result<Option<RoundMessage>, Errors> {
        if self.aborted {
            return Err(Errors::Aborted("Protocol has been aborted.".into()));
        }

        // Unwrap the wire envelope and deserialize the CGGMP24 message.
        let Cggmp24Wire::ProtocolMessage { payload }: Cggmp24Wire =
            decode_wire(&round_message.payload)?;

        let message: CggmpSigningMessage =
            from_slice(&payload).map_err(|error: Error| {
                Errors::InvalidMessage(format!(
                    "Failed to deserialize CGGMP message: {}",
                    error
                ))
            })?;

        // Resolve the sender identifier and message type for the state
        // machine.
        let sender_u16: u16 = round_message
            .from
            .ok_or(Errors::InvalidMessage("Missing sender.".into()))?
            .try_into()
            .map_err(|error: TryFromIntError| {
                Errors::InvalidMessage(format!(
                    "Failed to convert sender identifier to u16: {}",
                    error
                ))
            })?;

        // Deliver the message to the worker — P2P if a recipient is set,
        // broadcast otherwise.
        self.incoming_transmitter
            .send(Incoming {
                id: round_message.round as MsgId,
                sender: sender_u16,
                msg_type: if round_message.to.is_some() {
                    MessageType::P2P
                } else {
                    MessageType::Broadcast
                },
                msg: message,
            })
            .map_err(|error: SendError<Incoming<CggmpSigningMessage>>| {
                Errors::Aborted(format!(
                    "Failed to send incoming message: {}",
                    error
                ))
            })?;

        // Drain pending after delivering the message — the worker may have
        // produced new outgoing messages or a completion signal synchronously
        // in response. drain_pending is also called in next_round to catch
        // any messages produced asynchronously between rounds.
        self.drain_pending()?;

        Ok(self.pending_messages.pop_front())
    }

    /// Runs the protocol to completion, processing all messages and advancing
    /// rounds until the worker signals completion. This is used by the engine
    /// to drive the protocol after the initial round message is produced.
    ///
    /// # Returns
    /// * `Result<(), Errors>` - Ok if the protocol completes successfully, or
    ///   an error if any step fails.
    fn is_done(&self) -> bool {
        self.worker_done.is_some() && self.pending_messages.is_empty()
    }

    async fn finalize(&mut self) -> Result<ProtocolOutput, Errors> {
        if self.aborted {
            return Err(Errors::Aborted("Protocol has been aborted.".into()));
        }

        // Use the cached completion signal if already received during
        // drain_pending, otherwise block until the worker finishes.
        let done: WorkerDone<CggmpSigningOutput> =
            self.worker_done.take().map_or_else(
                || {
                    self.done_receiver.recv().map_err(|error: RecvError| {
                        Errors::FailedToSign(format!(
                            "Failed to finalize protocol: {}",
                            error
                        ))
                    })
                },
                Ok,
            )?;

        match done {
            SigningWorkerDone::Ok(signature) => {
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
                let k256_signature: K256Signature =
                    K256Signature::from_scalars(r, s).map_err(
                        |error: EcdsaError| {
                            Errors::InvalidSignature(format!(
                                "Failed to reconstruct K256 signature: {}",
                                error
                            ))
                        },
                    )?;

                // Reconstruct the verifying key from the stored public key
                // bytes for recovery identifier computation.
                let verifying_key: VerifyingKey =
                    VerifyingKey::from_sec1_bytes(&self.public_key_bytes)
                        .map_err(|error: EcdsaError| {
                            Errors::InvalidSignature(format!(
                                "Failed to reconstruct verifying key: {}",
                                error
                            ))
                        })?;

                // Compute the SHA-256 prehash of the message and recover the
                // recovery identifier (v) by trial recovery.
                let prehash: [u8; 32] =
                    Sha256::digest(&self.message_bytes).into();
                let recovery_id: RecoveryId =
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

                Ok(ProtocolOutput::Signature(FinalSignature::Ecdsa(
                    EcdsaSignature {
                        r: r.to_vec(),
                        s: s.to_vec(),
                        // u8 to u32 conversion.
                        v: recovery_id.to_byte() as u32,
                    },
                )))
            },

            SigningWorkerDone::Failed => {
                Err(Errors::FailedToSign("Protocol worker failed.".into()))
            },
        }
    }

    fn abort(&mut self) {
        self.aborted = true;
    }
}
