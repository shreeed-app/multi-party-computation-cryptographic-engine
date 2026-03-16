//! CGGMP24 ECDSA Secp256k1 auxiliary info generation node protocol.

use std::{collections::VecDeque, num::TryFromIntError};

use async_trait::async_trait;
use cggmp24::{
    KeyShare as CggmpKeyShare,
    generic_ec::curves::Secp256k1,
    key_share::{
        DirtyAuxInfo,
        DirtyIncompleteKeyShare,
        IncompleteKeyShare,
        InvalidKeyShare,
        Valid,
        ValidateError,
    },
};
use crossbeam_channel::{
    Receiver,
    RecvError,
    SendError,
    Sender,
    bounded,
    unbounded,
};
use rkyv::{
    Archived,
    access,
    deserialize,
    rancor::Error as RkyvError,
    to_bytes,
};
use round_based::{
    Incoming,
    MessageDestination,
    MessageType,
    MsgId,
    Outgoing,
};
use serde_json::{Error, from_slice, to_vec};

use crate::{
    proto::signer::v1::RoundMessage,
    protocols::{
        algorithm::Algorithm,
        cggmp24::{
            node::{
                keys::auxiliary::worker::{
                    AuxiliaryGenerationProtocol,
                    AuxiliaryGenerationWorkerDone,
                    CggmpAuxiliaryGenerationMessage,
                    CggmpAuxiliaryGenerationOutput,
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
            AuxiliaryGenerationInit,
            NodeAuxiliaryGenerationInit,
            ProtocolInit,
            ProtocolOutput,
            Round,
        },
    },
    secrets::{secret::Secret, types::KeyShare},
    transport::errors::Errors,
};

/// CGGMP24 ECDSA Secp256k1 auxiliary info generation node protocol instance.
///
/// Runs the aux gen MPC protocol to produce Paillier moduli and Pedersen
/// parameters for each participant. On completion, combines the
/// `IncompleteKeyShare` from DKG with the generated `AuxInfo` to produce
/// a complete `KeyShare` stored in Vault.
pub struct Cggmp24EcdsaSecp256k1NodeAuxiliaryGeneration {
    /// Total number of participants in the protocol.
    participants: u32,
    /// This participant's identifier as u32.
    identifier_u32: u32,
    /// Unique key identifier — used to scope the Vault storage path.
    key_identifier: String,
    /// The incomplete key share produced by DKG — combined with AuxInfo
    /// in finalize() to produce the complete KeyShare.
    incomplete_key_share: KeyShare,
    /// Channel for delivering incoming protocol messages to the worker.
    incoming_transmitter: Sender<Incoming<CggmpAuxiliaryGenerationMessage>>,
    /// Channel for receiving outgoing protocol message batches from the
    /// worker.
    outgoing_receiver:
        Receiver<Vec<Outgoing<CggmpAuxiliaryGenerationMessage>>>,
    /// Bounded channel for receiving the worker completion signal.
    done_receiver: Receiver<AuxiliaryGenerationWorkerDone>,
    /// Pending outgoing messages not yet forwarded to the engine.
    pending_messages: VecDeque<RoundMessage>,
    /// Worker completion signal captured by drain_pending.
    worker_done: Option<AuxiliaryGenerationWorkerDone>,
    /// Monotonic transport-level message identifier — not a protocol round.
    message_identifier: MsgId,
    /// True if the protocol has been aborted.
    aborted: bool,
}

impl Cggmp24EcdsaSecp256k1NodeAuxiliaryGeneration {
    /// Creates a new CGGMP24 ECDSA Secp256k1 auxiliary generation protocol
    /// instance.
    ///
    /// # Arguments
    /// * `protocol_init` (`ProtocolInit`) - Protocol initialization
    ///   parameters.
    ///
    /// # Errors
    /// * `Errors::InvalidProtocolInit` - If the init context is invalid.
    /// * `Errors::UnsupportedAlgorithm` - If the algorithm does not match.
    ///
    /// # Returns
    /// * `Self` - The initialized protocol instance ready to run.
    pub fn try_new(protocol_init: ProtocolInit) -> Result<Self, Errors> {
        let init: NodeAuxiliaryGenerationInit = match protocol_init {
            ProtocolInit::AuxiliaryGeneration(
                AuxiliaryGenerationInit::Node(init),
            ) => init,
            _ => {
                return Err(Errors::InvalidProtocolInit(
                    "Invalid protocol initialization context for CGGMP24 \
                    node auxiliary generation."
                        .into(),
                ));
            },
        };

        // Convert identifiers to u16 — required by the CGGMP24 state machine.
        let identifier: u16 =
            init.identifier.try_into().map_err(|error: TryFromIntError| {
                Errors::InvalidProtocolInit(error.to_string())
            })?;

        let participants: u16 = init.common.participants.try_into().map_err(
            |error: TryFromIntError| {
                Errors::InvalidProtocolInit(error.to_string())
            },
        )?;

        // Prefix the execution identifier to avoid collisions with keygen
        // and signing executions sharing the same key identifier.
        let execution_identifier_bytes: Vec<u8> =
            format!("auxiliary:{}", init.common.key_identifier).into_bytes();

        // Channel pair for delivering incoming protocol messages to the
        // worker.
        let (incoming_transmitter, incoming_receiver): (
            Sender<Incoming<CggmpAuxiliaryGenerationMessage>>,
            Receiver<Incoming<CggmpAuxiliaryGenerationMessage>>,
        ) = unbounded();

        // Channel pair for receiving outgoing protocol message batches from
        // the worker.
        let (outgoing_transmitter, outgoing_receiver): (
            Sender<Vec<Outgoing<CggmpAuxiliaryGenerationMessage>>>,
            Receiver<Vec<Outgoing<CggmpAuxiliaryGenerationMessage>>>,
        ) = unbounded();

        // Bounded channel for receiving the worker completion signal —
        // capacity of 1 since the worker sends exactly one done signal
        // at the end.
        let (done_transmitter, done_receiver): (
            Sender<AuxiliaryGenerationWorkerDone>,
            Receiver<AuxiliaryGenerationWorkerDone>,
        ) = bounded(1);

        // Spawn the worker thread — it will drive the CGGMP24 aux gen state
        // machine to completion and signal via done_transmitter when finished.
        spawn_worker(Worker {
            protocol: AuxiliaryGenerationProtocol {
                identifier,
                participants,
                execution_identifier_bytes,
            },
            incoming_receiver,
            outgoing_transmitter,
            done_transmitter,
        });

        Ok(Self {
            participants: init.common.participants,
            identifier_u32: init.identifier,
            key_identifier: init.common.key_identifier,
            incomplete_key_share: init.incomplete_key_share,
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
    /// completion signal.
    ///
    /// # Errors
    /// * `Errors::InvalidMessage` - If a message cannot be wrapped.
    fn drain_pending(&mut self) -> Result<(), Errors> {
        // Drain all outgoing message batches produced by the worker since the
        // last call — each batch corresponds to one state machine step.
        while let Ok(batch) = self.outgoing_receiver.try_recv() {
            for outgoing in batch {
                let round_message: RoundMessage =
                    self.wrap_outgoing(outgoing)?;
                self.pending_messages.push_back(round_message);
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

    /// Wraps an outgoing CGGMP24 aux gen message into a transport-level
    /// `RoundMessage`.
    ///
    /// # Arguments
    /// * `outgoing` (`Outgoing<CggmpAuxGenMessage>`) - The outgoing message
    ///   from the worker to wrap.
    ///
    /// # Errors
    /// * `Errors::InvalidMessage` - If the message cannot be serialized.
    ///
    /// # Returns
    /// * `RoundMessage` - The wrapped message ready to be sent to the engine.
    fn wrap_outgoing(
        &mut self,
        outgoing: Outgoing<CggmpAuxiliaryGenerationMessage>,
    ) -> Result<RoundMessage, Errors> {
        // Serialize the CGGMP24 message and wrap it in the wire envelope.
        let payload: Vec<u8> = encode_wire(&Cggmp24Wire::ProtocolMessage {
            payload: to_vec(&outgoing.msg).map_err(|error: Error| {
                Errors::InvalidMessage(error.to_string())
            })?,
        })?;

        // Resolve the recipient — P2P messages carry a specific target,
        // broadcast messages are sent to all parties.
        let to: Option<u32> = match outgoing.recipient {
            MessageDestination::OneParty(party) => Some(u32::from(party)),
            MessageDestination::AllParties => None,
        };

        // Assign a monotonic transport-level identifier — this is NOT a
        // CGGMP24 protocol round. Real rounds are encoded inside the message
        // payload by the state machine.
        let round: u32 = self.message_identifier as Round;
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
impl Protocol for Cggmp24EcdsaSecp256k1NodeAuxiliaryGeneration {
    fn algorithm(&self) -> Algorithm {
        Algorithm::Cggmp24EcdsaSecp256k1
    }

    fn threshold(&self) -> u32 {
        // Aux gen requires all participants — threshold equals participants.
        self.participants
    }

    fn participants(&self) -> u32 {
        self.participants
    }

    fn current_round(&self) -> Round {
        self.message_identifier as Round
    }

    /// Handle an incoming aux gen protocol message and deliver it to the
    /// worker.
    ///
    /// # Errors
    /// * `Errors::InvalidMessage` - If the message cannot be decoded or
    ///   delivered to the worker.
    async fn handle_message(
        &mut self,
        message: RoundMessage,
    ) -> Result<Option<RoundMessage>, Errors> {
        // Unwrap the wire envelope and deserialize the CGGMP24 message.
        let Cggmp24Wire::ProtocolMessage { payload }: Cggmp24Wire =
            decode_wire(&message.payload)?;

        let auxiliary_generation_message: CggmpAuxiliaryGenerationMessage =
            from_slice(&payload).map_err(|error: Error| {
                Errors::InvalidMessage(error.to_string())
            })?;

        // Resolve the sender identifier and message type for the state
        // machine.
        let sender: u16 = message
            .from
            .ok_or(Errors::InvalidMessage("Missing sender.".into()))?
            .try_into()
            .map_err(|error: TryFromIntError| {
                Errors::InvalidMessage(error.to_string())
            })?;

        // Deliver the message to the worker — P2P if a recipient is set,
        // broadcast otherwise. The worker will process it, advance the state
        // machine, and produce outgoing messages or a completion signal.
        self.incoming_transmitter
            .send(Incoming {
                id: message.round as MsgId,
                sender,
                msg_type: if message.to.is_some() {
                    MessageType::P2P
                } else {
                    MessageType::Broadcast
                },
                msg: auxiliary_generation_message,
            })
            .map_err(
                |error: SendError<
                    Incoming<CggmpAuxiliaryGenerationMessage>,
                >| {
                    Errors::InvalidMessage(error.to_string())
                },
            )?;

        Ok(None)
    }

    /// Drain pending outgoing messages and return the next one if available.
    ///
    /// # Errors
    /// * `Errors::Aborted` - If the protocol has been aborted.
    /// * `Errors::InvalidMessage` - If a message cannot be wrapped.
    async fn next_round(&mut self) -> Result<Option<RoundMessage>, Errors> {
        if self.aborted {
            return Err(Errors::Aborted("Protocol aborted.".into()));
        }

        // Drain any outgoing messages or completion signals produced by the
        // worker asynchronously since the last call.
        self.drain_pending()?;

        Ok(self.pending_messages.pop_front())
    }

    fn is_done(&self) -> bool {
        self.worker_done.is_some() && self.pending_messages.is_empty()
    }

    /// Finalize the aux gen protocol — combine the `IncompleteKeyShare` with
    /// the generated `AuxInfo` to produce a complete `KeyShare` for Vault
    /// storage.
    ///
    /// # Errors
    /// * `Errors::Aborted` - If the protocol has been aborted.
    /// * `Errors::InvalidKeyShare` - If any step of key assembly fails.
    ///
    /// # Returns
    /// * `ProtocolOutput::AuxiliaryGeneration` - The complete key share blob
    ///   and scoped key identifier.
    async fn finalize(&mut self) -> Result<ProtocolOutput, Errors> {
        if self.aborted {
            return Err(Errors::Aborted("Protocol aborted.".into()));
        }

        // Use the cached completion signal if already received during
        // drain_pending, otherwise block until the worker finishes.
        let done: WorkerDone<CggmpAuxiliaryGenerationOutput> =
            self.worker_done.take().map_or_else(
                || {
                    self.done_receiver.recv().map_err(|error: RecvError| {
                        Errors::InvalidKeyShare(format!(
                            "Failed to finalize aux gen: {}",
                            error
                        ))
                    })
                },
                Ok,
            )?;

        match done {
            AuxiliaryGenerationWorkerDone::Ok(aux_info) => {
                // Deserialize the IncompleteKeyShare from the Vault blob
                // passed at init — produced by the keygen protocol.
                let stored: Cggmp24StoredKey =
                    self.incomplete_key_share.with_ref(|blob: &Vec<u8>| {
                        let archived: &ArchivedCggmp24StoredKey = access::<
                            Archived<Cggmp24StoredKey>,
                            RkyvError,
                        >(
                            blob
                        )
                        .map_err(|error: RkyvError| {
                            Errors::InvalidKeyShare(error.to_string())
                        })?;

                        deserialize::<Cggmp24StoredKey, RkyvError>(archived)
                            .map_err(|error: RkyvError| {
                                Errors::InvalidKeyShare(error.to_string())
                            })
                    })?;

                let incomplete: IncompleteKeyShare<Secp256k1> = from_slice(
                    &stored.key_share_json,
                )
                .map_err(|error: Error| {
                    Errors::InvalidKeyShare(error.to_string())
                })?;

                // Combine IncompleteKeyShare + AuxInfo → complete KeyShare.
                let key_share: CggmpKeyShare<Secp256k1, Cggmp24SecurityLevel> =
                    CggmpKeyShare::from_parts((incomplete, aux_info)).map_err(
                        |error: ValidateError<
                            (
                                Valid<DirtyIncompleteKeyShare<Secp256k1>>,
                                Valid<DirtyAuxInfo<Cggmp24SecurityLevel>>,
                            ),
                            InvalidKeyShare,
                        >| {
                            Errors::InvalidKeyShare(error.to_string())
                        },
                    )?;

                // Serialize the complete KeyShare to JSON and wrap in a
                // Cggmp24StoredKey for rkyv Vault storage.
                let new_stored: Cggmp24StoredKey = Cggmp24StoredKey {
                    identifier: self.identifier_u32 as u16,
                    key_share_json: to_vec(&key_share).map_err(
                        |error: Error| {
                            Errors::InvalidKeyShare(error.to_string())
                        },
                    )?,
                };

                let blob: Vec<u8> = to_bytes::<RkyvError>(&new_stored)
                    .map_err(|error: RkyvError| {
                        Errors::InvalidKeyShare(error.to_string())
                    })?
                    .into_vec();

                // Scope the key share under "<key_id>/<participant_id>" to
                // avoid Vault collisions across participants.
                Ok(ProtocolOutput::AuxiliaryGeneration {
                    key_identifier: format!(
                        "{}/{}",
                        self.key_identifier, self.identifier_u32
                    ),
                    key_share: Some(Secret::new(blob)),
                })
            },

            AuxiliaryGenerationWorkerDone::Failed => {
                Err(Errors::InvalidKeyShare("AuxGen worker failed.".into()))
            },
        }
    }

    fn abort(&mut self) {
        self.aborted = true;
    }
}
