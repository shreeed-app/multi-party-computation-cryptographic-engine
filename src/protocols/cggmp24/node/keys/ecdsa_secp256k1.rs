//! CGGMP24 ECDSA Secp256k1 key generation protocol implementation.

use std::{collections::VecDeque, num::TryFromIntError};

use async_trait::async_trait;
use crossbeam_channel::{
    Receiver,
    RecvError,
    SendError,
    Sender,
    bounded,
    unbounded,
};
use rkyv::{rancor::Error as RkyvError, to_bytes};
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
                keys::worker::{
                    CggmpKeyGenerationMessage,
                    CggmpKeyGenerationOutput,
                    KeyGenerationProtocol,
                    KeyGenerationWorkerDone,
                },
                worker::{Worker, WorkerDone, spawn_worker},
            },
            stored_key::Cggmp24StoredKey,
            wire::Cggmp24Wire,
        },
        codec::{decode_wire, encode_wire},
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

/// CGGMP24 ECDSA Secp256k1 node key generation protocol descriptor.
pub struct Cggmp24EcdsaSecp256k1NodeKeyGeneration {
    /// Threshold number of participants required to complete the protocol.
    threshold: u32,
    /// Total number of participants in the protocol.
    participants: u32,
    /// Unique identifier for the protocol instance.
    identifier_u32: u32,
    /// Unique identifier for the key being generated.
    key_identifier: String,
    /// Channel for sending incoming messages to the protocol worker.
    incoming_transmitter: Sender<Incoming<CggmpKeyGenerationMessage>>,
    /// Channel for receiving outgoing messages from the protocol worker.
    outgoing_receiver: Receiver<Vec<Outgoing<CggmpKeyGenerationMessage>>>,
    /// Channel for receiving the completion signal from the protocol worker.
    done_receiver: Receiver<KeyGenerationWorkerDone>,
    /// Queue of pending outgoing messages to be sent in the next round.
    pending_messages: VecDeque<RoundMessage>,
    /// Optional completion signal from the protocol worker, set when the
    /// protocol is done.
    worker_done: Option<KeyGenerationWorkerDone>,
    /// Identifier for the next message to be sent, used to assign unique
    /// round numbers to outgoing messages.
    message_identifier: MsgId,
    /// Flag indicating whether the protocol has been aborted, used to prevent
    /// further processing of messages and rounds after abortion.
    aborted: bool,
}

impl Cggmp24EcdsaSecp256k1NodeKeyGeneration {
    /// Creates a new instance of the CGGMP24 ECDSA Secp256k1 node key
    /// generation protocol descriptor from the given protocol initialization
    /// parameters.
    ///
    /// # Arguments
    /// * `protocol_init` - The protocol initialization parameters, expected to
    ///   be of type `ProtocolInit::KeyGeneration(NodeKeyGenerationInit)`.
    ///
    /// # Returns
    /// * `Result<Self, Errors>` - Ok with the new instance if initialization
    ///   is successful, or an Err with an appropriate error if initialization
    ///   fails due to invalid parameters or unsupported algorithm.
    pub fn try_new(protocol_init: ProtocolInit) -> Result<Self, Errors> {
        let init: NodeKeyGenerationInit = match protocol_init {
            ProtocolInit::KeyGeneration(KeyGenerationInit::Node(init)) => init,
            _ => {
                return Err(Errors::InvalidProtocolInit(
                    "Expected NodeKeyGenerationInit struct.".into(),
                ));
            },
        };

        if init.common.algorithm != Algorithm::Cggmp24EcdsaSecp256k1 {
            return Err(Errors::UnsupportedAlgorithm(
                init.common.algorithm.as_str().into(),
            ));
        }

        let identifier: u16 =
            init.identifier.try_into().map_err(|error: TryFromIntError| {
                Errors::InvalidProtocolInit(error.to_string())
            })?;

        let participants_u16: u16 =
            init.common.participants.try_into().map_err(
                |error: TryFromIntError| {
                    Errors::InvalidProtocolInit(error.to_string())
                },
            )?;

        let threshold_u16: u16 = init.common.threshold.try_into().map_err(
            |error: TryFromIntError| {
                Errors::InvalidProtocolInit(error.to_string())
            },
        )?;

        let execution_id_bytes: Vec<u8> =
            init.common.key_identifier.clone().into_bytes();

        let (incoming_transmitter, incoming_receiver): (
            Sender<Incoming<CggmpKeyGenerationMessage>>,
            Receiver<Incoming<CggmpKeyGenerationMessage>>,
        ) = unbounded();
        let (outgoing_transmitter, outgoing_receiver): (
            Sender<Vec<Outgoing<CggmpKeyGenerationMessage>>>,
            Receiver<Vec<Outgoing<CggmpKeyGenerationMessage>>>,
        ) = unbounded();
        let (done_transmitter, done_receiver): (
            Sender<KeyGenerationWorkerDone>,
            Receiver<KeyGenerationWorkerDone>,
        ) = bounded(1);

        spawn_worker(Worker {
            protocol: KeyGenerationProtocol {
                identifier,
                participants: participants_u16,
                threshold: threshold_u16,
                execution_id_bytes,
            },
            incoming_receiver,
            outgoing_transmitter,
            done_transmitter,
        });

        Ok(Self {
            threshold: init.common.threshold,
            participants: init.common.participants,
            identifier_u32: init.identifier,
            key_identifier: init.common.key_identifier,
            incoming_transmitter,
            outgoing_receiver,
            done_receiver,
            worker_done: None,
            pending_messages: VecDeque::new(),
            message_identifier: 0,
            aborted: false,
        })
    }

    /// Drains all pending outgoing messages from the protocol worker and adds
    /// them to the queue of pending messages to be sent in the next round.
    /// Also checks for the completion signal from the worker and stores it if
    /// received.
    ///
    /// # Errors
    /// * `Errors::InvalidMessage` - If there is an error in receiving messages
    ///   from the worker or in processing them.
    ///
    /// # Returns
    /// * `Result<(), Errors>` - Ok if messages are successfully drained and
    ///   queued, or an Err if there is an error in receiving messages or the
    ///   completion signal.
    fn drain_pending(&mut self) -> Result<(), Errors> {
        while let Ok(batch) = self.outgoing_receiver.try_recv() {
            for outgoing in batch {
                let message: RoundMessage = self.wrap_outgoing(outgoing)?;
                self.pending_messages.push_back(message);
            }
        }
        if self.worker_done.is_none()
            && let Ok(done) = self.done_receiver.try_recv()
        {
            self.worker_done = Some(done);
        }
        Ok(())
    }

    /// Wraps an outgoing message from the protocol worker into a
    /// `RoundMessage` that can be sent to other parties. This involves
    /// serializing the message and encoding it into the appropriate wire
    /// format, as well as assigning a unique round number to the message.
    ///
    /// # Arguments
    /// * `outgoing` (`Outgoing<CggmpKeyGenerationMessage>`) - The outgoing
    ///   message from the protocol worker to be wrapped.
    ///
    /// # Errors
    /// * `Errors::InvalidMessage` - If there is an error in serializing the
    ///   message or encoding it into the wire format.
    ///
    /// # Returns
    /// * `Result<RoundMessage, Errors>` - Ok with the wrapped `RoundMessage`
    ///   if successful, or an Err with an appropriate error if there is a
    ///   failure in wrapping the message
    fn wrap_outgoing(
        &mut self,
        outgoing: Outgoing<CggmpKeyGenerationMessage>,
    ) -> Result<RoundMessage, Errors> {
        let inner: Vec<u8> =
            to_vec(&outgoing.msg).map_err(|error: Error| {
                Errors::InvalidMessage(error.to_string())
            })?;

        let payload: Vec<u8> =
            encode_wire(&Cggmp24Wire::ProtocolMessage { payload: inner })?;

        let to: Option<u32> = match outgoing.recipient {
            MessageDestination::OneParty(party) => Some(u32::from(party)),
            MessageDestination::AllParties => None,
        };

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
impl Protocol for Cggmp24EcdsaSecp256k1NodeKeyGeneration {
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

    async fn handle_message(
        &mut self,
        message: RoundMessage,
    ) -> Result<Option<RoundMessage>, Errors> {
        let Cggmp24Wire::ProtocolMessage { payload }: Cggmp24Wire =
            decode_wire(&message.payload)?;

        let key_generation_message: CggmpKeyGenerationMessage =
            from_slice(&payload).map_err(|error: Error| {
                Errors::InvalidMessage(error.to_string())
            })?;

        let sender: u16 = message
            .from
            .ok_or(Errors::InvalidMessage("Missing sender.".into()))?
            .try_into()
            .map_err(|error: TryFromIntError| {
                Errors::InvalidMessage(error.to_string())
            })?;

        // Send the incoming message to the protocol worker, which will process
        // it and generate any outgoing messages in response. The worker will
        // also update the protocol state and eventually produce a completion
        // signal when the protocol is done.
        self.incoming_transmitter
            .send(Incoming {
                id: message.round as MsgId,
                sender,
                msg_type: if message.to.is_some() {
                    MessageType::P2P
                } else {
                    MessageType::Broadcast
                },
                msg: key_generation_message,
            })
            .map_err(
                |error: SendError<Incoming<CggmpKeyGenerationMessage>>| {
                    Errors::InvalidMessage(error.to_string())
                },
            )?;

        Ok(None)
    }

    async fn next_round(&mut self) -> Result<Option<RoundMessage>, Errors> {
        if self.aborted {
            return Err(Errors::Aborted("Protocol aborted.".into()));
        }

        self.drain_pending()?;

        Ok(self.pending_messages.pop_front())
    }

    /// Runs the protocol by continuously processing incoming messages and
    /// generating outgoing messages until the protocol is complete. This
    /// involves draining pending messages from the worker, sending them to
    /// the appropriate recipients, and checking for the completion signal from
    /// the worker to determine when the protocol is done. The method returns
    /// an error if the protocol is aborted or if there are any issues in
    /// processing messages or the completion signal.
    ///
    /// # Returns
    /// * `Result<(), Errors>` - Ok if the protocol runs successfully until
    ///   completion, or an Err if the protocol is aborted or if there are any
    ///   errors in processing messages or the completion signal
    fn is_done(&self) -> bool {
        self.worker_done.is_some() && self.pending_messages.is_empty()
    }

    async fn finalize(&mut self) -> Result<ProtocolOutput, Errors> {
        if self.aborted {
            return Err(Errors::Aborted("Protocol aborted.".into()));
        }

        // Ensure that all pending messages are processed and the completion
        // signal from the worker is received before finalizing the protocol
        // and producing the output.
        let done: WorkerDone<CggmpKeyGenerationOutput> =
            if let Some(done) = self.worker_done.take() {
                done
            } else {
                self.done_receiver.recv().map_err(|error: RecvError| {
                    Errors::InvalidKeyShare(format!(
                        "Failed to finalize protocol: {}",
                        error
                    ))
                })?
            };

        match done {
            KeyGenerationWorkerDone::Ok(incomplete_key_share) => {
                let json: Vec<u8> = to_vec(&incomplete_key_share).map_err(
                    |error: Error| Errors::InvalidKeyShare(error.to_string()),
                )?;

                let stored: Cggmp24StoredKey = Cggmp24StoredKey {
                    identifier: self.identifier_u32 as u16,
                    key_share_json: json,
                };

                let blob: Vec<u8> = to_bytes::<RkyvError>(&stored)
                    .map_err(|error: RkyvError| {
                        Errors::InvalidKeyShare(error.to_string())
                    })?
                    .into_vec();

                let public_key: Vec<u8> = incomplete_key_share
                    .shared_public_key
                    .to_bytes(true)
                    .as_ref()
                    .to_vec();

                Ok(ProtocolOutput::KeyGeneration {
                    key_identifier: self.key_identifier.clone(),
                    key_share: Some(Secret::new(blob)),
                    public_key,
                    public_key_package: to_vec(&incomplete_key_share)
                        .map_err(|error: Error| {
                            Errors::InvalidKeyShare(error.to_string())
                        })?,
                })
            },

            KeyGenerationWorkerDone::Err => {
                Err(Errors::InvalidKeyShare("Protocol worker failed.".into()))
            },
        }
    }

    fn abort(&mut self) {
        self.aborted = true;
    }
}
