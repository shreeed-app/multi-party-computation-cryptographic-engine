//! CGGMP24 ECDSA Secp256k1 key generation protocol implementation.

use async_trait::async_trait;
use crossbeam_channel::{Receiver, Sender, bounded, unbounded};
use rkyv::rancor::Error as RkyvError;
use round_based::{
    Incoming,
    MessageDestination,
    MessageType,
    MsgId,
    Outgoing,
};
use serde_json::{from_slice, to_vec};

use crate::{
    protocols::{
        algorithm::Algorithm,
        cggmp24::{
            node::keys::worker::{
                CggmpKeyGenerationMessage,
                Worker,
                WorkerDone,
                spawn_worker,
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
            RoundMessage,
        },
    },
    secrets::secret::Secret,
    transport::error::Error,
};

/// CGGMP24 ECDSA Secp256k1 key generation protocol instance.
pub struct Cggmp24EcdsaSecp256k1NodeKeyGeneration {
    /// Number of participants required to generate the key.
    threshold: u32,
    /// Total number of participants.
    participants: u32,
    /// Participant's identifier as u32.
    identifier_u32: u32,
    /// Unique key identifier.
    key_id: String,
    /// Channel to send incoming CGGMP24 messages to the worker.
    incoming_transmitter: Sender<Incoming<CggmpKeyGenerationMessage>>,
    /// Channel to receive outgoing CGGMP24 messages from the worker.
    outgoing_receiver: Receiver<Outgoing<CggmpKeyGenerationMessage>>,
    /// Channel to receive the final result from the worker.
    done_receiver: Receiver<WorkerDone>,
    /// Monotonic message identifier for outgoing messages.
    message_id: MsgId,
    /// Indicates if the protocol has been aborted.
    aborted: bool,
}

impl Cggmp24EcdsaSecp256k1NodeKeyGeneration {
    /// Try to create a new CGGMP24 ECDSA Secp256k1 key generation protocol
    /// instance.
    ///
    /// # Arguments
    /// * `protocol_init` (`ProtocolInit`) - Protocol initialization context.
    ///
    /// # Errors
    /// * `Error::InvalidProtocolInit` if the initialization context is invalid
    ///   or contains unsupported parameters (e.g., zero threshold, identifier
    ///   out of range).
    /// * `Error::UnsupportedAlgorithm` if the algorithm specified in the
    ///   initialization context is not CGGMP24 ECDSA Secp256k1.
    ///
    /// # Returns
    /// * `Cggmp24EcdsaSecp256k1NodeKeyGeneration` - Initialized protocol
    ///   instance.
    pub fn try_new(protocol_init: ProtocolInit) -> Result<Self, Error> {
        let init: NodeKeyGenerationInit = match protocol_init {
            ProtocolInit::KeyGeneration(KeyGenerationInit::Node(init)) => init,
            _ => return Err(Error::InvalidProtocolInit),
        };

        if init.common.algorithm != Algorithm::Cggmp24EcdsaSecp256k1 {
            return Err(Error::UnsupportedAlgorithm(
                init.common.algorithm.as_str().into(),
            ));
        }

        // CGGMP24 key generation uses indices i in [0, n).
        if init.common.threshold == 0
            || init.common.threshold > init.common.participants
        {
            return Err(Error::InvalidThreshold);
        }

        // CGGMP24 key generation uses indices i in [0, n).
        let identifier: u16 = init
            .identifier
            .try_into()
            .map_err(|_| Error::InvalidProtocolInit)?;

        let participants_u16: u16 = u16::try_from(init.common.participants)
            .map_err(|_| Error::InvalidProtocolInit)?;

        if identifier >= participants_u16 {
            return Err(Error::InvalidProtocolInit);
        }

        let threshold_u16: u16 = u16::try_from(init.common.threshold)
            .map_err(|_| Error::InvalidProtocolInit)?;

        let execution_id_bytes: Vec<u8> =
            init.common.key_id.clone().into_bytes();

        let (incoming_transmitter, incoming_receiver): (
            Sender<Incoming<CggmpKeyGenerationMessage>>,
            Receiver<Incoming<CggmpKeyGenerationMessage>>,
        ) = unbounded();
        let (outgoing_transmitter, outgoing_receiver): (
            Sender<Outgoing<CggmpKeyGenerationMessage>>,
            Receiver<Outgoing<CggmpKeyGenerationMessage>>,
        ) = unbounded();
        let (done_transmitter, done_receiver): (
            Sender<WorkerDone>,
            Receiver<WorkerDone>,
        ) = bounded(1);

        // Spawn the CGGMP24 worker in a separate OS thread. The worker will
        // execute the actual CGGMP24 key generation protocol and communicate
        // with this instance via the provided channels.
        spawn_worker(Worker {
            identifier,
            participants: participants_u16,
            threshold: threshold_u16,
            execution_id_bytes,
            incoming_receiver,
            outgoing_transmitter,
            done_transmitter,
        });

        Ok(Self {
            threshold: init.common.threshold,
            participants: init.common.participants,
            identifier_u32: identifier as u32,
            key_id: init.common.key_id,
            incoming_transmitter,
            outgoing_receiver,
            done_receiver,
            message_id: 0,
            aborted: false,
        })
    }

    fn wrap_outgoing(
        &mut self,
        outgoing: Outgoing<CggmpKeyGenerationMessage>,
    ) -> Result<RoundMessage, Error> {
        // Serialize CGGMP24 key generation message.
        let inner: Vec<u8> =
            to_vec(&outgoing.msg).map_err(|_| Error::InvalidMessage)?;

        // Wrap into wire format.
        let payload: Vec<u8> =
            encode_wire(&Cggmp24Wire::ProtocolMessage { payload: inner })?;

        // Determine recipient.
        let to: Option<u32> = match outgoing.recipient {
            MessageDestination::OneParty(p) => Some(u32::from(p)),
            MessageDestination::AllParties => None,
        };

        // Transport-level monotonic identifier.
        let round: Round = self.message_id as Round;
        self.message_id = self.message_id.saturating_add(1);

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
    /// Return the algorithm identifier for this protocol instance.
    ///
    /// # Returns
    /// * `Algorithm::Cggmp24EcdsaSecp256k1` - Algorithm enum variant for
    ///   CGGMP24 ECDSA Secp256k1 key generation.
    fn algorithm(&self) -> Algorithm {
        Algorithm::Cggmp24EcdsaSecp256k1
    }

    /// Return the threshold number of participants required for key
    /// generation.
    ///
    /// # Returns
    /// * `u32` - Threshold number of participants.
    fn threshold(&self) -> u32 {
        self.threshold
    }

    /// Return the total number of participants in the key generation protocol.
    ///
    /// # Returns
    /// * `u32` - Total number of participants.
    fn participants(&self) -> u32 {
        self.participants
    }

    /// Return the current round number for transport messages. This is a
    /// monotonic identifier that increments with each outgoing message.
    /// It is not directly related to the CGGMP24 protocol rounds, but can be
    /// used for transport-level ordering and validation.
    ///
    /// # Returns
    /// * `Round` - Current round number for transport messages.
    fn current_round(&self) -> Round {
        self.message_id as Round
    }

    /// Advance the protocol by processing an incoming message from another
    /// participant. This method is called by the orchestrator when a message
    /// is received from the transport layer.
    ///
    /// It deserializes the incoming message, sends it to the worker via the
    /// `incoming_transmitter` channel, and checks if the worker has produced
    /// any outgoing messages to send back to the orchestrator.
    ///
    /// # Arguments
    /// * `message` (`RoundMessage`) - Message received from another
    ///   participant.
    ///
    /// # Errors
    /// * `Error::Aborted` if the protocol has been aborted.
    /// * `Error::InvalidMessage` if the incoming message cannot be
    ///   deserialized or does not conform to the expected format.
    /// * `Error::InvalidProtocolState` if the protocol is in an invalid state
    ///   for processing messages (e.g., if the worker has already completed).
    ///
    /// # Returns
    /// * `Option<RoundMessage>` - If the worker has produced an outgoing
    ///   message in response to the incoming message, it is returned wrapped
    ///   in a `RoundMessage` ready to be sent by the orchestrator. If no
    ///   outgoing message is produced, `None` is returned.
    async fn next_round(&mut self) -> Result<Option<RoundMessage>, Error> {
        if self.aborted {
            return Err(Error::Aborted);
        }

        // Check if the worker has produced any outgoing messages to send back
        // to the orchestrator. This allows the protocol to respond immediately
        // to any messages produced by the worker, even if they are not
        // directly triggered by an incoming message (e.g., if the worker
        // produces a message as part of its internal processing).
        if let Ok(outgoing) = self.outgoing_receiver.try_recv() {
            return Ok(Some(self.wrap_outgoing(outgoing)?));
        }

        Ok(None)
    }

    /// Finalize the protocol and return the result. This is called by the
    /// orchestrator when the protocol is complete and the final output is
    /// needed.
    ///
    /// It waits for the worker to send the final result via the
    /// `done_receiver` channel, and then processes the result to produce
    /// the `ProtocolOutput`. For CGGMP24 key generation, the worker will
    /// return an `IncompleteKeyShare` which is then serialized and wrapped
    /// in the `ProtocolOutput::KeyGeneration` variant.
    ///
    /// # Errors
    /// * `Error::Aborted` if the protocol has been aborted.
    /// * `Error::InvalidKeyShare` if the worker returns an invalid key share
    ///   or if serialization of the key share fails.
    /// * `Error::InvalidProtocolState` if the protocol is in an invalid state
    ///   for finalization (e.g., if the worker has not yet produced a result).
    /// * `Error::InvalidMessage` if the final result from the worker cannot be
    ///   deserialized or does not conform to the expected format.
    ///
    /// # Returns
    /// * `ProtocolOutput::KeyGeneration` - Contains the key identifier, the
    ///   serialized key share, and the public key bytes.
    async fn handle_message(
        &mut self,
        message: RoundMessage,
    ) -> Result<Option<RoundMessage>, Error> {
        if self.aborted {
            return Err(Error::Aborted);
        }

        let Cggmp24Wire::ProtocolMessage { payload }: Cggmp24Wire =
            decode_wire(&message.payload)?;

        // Deserialize CGGMP24 key generation message (not signing message).
        let key_generation_message: CggmpKeyGenerationMessage =
            from_slice(&payload).map_err(|_| Error::InvalidMessage)?;

        let sender: u16 = message
            .from
            .ok_or(Error::InvalidMessage)?
            .try_into()
            .map_err(|_| Error::InvalidMessage)?;

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
            .map_err(|_| Error::Aborted)?;

        if let Ok(outgoing) = self.outgoing_receiver.try_recv() {
            return Ok(Some(self.wrap_outgoing(outgoing)?));
        }

        Ok(None)
    }

    /// Finalize the protocol and return the result. This is called by the
    /// orchestrator when the protocol is complete and the final output is
    /// needed.
    ///
    /// It waits for the worker to send the final result via the
    /// `done_receiver` channel, and then processes the result to produce
    /// the `ProtocolOutput`. For CGGMP24 key generation, the worker will
    /// return an `IncompleteKeyShare` which is then serialized and wrapped
    /// in the `ProtocolOutput::KeyGeneration` variant.
    ///
    /// # Errors
    /// * `Error::Aborted` if the protocol has been aborted.
    /// * `Error::InvalidKeyShare` if the worker returns an invalid key share
    ///   or if serialization of the key share fails.
    /// * `Error::InvalidProtocolState` if the protocol is in an invalid state
    ///   for finalization (e.g., if the worker has not yet produced a result).
    /// * `Error::InvalidMessage` if the final result from the worker cannot be
    ///   deserialized or does not conform to the expected format.
    ///
    /// # Returns
    /// * `ProtocolOutput::KeyGeneration` - Contains the key identifier, the
    ///   serialized key share, and the public key bytes.
    async fn finalize(&mut self) -> Result<ProtocolOutput, Error> {
        if self.aborted {
            return Err(Error::Aborted);
        }

        match self.done_receiver.recv() {
            // Worker returns an *IncompleteKeyShare* for key generation.
            Ok(WorkerDone::Ok(incomplete_key_share)) => {
                // Store what we actually have (incomplete share). It’s fine as
                // long as your signing protocol later knows
                // how to “complete” it (aux-info step).
                let json: Vec<u8> = serde_json::to_vec(&incomplete_key_share)
                    .map_err(|_| Error::InvalidKeyShare)?;

                let stored: Cggmp24StoredKey = Cggmp24StoredKey {
                    identifier: u16::try_from(self.identifier_u32)
                        .map_err(|_| Error::InvalidKeyShare)?,
                    key_share_json: json,
                };

                let blob: Vec<u8> = rkyv::to_bytes::<RkyvError>(&stored)
                    .map_err(|_| Error::InvalidKeyShare)?
                    .into_vec();

                // Public key bytes: depending on the exact CGGMP24 type
                // layout, this is typically accessible from
                // the core share.
                //
                // If your `IncompleteKeyShare` exposes this differently,
                // adjust this field access accordingly.
                let public_key: Vec<u8> = incomplete_key_share
                    .shared_public_key
                    .to_bytes(true)
                    .as_ref()
                    .to_vec();

                Ok(ProtocolOutput::KeyGeneration {
                    key_id: self.key_id.clone(),
                    key_share: Secret::new(blob),
                    public_key,
                    public_key_package: to_vec(&incomplete_key_share)
                        .map_err(|_| Error::InvalidKeyShare)?,
                })
            },
            _ => Err(Error::InvalidKeyShare),
        }
    }

    /// Abort the protocol. This is called by the orchestrator when the
    /// protocol needs to be aborted (e.g., due to a timeout or an
    /// unrecoverable error). It sets the `aborted` flag to true, which
    /// will cause all subsequent calls to `handle_message`, `next_round`,
    /// and `finalize` to return an `Error::Aborted`.
    ///
    /// # Returns
    /// * `()` - Nothing.
    fn abort(&mut self) {
        self.aborted = true;
    }
}
