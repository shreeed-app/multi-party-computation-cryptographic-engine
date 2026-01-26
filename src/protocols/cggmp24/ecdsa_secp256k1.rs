//! CGGMP24 ECDSA Secp256k1 signing protocol implementation.

use cggmp24::{
    DataToSign,
    generic_ec::{NonZero, Point, curves::Secp256k1 as CggmpSecp256k1},
    key_share::KeyShare,
    signing::msg::Msg,
};
use crossbeam_channel::{Receiver, Sender, bounded, unbounded};
use k256::ecdsa::{RecoveryId, Signature as K256Signature, VerifyingKey};
use rkyv::{Archived, access, deserialize, rancor::Error as RkyvError};
use round_based::{
    Incoming,
    MessageDestination,
    MessageType,
    MsgId,
    Outgoing,
};
use serde_json::{from_slice, to_vec};
use sha2::{Digest, Sha256};

use crate::{
    messages::error::Error,
    protocols::{
        algorithm::Algorithm,
        cggmp24::{
            stored_key::{ArchivedCggmp24StoredKey, Cggmp24StoredKey},
            wire::Cggmp24Wire,
            worker::{CggmpMessage, Worker, WorkerDone, spawn_worker},
        },
        codec::{decode_wire, encode_wire},
        signing::SigningProtocol,
        types::{ProtocolInit, Round, RoundMessage, Signature},
    },
};

/// CGGMP24 ECDSA Secp256k1 signing protocol instance.
pub struct Cggmp24EcdsaSecp256k1Protocol {
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
    incoming_transmitter: Sender<Incoming<CggmpMessage>>,
    /// Channel to receive outgoing messages from the worker.
    outgoing_receiver: Receiver<round_based::Outgoing<CggmpMessage>>,
    /// Channel to receive worker completion notifications.
    done_receiver: Receiver<WorkerDone>,
    /// Message identifier counter used to populate `RoundMessage.round`.
    /// Important: `round_based::MsgId` is not cryptographically meaningful
    /// in CGGMP24. It is only used to ensure a monotonic message identifier
    /// when delivering messages to the state machine.
    /// CGGMP24 encodes its real protocol rounds inside the message payloads.
    /// Therefore, a local monotonic counter is sufficient and correct.
    message_id: MsgId,
    /// Indicates if the protocol has been aborted.
    aborted: bool,
}

impl Cggmp24EcdsaSecp256k1Protocol {
    /// Creates a new CGGMP24 ECDSA Secp256k1 signing protocol instance.
    ///
    /// # Arguments
    /// * `init` (`ProtocolInit`) - Protocol initialization parameters.
    ///
    /// # Returns
    /// * `Result<Self, Error>` - New protocol instance or error.
    pub fn try_new(init: ProtocolInit) -> Result<Self, Error> {
        if init.algorithm != Algorithm::Cggmp24EcdsaSecp256k1 {
            return Err(Error::UnsupportedAlgorithm(
                init.algorithm.as_str().into(),
            ));
        }

        let stored: Cggmp24StoredKey = init.key_share.with_ref(|bytes| {
            let archived: &ArchivedCggmp24StoredKey =
                match access::<Archived<Cggmp24StoredKey>, RkyvError>(bytes) {
                    Ok(archived) => archived,
                    Err(_) => return Err(Error::InvalidKeyShare),
                };
            deserialize::<Cggmp24StoredKey, RkyvError>(archived)
                .map_err(|_| Error::InvalidKeyShare)
        })?;

        let key_share: KeyShare<CggmpSecp256k1> =
            from_slice(&stored.key_share_json)
                .map_err(|_| Error::InvalidKeyShare)?;

        if init.message.len() != 32 {
            return Err(Error::InvalidMessage);
        }

        // Validate threshold and participants.
        if init.threshold == 0 || init.threshold > init.participants {
            return Err(Error::InvalidThreshold);
        }

        // Deterministic signer selection for CGGMP24.
        //
        // Context: CGGMP24 requires the exact set of signing participants
        // ("parties") to be known the protocol starts. Unlike Frost, there is
        // no protocol message where the orchestrator can announce who signs.
        //
        // In this system, `ProtocolInit` is shared across all protocols and
        // does not contain a list of signing participants. To keep the API
        // uniform and avoid protocol-specific configuration, we rely on a
        // deterministic convention.
        //
        // The orchestrator starts the signing session on all nodes.
        // All nodes know, the total number of participants (`participants`),
        // the signing threshold (`threshold`), the global key identifier
        // (`key_id`). From these public values, every node independently
        // derives the same signer set.
        //
        // Signer selection rule:
        //   1. Hash the global `key_id` using SHA-256.
        //   2. Interpret the first 8 bytes of the hash as a big-endian `u64`.
        //   3. Reduce this number modulo `participants` to obtain a starting
        //      index.
        //   4. Select `threshold` consecutive participant identifiers starting
        //      from this index, with wrap-around.
        //
        // Why this is deterministic:
        //   - `key_id` is identical on all nodes for a given MPC key.
        //   - SHA-256 is deterministic.
        //   - The arithmetic is pure and does not depend on local state.
        //   - Therefore, all nodes compute the *exact same* `parties` list.
        //
        // Why this provides rotation:
        //   - Different `key_id`s produce different hashes.
        //   - Different hashes produce different starting indices.
        //   - Over multiple keys (or sessions), different subsets of nodes are
        //     selected, distributing load and exposure.

        // Hash the global key identifier to derive a
        // deterministic starting index.
        let mut hasher: Sha256 = Sha256::new();
        hasher.update(init.key_id.as_bytes());
        let digest = hasher.finalize();

        // Use the first 8 bytes of the hash as a u64 to avoid modulo bias.
        let start: u16 = match digest[0..8].try_into() {
            Ok(bytes) => {
                // Reduce modulo number of participants to get starting index.
                (u64::from_be_bytes(bytes) % init.participants as u64) as u16
            },
            Err(_) => return Err(Error::InvalidMessage),
        };

        // Build the signer set as `threshold` consecutive
        // participant identifiers.
        let mut parties: Vec<u16> =
            Vec::with_capacity(init.threshold as usize);
        for index in 0..init.threshold {
            let party_id: u16 =
                (start + index as u16) % init.participants as u16;
            parties.push(party_id);
        }

        // Sort to ensure canonical ordering across all nodes.
        parties.sort();

        // Sanity check: the local participant must be part of the signer set.
        // If this check fails, it means the orchestrator violated the MPC
        // contract by starting a signing session on a node that is not
        // selected by the deterministic signer selection rule.
        if !parties.contains(&stored.identifier) {
            return Err(Error::InvalidParticipant);
        }

        // Prepare data to be signed as a digest.
        let data_to_sign: DataToSign<CggmpSecp256k1> =
            DataToSign::digest::<Sha256>(&init.message);

        let execution_id_bytes: Vec<u8> = init.key_id.into_bytes();

        // Extract public key bytes.
        let public_key: NonZero<Point<CggmpSecp256k1>> =
            key_share.core.shared_public_key;
        let public_key_bytes: Vec<u8> =
            public_key.to_bytes(true).as_ref().to_vec();

        // Setup communication channels.
        let (incoming_transmitter, incoming_receiver): (
            Sender<Incoming<CggmpMessage>>,
            Receiver<Incoming<CggmpMessage>>,
        ) = unbounded();
        let (outgoing_transmitter, outgoing_receiver): (
            Sender<round_based::Outgoing<CggmpMessage>>,
            Receiver<round_based::Outgoing<CggmpMessage>>,
        ) = unbounded();
        let (done_transmitter, done_receiver): (
            Sender<WorkerDone>,
            Receiver<WorkerDone>,
        ) = bounded(1);

        // Spawn the worker thread.
        spawn_worker(Worker {
            key_share,
            parties,
            identifier: stored.identifier,
            data_to_sign,
            execution_id_bytes,
            incoming_receiver,
            outgoing_transmitter,
            done_transmitter,
        });

        Ok(Self {
            threshold: init.threshold,
            participants: init.participants,
            identifier_u32: stored.identifier as u32,
            message_bytes: init.message,
            public_key_bytes,
            incoming_transmitter,
            outgoing_receiver,
            done_receiver,
            message_id: 0,
            aborted: false,
        })
    }

    /// Wraps an outgoing CGGMP message into a round-based protocol message.
    ///
    /// # Arguments
    /// * `outgoing` (`Outgoing<CggmpMessage>`) - Outgoing CGGMP message.
    ///
    /// # Returns
    /// * `Result<RoundMessage, Error>` - Wrapped round message or error.
    fn wrap_outgoing(
        &mut self,
        outgoing: Outgoing<CggmpMessage>,
    ) -> Result<RoundMessage, Error> {
        // Serialize the CGGMP message.
        let inner: Vec<u8> =
            to_vec(&outgoing.msg).map_err(|_| Error::InvalidMessage)?;

        // Wrap into CGGMP24 wire format.
        let wire: Cggmp24Wire =
            Cggmp24Wire::ProtocolMessage { payload: inner };
        let payload: Vec<u8> = encode_wire(&wire)?;

        // Determine recipient.
        let to: Option<u32> = match outgoing.recipient {
            MessageDestination::OneParty(one_party) => {
                Some(u32::from(one_party))
            },
            MessageDestination::AllParties => None,
        };

        // Note: `RoundMessage.round` does NOT represent a CGGMP24 protocol
        // round. It is a transport-level monotonic identifier used by the
        // engine and `round_based` to correlate messages.
        // CGGMP24 protocol rounds are encoded internally in the message
        // contents handled by the worker/state machine.
        let round: Round = self.message_id as Round;

        // Keep a monotonic local counter for debug/telemetry purposes.
        // Saturating add is used to avoid wrap-around in pathological cases.
        // In practice, message_id will never reach MsgId::MAX during a
        // session.
        self.message_id = self.message_id.saturating_add(1);

        Ok(RoundMessage {
            round,
            from: Some(self.identifier_u32),
            to,
            payload,
        })
    }
}

impl SigningProtocol for Cggmp24EcdsaSecp256k1Protocol {
    /// Return the algorithm identifier.
    ///
    /// # Returns
    /// * `Algorithm` - Algorithm identifier.
    fn algorithm(&self) -> Algorithm {
        Algorithm::Cggmp24EcdsaSecp256k1
    }

    /// Return the threshold required for signing.
    ///
    /// # Returns
    /// * `u32` - Threshold number of participants.
    fn threshold(&self) -> u32 {
        self.threshold
    }

    /// Return the total number of participants.
    ///
    /// # Returns
    /// * `u32` - Total number of participants.
    fn participants(&self) -> u32 {
        self.participants
    }

    /// Return the current round number.
    ///
    /// This value is a transport-level progress indicator.
    /// It does not correspond to CGGMP24 cryptographic rounds.
    ///
    /// # Returns
    /// * `Round` - Current round number.
    fn current_round(&self) -> Round {
        self.message_id as Round
    }

    /// Advance the protocol without receiving a message.
    fn next_round(&mut self) -> Result<Option<RoundMessage>, Error> {
        if self.aborted {
            return Err(Error::Aborted);
        }

        // Try to receive an outgoing message from the worker.
        // Note: the worker may emit multiple messages in quick succession.
        // We intentionally process at most one per call to preserve
        // back pressure and fairness with other protocols.
        if let Ok(outgoing) = self.outgoing_receiver.try_recv() {
            let round_message: RoundMessage = self.wrap_outgoing(outgoing)?;
            return Ok(Some(round_message));
        }

        Ok(None)
    }

    /// Process an incoming round message and advance the protocol state.
    ///
    /// # Arguments
    /// * `message` (`RoundMessage`) - Message received from another peer.
    ///
    /// # Returns
    /// * `Option<RoundMessage>` - Message to broadcast for the next round
    fn handle_message(
        &mut self,
        round_message: RoundMessage,
    ) -> Result<Option<RoundMessage>, Error> {
        if self.aborted {
            return Err(Error::Aborted);
        }

        // Decode the incoming round message payload.
        let Cggmp24Wire::ProtocolMessage { payload } =
            decode_wire(&round_message.payload)?;
        // Deserialize the CGGMP message.
        let message: CggmpMessage =
            from_slice(&payload).map_err(|_| Error::InvalidMessage)?;

        let sender_u16: u16 = round_message
            .from
            .ok_or(Error::InvalidMessage)?
            .try_into()
            .map_err(|_| Error::InvalidMessage)?;

        let incoming: Incoming<Msg<CggmpSecp256k1, Sha256>> = Incoming {
            id: round_message.round as MsgId,
            sender: sender_u16,
            // Message type based on presence of `to` field.
            msg_type: if round_message.to.is_some() {
                MessageType::P2P
            } else {
                MessageType::Broadcast
            },
            msg: message,
        };

        // Send the incoming message to the worker.
        self.incoming_transmitter
            .send(incoming)
            .map_err(|_| Error::Aborted)?;

        // Check if there are pending outputs first, return them before
        // checking outgoing channel.
        if let Ok(outgoing) = self.outgoing_receiver.try_recv() {
            let round_message: RoundMessage = self.wrap_outgoing(outgoing)?;
            return Ok(Some(round_message));
        }

        Ok(None)
    }

    /// Finalize the protocol and return the signature.
    ///
    /// # Returns
    /// * `Signature` - Final signature output.
    fn finalize(self: Box<Self>) -> Result<Signature, Error> {
        match self.done_receiver.recv() {
            Ok(WorkerDone::Ok(signature)) => {
                // Convert k256 signature to r, s, v components.
                let r: [u8; 32] = signature
                    .r
                    .to_be_bytes()
                    .as_bytes()
                    .try_into()
                    .map_err(|_| Error::InvalidSignature)?;

                let s: [u8; 32] = signature
                    .s
                    .to_be_bytes()
                    .as_bytes()
                    .try_into()
                    .map_err(|_| Error::InvalidSignature)?;

                // Reconstruct K256 signature.
                let signature: K256Signature =
                    K256Signature::from_scalars(r, s)
                        .map_err(|_| Error::InvalidSignature)?;

                // Reconstruct verifying key from public key bytes.
                let verifying_key: VerifyingKey =
                    VerifyingKey::from_sec1_bytes(&self.public_key_bytes)
                        .map_err(|_| Error::InvalidSignature)?;

                // Recover recovery identifier.
                let recovery_id: RecoveryId =
                    RecoveryId::trial_recovery_from_prehash(
                        &verifying_key,
                        &self.message_bytes,
                        &signature,
                    )
                    .map_err(|_| Error::InvalidSignature)?;

                Ok(Signature::EcdsaSecp256k1 {
                    r,
                    s,
                    v: recovery_id.to_byte(),
                })
            },
            _ => Err(Error::FailedToSign),
        }
    }

    /// Abort the protocol.
    fn abort(&mut self) {
        self.aborted = true;
    }
}
