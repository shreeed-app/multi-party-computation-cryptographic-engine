//! Generic CGGMP24 node protocol driver.

use std::{collections::VecDeque, num::TryFromIntError, sync::Arc};

use crossbeam_channel::{
    Receiver,
    RecvError,
    SendError,
    Sender,
    bounded,
    unbounded,
};
use round_based::{
    Incoming,
    MessageDestination,
    MessageType,
    MsgId,
    Outgoing,
};
use serde::{Serialize, de::DeserializeOwned};
use serde_json::{Error, to_vec};
use tokio::sync::Notify;

use crate::{
    proto::engine::v1::{Algorithm, RoundMessage},
    protocols::{
        cggmp24::{
            node::worker::{CggmpProtocol, Worker, WorkerDone, spawn_worker},
            wire::Cggmp24Wire,
        },
        codec::{decode_wire, encode_wire},
        types::{ProtocolOutput, Round},
    },
    transport::errors::Errors,
};

/// Abstracts over CGGMP24 node protocol variants (key generation, auxiliary
/// generation, signing).
pub trait CggmpNodeProtocol: Send + 'static {
    /// Protocol message type.
    type Message: Send + Serialize + DeserializeOwned + 'static;
    /// Worker output type.
    type Output: Send + 'static;
    /// Protocol-specific data needed for `finalize` and `Protocol` trait
    /// methods (e.g. `key_identifier`, `incomplete_key_share`, thresholds).
    type Data: Send + 'static;

    /// The algorithm identifier for this protocol.
    ///
    /// # Returns
    /// * `Algorithm` - The algorithm identifier for this protocol.
    fn algorithm() -> Algorithm;

    /// Threshold from protocol-specific data.
    ///
    /// # Arguments
    /// * `data` (`&Self::Data`) - Protocol-specific data.
    ///
    /// # Returns
    /// * `u32` - The threshold for this protocol.
    fn threshold(data: &Self::Data) -> u32;

    /// Participants from protocol-specific data.
    ///
    /// # Arguments
    /// * `data` (`&Self::Data`) - Protocol-specific data.
    ///
    /// # Returns
    /// * `u32` - The number of participants for this protocol.
    fn participants(data: &Self::Data) -> u32;

    /// Finalize the protocol from the worker output and protocol data.
    ///
    /// # Arguments
    /// * `data` (`&mut Self::Data`) - Protocol-specific data.
    /// * `output` (`Self::Output`) - The output produced by the worker.
    ///
    /// # Errors
    /// * `Errors::InvalidState` - If the worker output is invalid or cannot be
    ///   used to finalize the protocol.
    /// * `Errors::InvalidKeyShare` - If the finalized key share is invalid
    ///   (for key generation/auxiliary generation).
    /// * `Errors::FailedToSign` - If the signature share is invalid (for
    ///   signing).
    ///
    /// # Returns
    /// * `ProtocolOutput` - The finalized protocol output (key shares or
    ///   signature share).
    fn finalize(
        data: &mut Self::Data,
        output: Self::Output,
    ) -> Result<ProtocolOutput, Errors>;
}

/// Generic CGGMP24 node protocol driver.
///
/// Handles the common channel and message infrastructure shared across all
/// CGGMP24 node protocols (key generation, auxiliary generation, signing).
/// Protocol-specific initialization and finalization are delegated to `P`.
pub struct Cggmp24NodeProtocol<P: CggmpNodeProtocol> {
    /// Protocol-specific data (key identifier, thresholds, key share, etc.)
    pub data: P::Data,
    /// This participant's identifier as u32.
    pub identifier_u32: u32,
    /// Channel for delivering incoming protocol messages to the worker.
    /// Wrapped in `Option` so it can be dropped on abort — dropping the
    /// sender causes the worker's receiver to return an error, prompting
    /// the worker thread to exit promptly rather than waiting for the
    /// 300-second message timeout.
    incoming_transmitter: Option<Sender<Incoming<P::Message>>>,
    /// Channel for receiving outgoing protocol message batches from the
    /// worker.
    outgoing_receiver: Receiver<Vec<Outgoing<P::Message>>>,
    /// Bounded channel for receiving the worker completion signal.
    done_receiver: Receiver<WorkerDone<P::Output>>,
    /// Pending outgoing messages not yet forwarded to the engine.
    pub pending_messages: VecDeque<RoundMessage>,
    /// Worker completion signal captured by drain_pending.
    worker_done: Option<WorkerDone<P::Output>>,
    /// Monotonic transport-level message identifier — not a protocol round.
    pub message_identifier: MsgId,
    /// True if the protocol has been aborted.
    pub aborted: bool,
    /// Shared with the worker OS thread. The worker fires this after every
    /// outgoing batch and after the done signal so that `collect_round` can
    /// await it instead of busy-spinning with `yield_now`.
    notify: Arc<Notify>,
}

impl<P: CggmpNodeProtocol> Cggmp24NodeProtocol<P>
where
    P::Message: Serialize + DeserializeOwned,
{
    /// Create a new protocol driver, spawning the worker thread.
    ///
    /// # Arguments
    /// * `data` (`P::Data`) - Protocol-specific data.
    /// * `identifier_u32` (`u32`) - This participant's identifier.
    /// * `worker_protocol` (`W`) - The worker protocol descriptor to spawn.
    pub fn new<W>(
        data: P::Data,
        identifier_u32: u32,
        worker_protocol: W,
    ) -> Self
    where
        W: CggmpProtocol<Message = P::Message, Output = P::Output>,
    {
        // Channel pair for delivering incoming protocol messages to the
        // worker.
        let (incoming_transmitter, incoming_receiver): (
            Sender<Incoming<P::Message>>,
            Receiver<Incoming<P::Message>>,
        ) = unbounded();

        // Channel pair for receiving outgoing protocol message batches from
        // the worker.
        let (outgoing_transmitter, outgoing_receiver): (
            Sender<Vec<Outgoing<P::Message>>>,
            Receiver<Vec<Outgoing<P::Message>>>,
        ) = unbounded();

        // Bounded channel for receiving the worker completion signal —
        // capacity of 1 since the worker sends exactly one done signal
        // at the end.
        let (done_transmitter, done_receiver): (
            Sender<WorkerDone<P::Output>>,
            Receiver<WorkerDone<P::Output>>,
        ) = bounded(1);

        // Shared notification handle — the worker fires this after every
        // outgoing batch and after the done signal; `collect_round` awaits
        // it to avoid busy-spinning on slow hardware.
        let notify: Arc<Notify> = Arc::new(Notify::new());

        // Spawn the worker thread with the provided protocol descriptor and
        // the transmitting ends of the channels.
        spawn_worker(Worker {
            protocol: worker_protocol,
            incoming_receiver,
            outgoing_transmitter,
            done_transmitter,
            notify: Arc::clone(&notify),
        });

        Self {
            data,
            identifier_u32,
            incoming_transmitter: Some(incoming_transmitter),
            outgoing_receiver,
            done_receiver,
            pending_messages: VecDeque::new(),
            worker_done: None,
            message_identifier: 0,
            aborted: false,
            notify,
        }
    }

    /// Drain all pending outgoing messages from the worker and capture any
    /// completion signal.
    ///
    /// # Errors
    /// * `Errors::InvalidMessage` - If a message cannot be wrapped.
    pub fn drain_pending(&mut self) -> Result<(), Errors> {
        // Drain all outgoing message batches produced by the worker since the
        // last call — each batch corresponds to one state machine step.
        while let Ok(batch) = self.outgoing_receiver.try_recv() {
            let wrapped_batch: Vec<RoundMessage> = batch
                .into_iter()
                .map(
                    |outgoing: Outgoing<<P as CggmpNodeProtocol>::Message>| {
                        self.wrap_outgoing(outgoing)
                    },
                )
                .collect::<Result<Vec<RoundMessage>, Errors>>()?;
            self.pending_messages.extend(wrapped_batch);
        }

        // Capture the worker completion signal if not already received —
        // try_recv avoids blocking since the worker may still be running.
        // Re-drain outgoing after capturing done signal — the worker may have
        // sent final messages just before signaling completion.
        if self.worker_done.is_none()
            && let Ok(done) = self.done_receiver.try_recv()
        {
            self.worker_done = Some(done);
            // Drain any final messages flushed just before the done
            // signal.
            while let Ok(batch) = self.outgoing_receiver.try_recv() {
                let wrapped_batch: Vec<RoundMessage> = batch
                    .into_iter()
                    .map(
                        |outgoing: Outgoing<
                            <P as CggmpNodeProtocol>::Message,
                        >| {
                            self.wrap_outgoing(outgoing)
                        },
                    )
                    .collect::<Result<Vec<RoundMessage>, Errors>>()?;
                self.pending_messages.extend(wrapped_batch);
            }
        }

        Ok(())
    }

    /// Wrap an outgoing worker message into a transport-level `RoundMessage`.
    ///
    /// # Errors
    /// * `Errors::InvalidMessage` - If the message cannot be serialized.
    pub fn wrap_outgoing(
        &mut self,
        outgoing: Outgoing<P::Message>,
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
            MessageDestination::OneParty(party) => Some(u32::from(party)),
            MessageDestination::AllParties => None,
        };

        // Assign a monotonic transport-level identifier — this is NOT a
        // CGGMP24 protocol round. Real rounds are encoded inside the message
        // payload by the state machine.
        let round: Round = self.message_identifier as Round;
        self.message_identifier = self.message_identifier.saturating_add(1);

        Ok(RoundMessage {
            round,
            from: Some(self.identifier_u32),
            to,
            payload,
        })
    }

    /// Deliver an incoming `RoundMessage` to the worker.
    ///
    /// # Arguments
    /// * `round_message` (`RoundMessage`) - The incoming message to deliver.
    ///
    /// # Errors
    /// * `Errors::InvalidMessage` - If the message cannot be decoded or
    ///   delivered.
    pub fn deliver_message(
        &mut self,
        round_message: RoundMessage,
    ) -> Result<(), Errors> {
        // Unwrap the wire envelope and deserialize the CGGMP24 message.
        let Cggmp24Wire::ProtocolMessage { payload }: Cggmp24Wire =
            decode_wire(&round_message.payload)?;

        let message: P::Message =
            serde_json::from_slice(&payload).map_err(|error: Error| {
                Errors::InvalidMessage(format!(
                    "Failed to deserialize CGGMP message: {}",
                    error
                ))
            })?;

        // Resolve the sender identifier and message type for the state
        // machine.
        let sender: u16 = round_message
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
        // broadcast otherwise. Returns Aborted if the channel was dropped
        // (i.e. abort_worker was called).
        self.incoming_transmitter
            .as_ref()
            .ok_or_else(|| {
                Errors::Aborted("Protocol has been aborted.".into())
            })?
            .send(Incoming {
                id: round_message.round as MsgId,
                sender,
                msg_type: if round_message.to.is_some() {
                    MessageType::P2P
                } else {
                    MessageType::Broadcast
                },
                msg: message,
            })
            .map_err(
                |error: SendError<
                    Incoming<<P as CggmpNodeProtocol>::Message>,
                >| {
                    Errors::Aborted(format!(
                        "Failed to send incoming message: {}",
                        error
                    ))
                },
            )?;

        Ok(())
    }

    /// Signal the worker thread to stop by dropping the incoming channel.
    ///
    /// Once the transmitter is dropped the worker's `recv_timeout` call will
    /// return a `RecvError`, causing it to exit immediately rather than
    /// waiting for the 300-second message timeout.
    pub fn abort_worker(&mut self) {
        self.incoming_transmitter = None;
    }

    /// Return true if the protocol is complete and all pending messages
    /// have been drained.
    ///
    /// # Returns
    /// * `bool` - True if the protocol is complete and all pending messages
    ///   have been drained, false otherwise.
    pub fn is_done(&self) -> bool {
        self.worker_done.is_some() && self.pending_messages.is_empty()
    }

    /// Return a clone of the shared `Notify` handle.
    ///
    /// Used by `Protocol::activity_notify` implementations on the wrapper
    /// types so that `collect_round` can await the worker instead of
    /// busy-spinning with `yield_now`.
    ///
    /// # Returns
    /// * `Arc<Notify>` - A cloned reference to the shared notify handle.
    pub fn activity_notify(&self) -> Arc<Notify> {
        Arc::clone(&self.notify)
    }

    /// Consume the worker done signal and finalize via `P::finalize`.
    ///
    /// # Errors
    /// * `Errors::InvalidState` - If the worker has not completed yet.
    ///
    /// # Returns
    /// * `ProtocolOutput` - The finalized protocol output (key shares or
    ///   signature share).
    pub fn finalize_inner(&mut self) -> Result<ProtocolOutput, Errors> {
        let done: WorkerDone<<P as CggmpNodeProtocol>::Output> =
            self.worker_done.take().map_or_else(
                || {
                    self.done_receiver.recv().map_err(|error: RecvError| {
                        Errors::InvalidState(format!(
                            "Failed to finalize protocol: {}",
                            error
                        ))
                    })
                },
                Ok,
            )?;

        match done {
            WorkerDone::Ok(output) => P::finalize(&mut self.data, output),
            WorkerDone::Failed => {
                Err(Errors::Internal("Protocol worker failed.".into()))
            },
        }
    }
}
