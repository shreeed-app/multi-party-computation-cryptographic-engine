//! CGGMP24 protocol worker implementation.

use std::thread::{
    spawn,
    yield_now,
};

use cggmp24::{
    ExecutionId,
    generic_ec::curves::Secp256k1,
    key_share::KeyShare,
    signing::{
        DataToSign,
        Signature,
        msg::Msg,
    },
};
use crossbeam_channel::{
    Receiver,
    SendError,
    Sender,
};
use rand_core::OsRng;
use round_based::{
    Incoming,
    Outgoing,
    state_machine::{
        ProceedResult,
        StateMachine,
    },
};
use sha2::Sha256;

/// Message type used by CGGMP24 ECDSA Secp256k1 protocol worker.
pub type CggmpMessage = Msg<Secp256k1, Sha256>;

/// Worker completion notification.
pub enum WorkerDone {
    /// Protocol completed successfully with resulting signature.
    Ok(Signature<Secp256k1>),
    /// Protocol ended with an error.
    Err,
}

/// Spawns a worker thread to execute CGGMP24 ECDSA Secp256k1 protocol.
///
/// # Arguments
/// * `key_share` (`KeyShare<CggmpSecp256k1>`) - The key share of the
///   participant.
/// * `parties` (`Vec<u16>`) - List of participant identifiers.
/// * `identifier` (`u16`) - Identifier of the current participant.
/// * `data_to_sign` (`DataToSign<CggmpSecp256k1>`) - The data to be signed.
/// * `execution_id_bytes` (`Vec<u8>`) - Execution identifier as bytes.
/// * `incoming_receiver` (`Receiver<Incoming<CggmpMessage>>`) - Channel to
///   receive incoming messages.
/// * `outgoing_transmitter` (`Sender<Outgoing<CggmpMessage>>`) - Channel to
///   send outgoing messages.
/// * `done_transmitter` (`Sender<WorkerDone>`) - Channel to notify when the
///   worker is done.
pub fn spawn_worker(
    key_share: KeyShare<Secp256k1>,
    parties: Vec<u16>,
    identifier: u16,
    data_to_sign: DataToSign<Secp256k1>,
    execution_id_bytes: Vec<u8>,
    incoming_receiver: Receiver<Incoming<CggmpMessage>>,
    outgoing_transmitter: Sender<Outgoing<CggmpMessage>>,
    done_transmitter: Sender<WorkerDone>,
) {
    spawn(move || {
        let mut random: OsRng = OsRng;
        // Safety: `execution_id_bytes` is owned by this thread and lives
        // for the entire lifetime of the state machine.
        let execution_id: ExecutionId<'_> =
            ExecutionId::new(&execution_id_bytes);

        let mut state_machine =
            cggmp24::signing(execution_id, identifier, &parties, &key_share)
                .sign_sync(&mut random, &data_to_sign);

        // Important: messages delivered via `incoming_receiver` must preserve
        // the order enforced by the orchestrator. Reordering would
        // violate CGGMP24 protocol assumptions.
        loop {
            match state_machine.proceed() {
                // Outgoing message to be sent to other participants.
                ProceedResult::SendMsg(out) => {
                    // Ignore send errors: if the receiver is gone, the
                    // protocol is already aborted and there is nothing
                    // meaningful to do.
                    let _: Result<(), SendError<Outgoing<CggmpMessage>>> =
                        outgoing_transmitter.send(out);
                },

                // Incoming message to be processed.
                ProceedResult::NeedsOneMoreMessage => {
                    match incoming_receiver.recv() {
                        Ok(incoming) => {
                            if state_machine.received_msg(incoming).is_err() {
                                let _: Result<(), SendError<WorkerDone>> =
                                    done_transmitter.send(WorkerDone::Err);
                                break;
                            }
                        },
                        Err(_) => {
                            // Incoming channel closed: protocol aborted.
                            let _: Result<(), SendError<WorkerDone>> =
                                done_transmitter.send(WorkerDone::Err);
                            break;
                        },
                    }
                },

                // Yielded execution, continue.
                ProceedResult::Yielded => {
                    yield_now();
                },

                // Protocol completed with resulting signature.
                ProceedResult::Output(Ok(signature)) => {
                    let _: Result<(), SendError<WorkerDone>> =
                        done_transmitter.send(WorkerDone::Ok(signature));
                    break;
                },

                // Protocol ended with an error.
                ProceedResult::Output(Err(_)) | ProceedResult::Error(_) => {
                    let _: Result<(), SendError<WorkerDone>> =
                        done_transmitter.send(WorkerDone::Err);
                    break;
                },
            }
        }
    });
}
