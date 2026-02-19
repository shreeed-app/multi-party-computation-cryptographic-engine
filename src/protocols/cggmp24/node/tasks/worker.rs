//! CGGMP24 protocol worker implementation.

use std::{
    sync::Arc,
    thread::{sleep, spawn},
    time::Duration,
};

use cggmp24::{
    ExecutionId,
    SigningError,
    generic_ec::curves::Secp256k1,
    key_share::KeyShare,
    signing::{DataToSign, Signature, msg::Msg},
};
use crossbeam_channel::{Receiver, SendError, Sender};
use once_cell::sync::Lazy;
use rand_core::OsRng;
use round_based::{
    Incoming,
    Outgoing,
    state_machine::{ProceedResult, StateMachine},
};
use sha2::Sha256;
use tokio::sync::{Semaphore, SemaphorePermit};

/// Maximum number of concurrent CGGMP24 workers.
/// This bounds the number of OS threads spawned for CGGMP24 signing
/// and prevents resource exhaustion under load.
const MAXIMUM_WORKERS: usize = 8;

/// Timeout duration for incoming messages.
const INCOMING_MESSAGE_TIMEOUT: Duration = Duration::from_secs(60);

/// Global semaphore used to limit concurrent CGGMP24 workers.
/// A permit is acquired before spawning a worker thread and
/// released automatically when the worker exits.
static CGGMP_WORKER_SEMAPHORE: Lazy<Arc<Semaphore>> =
    Lazy::new(|| Arc::new(Semaphore::new(MAXIMUM_WORKERS)));

/// Message type used by CGGMP24 ECDSA Secp256k1 protocol worker.
pub type CggmpSigningMessage = Msg<Secp256k1, Sha256>;

/// Worker completion notification.
pub enum WorkerDone {
    /// Protocol completed successfully with resulting signature.
    Ok(Signature<Secp256k1>),
    /// Protocol ended with an error.
    Err,
}

/// CGGMP24 ECDSA Secp256k1 protocol worker.
pub struct Worker {
    /// Key share of the participant.
    pub key_share: KeyShare<Secp256k1>,
    /// List of participant identifiers.
    pub parties: Vec<u16>,
    /// Identifier of the current participant.
    pub identifier: u16,
    /// Data to be signed.
    pub data_to_sign: DataToSign<Secp256k1>,
    /// Execution identifier as bytes.
    pub execution_id_bytes: Vec<u8>,
    /// Channel to receive incoming messages.
    pub incoming_receiver: Receiver<Incoming<CggmpSigningMessage>>,
    /// Channel to send outgoing messages.
    pub outgoing_transmitter: Sender<Outgoing<CggmpSigningMessage>>,
    /// Channel to notify when the worker is done.
    pub done_transmitter: Sender<WorkerDone>,
}

/// Spawns a worker thread to execute CGGMP24 ECDSA Secp256k1 protocol.
///
/// # Arguments
/// * `worker` (`Worker`) - The worker instance containing protocol parameters
///   and channels.
pub fn spawn_worker(worker: Worker) {
    let semaphore: Arc<Semaphore> = CGGMP_WORKER_SEMAPHORE.clone();

    // We rely on Tokio here only as a scheduler to provide back pressure.
    // The actual CGGMP24 execution still happens in a dedicated OS thread.
    tokio::spawn(async move {
        // Acquire a permit before spawning the OS thread.
        // This provides a hard upper bound on concurrent CGGMP24 workers.
        let _permit: SemaphorePermit<'_> = match semaphore.acquire().await {
            Ok(permit) => permit,
            Err(_) => {
                // Semaphore closed: treat as protocol abort.
                let _: Result<(), SendError<WorkerDone>> =
                    worker.done_transmitter.send(WorkerDone::Err);
                return;
            },
        };

        spawn(move || {
            run_worker(worker);
            // Permit is released automatically when `_permit` is dropped
            // after the thread exits.
        });
    });
}

/// Runs a single CGGMP24 signing session.
///
/// # Arguments
/// * `worker` (`Worker`) - The worker instance containing protocol parameters
///   and channels.
fn run_worker(worker: Worker) {
    let mut random: OsRng = OsRng;

    // Safety: `execution_id_bytes` is owned by this thread and lives
    // for the entire lifetime of the state machine.
    let execution_id: ExecutionId<'_> =
        ExecutionId::new(&worker.execution_id_bytes);

    let mut state_machine: impl StateMachine<
        Output = Result<Signature<Secp256k1>, SigningError>,
        Msg = CggmpSigningMessage,
    > = cggmp24::signing(
        execution_id,
        worker.identifier,
        &worker.parties,
        &worker.key_share,
    )
    .sign_sync(&mut random, &worker.data_to_sign);

    // Backoff delay for yielded executions.
    let mut backoff: u64 = 1u64; // µs

    // Important: messages delivered via `incoming_receiver` must preserve
    // the order enforced by the controller. Reordering would
    // violate CGGMP24 protocol assumptions.
    loop {
        match state_machine.proceed() {
            // Outgoing message to be sent to other participants.
            ProceedResult::SendMsg(output) => {
                backoff = 1; // Reset backoff on successful progress.

                // Ignore send errors: if the receiver is gone, the
                // protocol is already aborted and there is nothing
                // meaningful to do.
                let _: Result<(), SendError<Outgoing<CggmpSigningMessage>>> =
                    worker.outgoing_transmitter.send(output);
            },

            // Incoming message to be processed.
            ProceedResult::NeedsOneMoreMessage => {
                backoff = 1; // Reset backoff on successful progress.

                match worker
                    .incoming_receiver
                    .recv_timeout(INCOMING_MESSAGE_TIMEOUT)
                {
                    Ok(incoming) => {
                        if state_machine.received_msg(incoming).is_err() {
                            let _: Result<(), SendError<WorkerDone>> =
                                worker.done_transmitter.send(WorkerDone::Err);
                            break;
                        }
                    },

                    // Any error, `RecvTimeoutError::Timeout` or
                    // `RecvTimeoutError::Disconnected` are treated.
                    Err(_) => {
                        // Incoming channel closed: protocol aborted.
                        let _: Result<(), SendError<WorkerDone>> =
                            worker.done_transmitter.send(WorkerDone::Err);
                        break;
                    },
                }
            },

            // Yielded execution, continue.
            ProceedResult::Yielded => {
                // Simple exponential backoff to avoid busy-waiting.
                sleep(Duration::from_micros(backoff));
                backoff = (backoff * 2).min(100);
            },

            // Protocol completed with resulting signature.
            ProceedResult::Output(Ok(signature)) => {
                let _: Result<(), SendError<WorkerDone>> =
                    worker.done_transmitter.send(WorkerDone::Ok(signature));
                break;
            },

            // Protocol ended with an error.
            ProceedResult::Output(Err(_)) | ProceedResult::Error(_) => {
                let _: Result<(), SendError<WorkerDone>> =
                    worker.done_transmitter.send(WorkerDone::Err);
                break;
            },
        }
    }
}
